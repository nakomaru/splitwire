// Package engine brings a tunnel up and down: the WireGuardNT adapter, its
// network configuration, the firewall and the split tunnel driver.
package engine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/firewall"
	"splitwire/internal/netcfg"
	"splitwire/internal/stdriver"
)

// TunnelType is the WireGuardNT adapter type name.
const TunnelType = "splitwire"

const instanceMutex = `Global\splitwire-tunnel`

// Tunnel is a running tunnel.
type Tunnel struct {
	cfg      *config.Config
	adapter  *driver.Adapter
	luid     winipcfg.LUID
	mutex    windows.Handle
	firewall bool

	callbacks []winipcfg.ChangeCallback
	drv       *stdriver.Driver
	physical  *netcfg.PhysicalWatcher
	events    chan struct{}
}

// adapterGUID derives a stable adapter GUID from the tunnel name, so Windows
// keeps recognizing the network across restarts.
func adapterGUID(name string) *windows.GUID {
	sum := sha256.Sum256([]byte("splitwire adapter " + name))
	g := windows.GUID{
		Data1: uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3]),
		Data2: uint16(sum[4])<<8 | uint16(sum[5]),
		Data3: uint16(sum[6])<<8 | uint16(sum[7]),
	}
	copy(g.Data4[:], sum[8:16])
	g.Data3 = g.Data3&0x0fff | 0x5000
	g.Data4[0] = g.Data4[0]&0x3f | 0x80
	return &g
}

// Run brings the tunnel up and keeps it up until ctx ends.
func Run(ctx context.Context, c *config.Config) error {
	t, err := Up(ctx, c)
	if err != nil {
		return err
	}
	log.Printf("Tunnel %s is up (mode %s)", c.WG.Name, c.Mode)
	<-ctx.Done()
	log.Printf("Shutting down tunnel %s", c.WG.Name)
	t.Down()
	return nil
}

// Up brings the tunnel up. On failure it undoes what it did.
func Up(ctx context.Context, c *config.Config) (t *Tunnel, err error) {
	t = &Tunnel{cfg: c}
	defer func() {
		if err != nil {
			t.Down()
			t = nil
		}
	}()

	name, err := windows.UTF16PtrFromString(instanceMutex)
	if err != nil {
		return nil, err
	}
	mutex, err := windows.CreateMutex(nil, true, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(mutex)
		return nil, errors.New("another splitwire tunnel is running")
	}
	if err != nil {
		return nil, fmt.Errorf("create instance mutex: %w", err)
	}
	t.mutex = mutex

	split := c.Mode != config.ModeFull
	var devicePaths []string
	if split {
		devicePaths, err = resolveApps(c)
		if err != nil {
			return nil, err
		}
	}

	if err := bootstrap.EnsureDirs(); err != nil {
		return nil, err
	}
	dll, err := bootstrap.EnsureWireGuardDLL(ctx)
	if err != nil {
		return nil, err
	}
	if err := bootstrap.LoadWireGuardDLL(dll); err != nil {
		return nil, err
	}
	if split {
		sys, err := bootstrap.EnsureDriver(ctx)
		if err != nil {
			return nil, err
		}
		if err := bootstrap.EnsureDriverService(sys); err != nil {
			return nil, err
		}
	}

	log.Println("Resolving endpoints")
	if err := c.WG.ResolveEndpoints(); err != nil {
		return nil, err
	}

	log.Println("Creating network adapter")
	t.adapter, err = driver.CreateAdapter(c.WG.Name, TunnelType, adapterGUID(c.WG.Name))
	if err != nil {
		return nil, fmt.Errorf("create adapter: %w", err)
	}
	t.luid = t.adapter.LUID()
	if v, err := driver.RunningVersion(); err == nil {
		log.Printf("Using WireGuardNT/%d.%d", (v>>16)&0xffff, v&0xffff)
	}
	if err := t.adapter.SetLogging(driver.AdapterLogOn); err != nil {
		return nil, fmt.Errorf("enable adapter logging: %w", err)
	}

	if err := t.enableFirewall(); err != nil {
		return nil, err
	}

	log.Println("Setting interface configuration")
	if err := t.adapter.SetConfiguration(c.WG.ToDriverConfiguration()); err != nil {
		return nil, fmt.Errorf("configure adapter: %w", err)
	}
	if err := t.adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return nil, fmt.Errorf("bring adapter up: %w", err)
	}

	families, err := netcfg.WaitForInterfaces(c, t.luid, time.Minute)
	if err != nil {
		return nil, err
	}
	for _, f := range families {
		if c.WG.Interface.MTU == 0 {
			cbs, err := netcfg.MonitorMTU(f, t.luid)
			if err != nil {
				return nil, fmt.Errorf("monitor MTU: %w", err)
			}
			t.callbacks = append(t.callbacks, cbs...)
		}
		if err := netcfg.Configure(c, t.luid, f); err != nil {
			return nil, err
		}
	}

	if split {
		if err := t.engageDriver(devicePaths); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *Tunnel) enableFirewall() error {
	c := t.cfg
	opts := firewall.Options{
		TunnelLUID: uint64(t.luid),
		KillSwitch: c.KillSwitchOn(),
		AllowLAN:   c.AllowLAN,
	}
	if c.StrictDNS && !c.WG.Interface.TableOff {
		opts.DNSServers = c.WG.Interface.DNS
	}
	for _, p := range c.WG.Peers {
		if p.Endpoint.IsEmpty() {
			continue
		}
		a, err := netip.ParseAddr(p.Endpoint.Host)
		if err != nil {
			return fmt.Errorf("endpoint %s did not resolve to an address", p.Endpoint.Host)
		}
		opts.Endpoints = append(opts.Endpoints, netip.AddrPortFrom(a, p.Endpoint.Port))
	}
	if err := firewall.EnsureSublayers(); err != nil {
		return fmt.Errorf("register firewall sublayers: %w", err)
	}
	if !opts.KillSwitch && len(opts.DNSServers) == 0 {
		return nil
	}
	log.Printf("Enabling firewall (kill switch %t, LAN %t, DNS restricted to %v)", opts.KillSwitch, opts.AllowLAN, opts.DNSServers)
	if err := firewall.EnableFirewall(opts); err != nil {
		return fmt.Errorf("enable firewall: %w", err)
	}
	t.firewall = true
	return nil
}

func resolveApps(c *config.Config) ([]string, error) {
	paths, warnings, err := c.ExpandApps()
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		log.Printf("Warning: %s", w)
	}
	devicePaths := make([]string, 0, len(paths))
	for _, p := range paths {
		d, err := stdriver.DevicePath(p)
		if err != nil {
			return nil, fmt.Errorf("App %s: %w", p, err)
		}
		devicePaths = append(devicePaths, d)
	}
	if len(devicePaths) == 0 {
		return nil, errors.New("no App entry resolved to a file")
	}
	return devicePaths, nil
}

// driverAddresses maps tunnel and physical addresses onto the driver's
// redirect slots. The driver rebinds split processes from its Tunnel address
// to its Internet address and blocks split processes that end up on the
// Tunnel address, so include mode hands it the physical addresses as Tunnel
// and the WireGuard addresses as Internet. A family with a Tunnel address but
// no Internet address is blocked for split processes instead of leaking.
func driverAddresses(mode config.Mode, wg4, wg6 netip.Addr, phys netcfg.Physical) stdriver.Addresses {
	if mode == config.ModeInclude {
		return stdriver.Addresses{TunnelIPv4: phys.IPv4, InternetIPv4: wg4, TunnelIPv6: phys.IPv6, InternetIPv6: wg6}
	}
	return stdriver.Addresses{TunnelIPv4: wg4, InternetIPv4: phys.IPv4, TunnelIPv6: wg6, InternetIPv6: phys.IPv6}
}

func (t *Tunnel) engageDriver(devicePaths []string) error {
	c := t.cfg
	drv, err := stdriver.Open()
	if err != nil {
		return err
	}
	t.drv = drv
	state, err := drv.State()
	if err != nil {
		return err
	}
	if state != stdriver.StateStarted {
		log.Printf("Split tunnel driver is %s; resetting it", state)
		if err := drv.Reset(); err != nil {
			return err
		}
	}
	if err := drv.Initialize(firewall.BaselineKey, firewall.DNSKey); err != nil {
		return err
	}
	if err := drv.RegisterRunningProcesses(); err != nil {
		return err
	}

	wg4, wg6 := c.TunnelAddress(true), c.TunnelAddress(false)
	registered := make(chan error, 1)
	first := true
	t.physical, err = netcfg.WatchPhysical(t.luid, func(p netcfg.Physical) {
		a := driverAddresses(c.Mode, wg4, wg6, p)
		log.Printf("Physical addresses %s %s; driver tunnel %s %s, internet %s %s",
			addrText(p.IPv4), addrText(p.IPv6), addrText(a.TunnelIPv4), addrText(a.TunnelIPv6),
			addrText(a.InternetIPv4), addrText(a.InternetIPv6))
		err := drv.RegisterAddresses(a)
		if err != nil {
			log.Printf("Warning: %v", err)
		}
		if first {
			first = false
			registered <- err
		}
	})
	if err != nil {
		return fmt.Errorf("watch physical interface: %w", err)
	}
	if err := <-registered; err != nil {
		return fmt.Errorf("no usable physical address for split tunneling: %w", err)
	}

	if err := drv.SetConfiguration(devicePaths); err != nil {
		return err
	}
	for _, d := range devicePaths {
		log.Printf("Split app: %s", d)
	}
	state, err = drv.State()
	if err != nil {
		return err
	}
	if state != stdriver.StateEngaged {
		return fmt.Errorf("split tunnel driver is %s after configuration, want engaged", state)
	}

	t.events = make(chan struct{})
	go t.logEvents()
	return nil
}

func (t *Tunnel) logEvents() {
	defer close(t.events)
	verb := "Tunneling"
	if t.cfg.Mode == config.ModeExclude {
		verb = "Bypassing tunnel for"
	}
	for {
		ev, err := t.drv.DequeueEvent()
		if err != nil {
			if !errors.Is(err, windows.ERROR_OPERATION_ABORTED) && !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
				log.Printf("Split tunnel event: %v", err)
			}
			return
		}
		exe := filepath.Base(strings.ReplaceAll(ev.ImageName, `\`, "/"))
		switch ev.Kind {
		case stdriver.EventStartSplitting:
			how := "configured"
			if ev.Reason&stdriver.ReasonByInheritance != 0 {
				how = "inherited"
			}
			log.Printf("%s %s (pid %d, %s)", verb, exe, ev.PID, how)
		case stdriver.EventStopSplitting:
			if ev.Reason&stdriver.ReasonProcessDeparting == 0 {
				log.Printf("Stopped splitting %s (pid %d)", exe, ev.PID)
			}
		case stdriver.EventErrorStartSplitting, stdriver.EventErrorStopSplitting:
			log.Printf("Split tunnel driver failed to update %s (pid %d)", exe, ev.PID)
		case stdriver.EventErrorMessage:
			log.Printf("Split tunnel driver error 0x%08x: %s", ev.Status, ev.Message)
		}
	}
}

// Down tears the tunnel down. It is safe on a partly built tunnel.
func (t *Tunnel) Down() {
	if t.physical != nil {
		t.physical.Close()
		t.physical = nil
	}
	if t.drv != nil {
		if err := t.drv.Reset(); err != nil {
			log.Printf("Warning: %v", err)
		}
		t.drv.CancelPending()
		if t.events != nil {
			<-t.events
		}
		t.drv.Close()
		t.drv = nil
	}
	for _, cb := range t.callbacks {
		cb.Unregister()
	}
	t.callbacks = nil
	if t.firewall {
		firewall.DisableFirewall()
		t.firewall = false
	}
	if t.adapter != nil {
		netcfg.Flush(t.luid)
		t.adapter.Close()
		t.adapter = nil
	}
	if t.mutex != 0 {
		if err := firewall.RemoveSublayers(); err != nil {
			log.Printf("Warning: remove firewall sublayers: %v", err)
		}
		windows.ReleaseMutex(t.mutex)
		windows.CloseHandle(t.mutex)
		t.mutex = 0
	}
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return "none"
	}
	return a.String()
}
