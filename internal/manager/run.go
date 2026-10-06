package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/engine"
	"splitwire/internal/ipc"
	"splitwire/internal/logx"
	"splitwire/internal/netcfg"
	"splitwire/internal/proxy"
	"splitwire/internal/settings"
	"splitwire/internal/stats"
)

// running is a tunnel the manager runs: through an adapter, as the Split
// VPN or a VPN, or as a proxy.
type running struct {
	as      string
	text    string
	cfg     *config.Config
	adapter *engine.Tunnel
	proxy   *proxy.Proxy
	// claims are the destinations the adapter routes for every app.
	claims []netip.Prefix
}

func (r *running) peers() ([]stats.Peer, error) {
	if r.adapter != nil {
		return r.adapter.Peers()
	}
	return r.proxy.Peers()
}

type manager struct {
	ring *logx.Ring

	// op serializes bringing tunnels up and down.
	op sync.Mutex

	// tunMu guards tunnels. Statistics readers hold it shared, so teardown
	// never closes a tunnel under them.
	tunMu   sync.RWMutex
	tunnels map[string]*running

	mu       sync.Mutex
	status   ipc.Status
	watchers map[chan ipc.Status]struct{}

	// lnMu guards ln, the pipe listener, which reloadUsers replaces.
	lnMu sync.Mutex
	ln   net.Listener

	// direct is the resolved Always direct list; op guards it.
	direct []netip.Prefix
}

type service struct {
	// legacyUser is the user an install that predates the users file
	// passed on the command line; it joins the users.
	legacyUser string
}

// Run executes the manager service.
func Run(legacyUser string) error {
	return svc.Run(ServiceName, &service{legacyUser: legacyUser})
}

func (s *service) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	m := &manager{
		ring:     logx.NewRing(500),
		tunnels:  make(map[string]*running),
		watchers: make(map[chan ipc.Status]struct{}),
	}
	if dir, err := bootstrap.LogsDir(); err == nil {
		os.MkdirAll(dir, 0o700)
		if f, err := logx.Setup(filepath.Join(dir, "manager.log"), m.ring); err == nil {
			defer f.Close()
		}
	}
	if s.legacyUser != "" {
		if err := addUser(s.legacyUser); err != nil {
			log.Printf("Warning: %v", err)
		}
	}
	users := Users()
	m.status.Users = len(users)
	set := settings.LoadOrDefaults()
	m.status.Settings = set
	m.direct = set.DirectPrefixes()
	if err := engine.SetSettings(set); err != nil {
		log.Printf("Settings: %v", err)
	}
	ln, err := ipc.Listen(users)
	if err != nil {
		log.Printf("Error: listen on %s: %v", ipc.PipeName, err)
		return true, 1
	}
	m.ln = ln
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Printf("Manager started")

	entries, boot := m.loadBoot()
	m.status.Boot = boot
	if resumed, ok := loadResume(); ok {
		entries = resumed
		log.Printf("Reconnecting the %d tunnels that ran before the update", len(entries))
	}
	go func() {
		for _, e := range entries {
			if err := m.up(e.Name, e.As, e.Config); err != nil {
				log.Printf("Boot start of %s failed: %v", e.Name, err)
			}
		}
		// The file then lists what runs, so a later update brings back
		// these tunnels and none from before a restart.
		if err := m.writeRunning(runningFile); err != nil {
			log.Printf("Save the running tunnels: %v", err)
		}
	}()
	go m.serve(ln)
	stop := make(chan struct{})
	go m.tick(stop)

	for req := range r {
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			m.lnMu.Lock()
			m.ln.Close()
			m.lnMu.Unlock()
			close(stop)
			m.down("")
			log.Printf("Manager stopped")
			return false, 0
		case svc.Interrogate:
			changes <- req.CurrentStatus
		}
	}
	return false, 0
}

// reloadUsers reopens the pipe for the users in the users file. Open
// connections stay; new ones need the new access list.
func (m *manager) reloadUsers() error {
	users := Users()
	m.lnMu.Lock()
	defer m.lnMu.Unlock()
	// The pipe takes one listener at a time, so the old one closes first.
	m.ln.Close()
	ln, err := ipc.Listen(users)
	if err != nil {
		return fmt.Errorf("reopen %s: %w", ipc.PipeName, err)
	}
	m.ln = ln
	go m.serve(ln)
	m.publish(func(s *ipc.Status) { s.Users = len(users) })
	log.Printf("Users reloaded: %d may connect", len(users))
	return nil
}

func (m *manager) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go m.handle(ipc.NewConn(c))
	}
}

func (m *manager) handle(c *ipc.Conn) {
	defer c.Close()
	for {
		var req ipc.Request
		if err := c.Receive(&req); err != nil {
			return
		}
		var rep ipc.Reply
		switch req.Op {
		case ipc.OpStatus:
			m.refreshPeers()
		case ipc.OpUp:
			if err := m.up(req.Name, req.As, req.Config); err != nil {
				rep.Error = err.Error()
			}
			m.saveState()
		case ipc.OpDown:
			m.down(req.Name)
			m.saveState()
		case ipc.OpBoot:
			if err := m.setBoot(req.Boot); err != nil {
				rep.Error = err.Error()
			}
		case ipc.OpLog:
			rep.Log = m.ring.Lines()
		case ipc.OpUsers:
			if err := m.reloadUsers(); err != nil {
				rep.Error = err.Error()
			}
		case ipc.OpSettings:
			if req.Settings == nil {
				rep.Error = "no settings"
			} else if err := m.setSettings(*req.Settings); err != nil {
				rep.Error = err.Error()
			}
		case ipc.OpWatch:
			m.watch(c)
			return
		default:
			rep.Error = fmt.Sprintf("unknown operation %q", req.Op)
		}
		if req.Op != ipc.OpLog {
			st := m.snapshot()
			rep.Status = &st
		}
		if err := c.Send(rep); err != nil {
			return
		}
	}
}

// watch streams statuses to c until the client goes away.
func (m *manager) watch(c *ipc.Conn) {
	ch := make(chan ipc.Status, 1)
	m.mu.Lock()
	m.watchers[ch] = struct{}{}
	first := clone(m.status)
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.watchers, ch)
		m.mu.Unlock()
	}()
	if err := c.Send(first); err != nil {
		return
	}
	for st := range ch {
		if err := c.Send(st); err != nil {
			return
		}
	}
}

func clone(s ipc.Status) ipc.Status {
	s.Tunnels = append([]ipc.Tunnel(nil), s.Tunnels...)
	return s
}

// publish changes the status and hands a copy to every watcher, dropping a
// status a slow watcher has not taken yet.
func (m *manager) publish(update func(*ipc.Status)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	update(&m.status)
	sort.Slice(m.status.Tunnels, func(i, j int) bool {
		return strings.ToLower(m.status.Tunnels[i].Name) < strings.ToLower(m.status.Tunnels[j].Name)
	})
	for ch := range m.watchers {
		select {
		case <-ch:
		default:
		}
		ch <- clone(m.status)
	}
}

// setTunnel changes the named tunnel's entry, adding it when missing.
func (m *manager) setTunnel(name string, update func(*ipc.Tunnel)) {
	m.publish(func(s *ipc.Status) {
		t := s.Find(name)
		if t == nil {
			s.Tunnels = append(s.Tunnels, ipc.Tunnel{Name: name})
			t = &s.Tunnels[len(s.Tunnels)-1]
		}
		update(t)
	})
}

// removeTunnels drops the entries match selects.
func (m *manager) removeTunnels(match func(*ipc.Tunnel) bool) {
	m.publish(func(s *ipc.Status) {
		kept := s.Tunnels[:0]
		for i := range s.Tunnels {
			if !match(&s.Tunnels[i]) {
				kept = append(kept, s.Tunnels[i])
			}
		}
		s.Tunnels = kept
	})
}

func (m *manager) snapshot() ipc.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clone(m.status)
}

func (m *manager) refreshPeers() {
	type result struct {
		name  string
		peers []stats.Peer
	}
	var results []result
	m.tunMu.RLock()
	for name, r := range m.tunnels {
		if peers, err := r.peers(); err == nil && peers != nil {
			results = append(results, result{name, peers})
		}
	}
	m.tunMu.RUnlock()
	if len(results) == 0 {
		return
	}
	m.publish(func(s *ipc.Status) {
		for _, res := range results {
			if t := s.Find(res.name); t != nil && t.State == ipc.StateUp {
				t.Peers = res.peers
			}
		}
	})
}

// tick refreshes peer statistics while anyone watches.
func (m *manager) tick(stop chan struct{}) {
	tk := time.NewTicker(statsInterval)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			m.mu.Lock()
			watched := len(m.watchers) > 0 && len(m.status.Tunnels) > 0
			m.mu.Unlock()
			if watched {
				m.refreshPeers()
			}
		}
	}
}

func (m *manager) up(name, as, text string) error {
	if as != ipc.AsSplit && as != ipc.AsVPN && as != ipc.AsProxy {
		return fmt.Errorf("unknown way to run a tunnel: %q", as)
	}
	c, err := config.Parse(text, name)
	if err != nil {
		return err
	}
	switch as {
	case ipc.AsSplit:
		if c.Mode == config.ModeFull {
			return fmt.Errorf("%s needs Mode = include or exclude to run as the Split VPN", name)
		}
	case ipc.AsVPN:
		c.Mode = config.ModeFull
	}
	m.op.Lock()
	defer m.op.Unlock()

	m.stopLocked(name)
	if as == ipc.AsSplit {
		if split := m.splitName(); split != "" {
			m.stopLocked(split)
		}
	}
	m.removeTunnels(func(t *ipc.Tunnel) bool {
		return t.Name == name || (as == ipc.AsSplit && t.As == ipc.AsSplit && t.State == ipc.StateError)
	})

	entry := ipc.Tunnel{Name: name, As: as, State: ipc.StateStarting, ConfigHash: ipc.ConfigHash(text)}
	switch as {
	case ipc.AsSplit:
		entry.Mode, entry.Apps = c.Mode.String(), len(c.Apps)
		log.Printf("Starting %s as the Split VPN (mode %s)", name, c.Mode)
	case ipc.AsVPN:
		log.Printf("Starting %s as a VPN", name)
	default:
		entry.Listen = c.Proxy.String()
		log.Printf("Starting %s as a proxy on %s", name, c.Proxy)
	}
	m.setTunnel(name, func(t *ipc.Tunnel) { *t = entry })
	fail := func(err error) error {
		log.Printf("%s failed: %v", name, err)
		m.setTunnel(name, func(t *ipc.Tunnel) { t.State, t.Error = ipc.StateError, err.Error() })
		return err
	}

	r := &running{as: as, text: text, cfg: c}
	if ipc.Adapter(as) {
		m.refreshDirectLocked()
		r.claims = claims(c, m.direct)
		if other, p, ok := conflict(m.claimsLocked(), r.claims); ok {
			return fail(fmt.Errorf("%s already routes %s", other, p))
		}
		r.adapter, err = engine.Up(context.Background(), c, m.direct)
	} else {
		r.proxy, err = proxy.Start(c)
	}
	if err != nil {
		return fail(err)
	}
	m.tunMu.Lock()
	m.tunnels[name] = r
	m.tunMu.Unlock()
	log.Printf("%s is up", name)
	m.setTunnel(name, func(t *ipc.Tunnel) { t.State, t.Since = ipc.StateUp, time.Now() })
	return nil
}

// splitName is the tunnel running as the Split VPN, if any.
func (m *manager) splitName() string {
	m.tunMu.RLock()
	defer m.tunMu.RUnlock()
	for name, r := range m.tunnels {
		if r.as == ipc.AsSplit {
			return name
		}
	}
	return ""
}

// claimsLocked are the destinations each running adapter routes for
// every app, by tunnel.
func (m *manager) claimsLocked() map[string][]netip.Prefix {
	m.tunMu.RLock()
	defer m.tunMu.RUnlock()
	out := make(map[string][]netip.Prefix)
	for name, r := range m.tunnels {
		if r.adapter != nil {
			out[name] = r.claims
		}
	}
	return out
}

// setSettings saves the machine-wide settings and applies them to the
// running tunnels.
func (m *manager) setSettings(s settings.Settings) error {
	if _, err := config.ParseDirect(s.Direct); err != nil {
		return err
	}
	m.op.Lock()
	defer m.op.Unlock()
	if err := settings.Save(s); err != nil {
		return err
	}
	m.publish(func(st *ipc.Status) { st.Settings = s })
	log.Printf("Settings: kill switch %t, local network %t, strict DNS %t, Always direct %v",
		s.KillSwitch, s.AllowLAN, s.StrictDNS, s.Direct)
	m.refreshDirectLocked()
	return engine.SetSettings(s)
}

// refreshDirectLocked resolves the Always direct list again and, when it
// changed, applies it to the running adapters.
func (m *manager) refreshDirectLocked() {
	m.mu.Lock()
	s := m.status.Settings
	m.mu.Unlock()
	direct := s.DirectPrefixes()
	if slices.Equal(direct, m.direct) {
		return
	}
	m.direct = direct
	m.tunMu.Lock()
	defer m.tunMu.Unlock()
	for name, r := range m.tunnels {
		if r.adapter == nil {
			continue
		}
		if err := r.adapter.SetDirect(direct); err != nil {
			log.Printf("%s: apply Always direct: %v", name, err)
		}
		r.claims = claims(r.cfg, direct)
	}
}

// claims are the destinations a tunnel's adapter routes for every app: its
// routes without the Always direct prefixes, except include mode's default
// route, which carries only the Split VPN's apps.
func claims(c *config.Config, direct []netip.Prefix) []netip.Prefix {
	if c.WG.Interface.TableOff {
		return nil
	}
	var out []netip.Prefix
	for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		routes, _ := netcfg.Routes(c, f)
		for _, r := range netcfg.WithoutDirect(routes, direct) {
			if r.Metric != netcfg.IncludeDefaultMetric {
				out = append(out, r.Destination)
			}
		}
	}
	return out
}

// conflict finds a running tunnel that already routes one of mine's
// destinations. Windows sends each packet down the most specific route, so
// only an identical destination conflicts.
func conflict(running map[string][]netip.Prefix, mine []netip.Prefix) (string, netip.Prefix, bool) {
	names := make([]string, 0, len(running))
	for name := range running {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, p := range mine {
		for _, name := range names {
			for _, q := range running[name] {
				if p == q {
					return name, p, true
				}
			}
		}
	}
	return "", netip.Prefix{}, false
}

// stopLocked takes the named tunnel down if it runs.
func (m *manager) stopLocked(name string) {
	m.tunMu.Lock()
	r := m.tunnels[name]
	delete(m.tunnels, name)
	m.tunMu.Unlock()
	if r == nil {
		return
	}
	m.setTunnel(name, func(t *ipc.Tunnel) { t.State = ipc.StateStopping })
	if r.adapter != nil {
		r.adapter.Down()
	} else {
		r.proxy.Close()
	}
	log.Printf("%s is down", name)
	m.removeTunnels(func(t *ipc.Tunnel) bool { return t.Name == name })
}

// down takes the named tunnel down, or every tunnel when name is empty,
// and clears their failures. Proxies stop first, then the adapters.
func (m *manager) down(name string) {
	m.op.Lock()
	defer m.op.Unlock()
	if name != "" {
		m.stopLocked(name)
		m.removeTunnels(func(t *ipc.Tunnel) bool { return t.Name == name })
		return
	}
	m.tunMu.RLock()
	var proxies, adapters []string
	for n, r := range m.tunnels {
		if r.adapter != nil {
			adapters = append(adapters, n)
		} else {
			proxies = append(proxies, n)
		}
	}
	m.tunMu.RUnlock()
	for _, n := range append(proxies, adapters...) {
		m.stopLocked(n)
	}
	m.removeTunnels(func(*ipc.Tunnel) bool { return true })
}

// bootEntry is a tunnel to bring up at boot.
type bootEntry struct {
	Name   string
	As     string
	Config string
}

// loadResume reads the tunnels that ran before an update, and reports
// false when the last stop was not for an update or they were not saved.
func loadResume() ([]bootEntry, bool) {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return nil, false
	}
	marker := filepath.Join(dir, resumeFile)
	if _, err := os.Stat(marker); err != nil {
		return nil, false
	}
	os.Remove(marker)
	entries, err := readEntries(filepath.Join(dir, runningFile))
	if err != nil {
		log.Printf("Tunnels before the update: %v", err)
		return nil, false
	}
	return entries, true
}

// loadBoot reads the boot tunnels and whether boot start is on. A boot
// tunnel in the legacy files becomes an entry of bootFile.
func (m *manager) loadBoot() ([]bootEntry, bool) {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return nil, false
	}
	path := filepath.Join(dir, bootFile)
	if name, err := os.ReadFile(filepath.Join(dir, legacyBootName)); err == nil {
		if text, err := os.ReadFile(filepath.Join(dir, legacyBootConf)); err == nil {
			entries := []bootEntry{{Name: strings.TrimSpace(string(name)), As: adapterRole(string(text)), Config: string(text)}}
			if err := writeBoot(path, entries); err != nil {
				log.Printf("Convert the boot tunnel: %v", err)
				return entries, true
			}
		}
		os.Remove(filepath.Join(dir, legacyBootName))
		os.Remove(filepath.Join(dir, legacyBootConf))
	}
	entries, err := readEntries(path)
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		log.Printf("Boot tunnels: %v", err)
	}
	return entries, true
}

// readEntries reads a file of tunnels, the Split VPN first, then the VPNs,
// then the proxies.
func readEntries(path string) ([]bootEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []bootEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].As == ipc.AsVPN {
			entries[i].As = adapterRole(entries[i].Config)
		}
	}
	rank := map[string]int{ipc.AsSplit: 0, ipc.AsVPN: 1, ipc.AsProxy: 2}
	sort.SliceStable(entries, func(i, j int) bool { return rank[entries[i].As] < rank[entries[j].As] })
	return entries, nil
}

// adapterRole is the way a boot entry recorded as a VPN runs: the Split VPN
// when its configuration picks apps, a VPN otherwise.
func adapterRole(text string) string {
	if c, err := config.Parse(text, "boot"); err == nil && c.Mode != config.ModeFull {
		return ipc.AsSplit
	}
	return ipc.AsVPN
}

func writeBoot(path string, entries []bootEntry) error {
	if entries == nil {
		entries = []bootEntry{}
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// saveState records the running tunnels for an update, and as the boot
// tunnels while boot start is on.
func (m *manager) saveState() {
	if err := m.writeRunning(runningFile); err != nil {
		log.Printf("Save the running tunnels: %v", err)
	}
	m.mu.Lock()
	on := m.status.Boot
	m.mu.Unlock()
	if !on {
		return
	}
	if err := m.writeRunning(bootFile); err != nil {
		log.Printf("Save the boot tunnels: %v", err)
	}
}

// writeRunning writes the running tunnels to the configs folder's file.
func (m *manager) writeRunning(file string) error {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return err
	}
	m.tunMu.RLock()
	entries := make([]bootEntry, 0, len(m.tunnels))
	for name, r := range m.tunnels {
		entries = append(entries, bootEntry{Name: name, As: r.as, Config: r.text})
	}
	m.tunMu.RUnlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return writeBoot(filepath.Join(dir, file), entries)
}

// setBoot turns boot start on, recording the running tunnels, or off.
func (m *manager) setBoot(on bool) error {
	m.op.Lock()
	defer m.op.Unlock()
	if on {
		if err := m.writeRunning(bootFile); err != nil {
			return err
		}
		log.Printf("Boot start on")
	} else {
		dir, err := bootstrap.ConfigsDir()
		if err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(dir, bootFile)); err != nil && !os.IsNotExist(err) {
			return err
		}
		log.Printf("Boot start off")
	}
	m.publish(func(s *ipc.Status) { s.Boot = on })
	return nil
}
