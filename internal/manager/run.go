package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/engine"
	"splitwire/internal/ipc"
	"splitwire/internal/logx"
	"splitwire/internal/proxy"
	"splitwire/internal/stats"
)

// running is a tunnel the manager runs: a VPN or a proxy.
type running struct {
	as    string
	text  string
	vpn   *engine.Tunnel
	proxy *proxy.Proxy
	via   config.Via
}

func (r *running) peers() ([]stats.Peer, error) {
	if r.vpn != nil {
		return r.vpn.Peers()
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
}

type service struct {
	userSID string
}

// Run executes the manager service.
func Run(userSID string) error {
	return svc.Run(ServiceName, &service{userSID: userSID})
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
	ln, err := ipc.Listen(s.userSID)
	if err != nil {
		log.Printf("Error: listen on %s: %v", ipc.PipeName, err)
		return true, 1
	}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Printf("Manager started")

	entries, boot := m.loadBoot()
	m.status.Boot = boot
	go func() {
		for _, e := range entries {
			if err := m.up(e.Name, e.As, e.Config); err != nil {
				log.Printf("Boot start of %s failed: %v", e.Name, err)
			}
		}
	}()
	go m.serve(ln)
	stop := make(chan struct{})
	go m.tick(stop)

	for req := range r {
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ln.Close()
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
			m.saveBoot()
		case ipc.OpDown:
			m.down(req.Name)
			m.saveBoot()
		case ipc.OpBoot:
			if err := m.setBoot(req.Boot); err != nil {
				rep.Error = err.Error()
			}
		case ipc.OpLog:
			rep.Log = m.ring.Lines()
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
	if as != ipc.AsVPN && as != ipc.AsProxy {
		return fmt.Errorf("unknown way to run a tunnel: %q", as)
	}
	c, err := config.Parse(text, name)
	if err != nil {
		return err
	}
	m.op.Lock()
	defer m.op.Unlock()

	m.stopLocked(name)
	if as == ipc.AsVPN {
		if vpn := m.vpnName(); vpn != "" {
			m.stopLocked(vpn)
		}
	}
	m.removeTunnels(func(t *ipc.Tunnel) bool {
		return t.Name == name || (as == ipc.AsVPN && t.As == ipc.AsVPN && t.State == ipc.StateError)
	})

	entry := ipc.Tunnel{Name: name, As: as, State: ipc.StateStarting, ConfigHash: ipc.ConfigHash(text)}
	if as == ipc.AsVPN {
		entry.Mode, entry.Apps = c.Mode.String(), len(c.Apps)
		log.Printf("Starting %s as the VPN (mode %s)", name, c.Mode)
	} else {
		entry.Listen = c.Proxy.String()
		if c.ProxyVia == config.ViaVPN {
			entry.Via = c.ProxyVia.String()
		}
		log.Printf("Starting %s as a proxy on %s (via %s)", name, c.Proxy, c.ProxyVia)
	}
	m.setTunnel(name, func(t *ipc.Tunnel) { *t = entry })

	r := &running{as: as, text: text, via: c.ProxyVia}
	if as == ipc.AsVPN {
		r.vpn, err = engine.Up(context.Background(), c)
	} else {
		r.proxy, err = proxy.Start(c)
	}
	if err != nil {
		log.Printf("%s failed: %v", name, err)
		m.setTunnel(name, func(t *ipc.Tunnel) { t.State, t.Error = ipc.StateError, err.Error() })
		return err
	}
	m.tunMu.Lock()
	m.tunnels[name] = r
	m.tunMu.Unlock()
	log.Printf("%s is up", name)
	m.setTunnel(name, func(t *ipc.Tunnel) { t.State, t.Since = ipc.StateUp, time.Now() })
	m.rebindLocked()
	return nil
}

// vpnName is the tunnel running as the VPN, if any.
func (m *manager) vpnName() string {
	m.tunMu.RLock()
	defer m.tunMu.RUnlock()
	for name, r := range m.tunnels {
		if r.vpn != nil {
			return name
		}
	}
	return ""
}

// rebindLocked points proxies with ProxyVia = vpn at the running VPN's
// interface, or drops their packets while no VPN runs.
func (m *manager) rebindLocked() {
	m.tunMu.RLock()
	var index uint32
	vpn := false
	for name, r := range m.tunnels {
		if r.vpn == nil {
			continue
		}
		i, err := r.vpn.InterfaceIndex()
		if err != nil {
			log.Printf("VPN %s interface: %v", name, err)
			continue
		}
		index, vpn = i, true
	}
	waiting := make(map[string]bool)
	for name, r := range m.tunnels {
		if r.proxy == nil || r.via != config.ViaVPN {
			continue
		}
		if err := r.proxy.BindToInterface(index, !vpn); err != nil {
			log.Printf("Proxy %s: bind to the VPN interface: %v", name, err)
		}
		waiting[name] = !vpn
	}
	m.tunMu.RUnlock()
	if len(waiting) == 0 {
		return
	}
	m.publish(func(s *ipc.Status) {
		for name, w := range waiting {
			if t := s.Find(name); t != nil {
				t.Waiting = w
			}
		}
	})
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
	if r.vpn != nil {
		r.vpn.Down()
	} else {
		r.proxy.Close()
	}
	log.Printf("%s is down", name)
	m.removeTunnels(func(t *ipc.Tunnel) bool { return t.Name == name })
	if r.vpn != nil {
		m.rebindLocked()
	}
}

// down takes the named tunnel down, or every tunnel when name is empty,
// and clears their failures. Proxies stop before the VPN they may use.
func (m *manager) down(name string) {
	m.op.Lock()
	defer m.op.Unlock()
	if name != "" {
		m.stopLocked(name)
		m.removeTunnels(func(t *ipc.Tunnel) bool { return t.Name == name })
		return
	}
	m.tunMu.RLock()
	var names []string
	vpn := ""
	for n, r := range m.tunnels {
		if r.vpn != nil {
			vpn = n
		} else {
			names = append(names, n)
		}
	}
	m.tunMu.RUnlock()
	if vpn != "" {
		names = append(names, vpn)
	}
	for _, n := range names {
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

// loadBoot reads the boot tunnels, VPN first so proxies through it start
// bound to it, and whether boot start is on. A boot tunnel in the legacy
// files becomes a VPN entry of bootFile.
func (m *manager) loadBoot() ([]bootEntry, bool) {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return nil, false
	}
	path := filepath.Join(dir, bootFile)
	if name, err := os.ReadFile(filepath.Join(dir, legacyBootName)); err == nil {
		if text, err := os.ReadFile(filepath.Join(dir, legacyBootConf)); err == nil {
			entries := []bootEntry{{Name: strings.TrimSpace(string(name)), As: ipc.AsVPN, Config: string(text)}}
			if err := writeBoot(path, entries); err != nil {
				log.Printf("Convert the boot tunnel: %v", err)
				return entries, true
			}
		}
		os.Remove(filepath.Join(dir, legacyBootName))
		os.Remove(filepath.Join(dir, legacyBootConf))
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false
	}
	var entries []bootEntry
	if err == nil {
		err = json.Unmarshal(b, &entries)
	}
	if err != nil {
		log.Printf("Boot tunnels: %v", err)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].As == ipc.AsVPN && entries[j].As != ipc.AsVPN
	})
	return entries, true
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

// saveBoot records the running tunnels as the boot tunnels while boot
// start is on.
func (m *manager) saveBoot() {
	m.mu.Lock()
	on := m.status.Boot
	m.mu.Unlock()
	if !on {
		return
	}
	if err := m.writeRunning(); err != nil {
		log.Printf("Save the boot tunnels: %v", err)
	}
}

func (m *manager) writeRunning() error {
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
	return writeBoot(filepath.Join(dir, bootFile), entries)
}

// setBoot turns boot start on, recording the running tunnels, or off.
func (m *manager) setBoot(on bool) error {
	m.op.Lock()
	defer m.op.Unlock()
	if on {
		if err := m.writeRunning(); err != nil {
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
