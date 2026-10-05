// Package manager is the splitwire service that runs tunnels for the tray app.
// It runs as LocalSystem and serves the ipc protocol on a pipe that only
// SYSTEM, Administrators and the installing user can open.
package manager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/engine"
	"splitwire/internal/ipc"
	"splitwire/internal/logx"
	"splitwire/internal/stats"
)

// ServiceName is the manager service.
const ServiceName = ipc.ServiceName

// RunCommand is the hidden CLI command the service executes.
const RunCommand = "manager-run"

// statsInterval is how often watchers get fresh peer statistics while a tunnel is up.
const statsInterval = 2 * time.Second

const (
	autostartName = "autostart.name"
	autostartConf = "autostart.conf"
)

// Install copies the executables into the install root and registers and
// starts the manager service for the calling user. Installing again
// updates the executables and restarts the service.
func Install() error {
	if err := bootstrap.EnsureDirs(); err != nil {
		return err
	}
	exe, err := bootstrap.InstallExe()
	if err != nil {
		return err
	}
	if tray, err := bootstrap.InstallTray(); err != nil {
		return err
	} else if tray != "" {
		log.Printf("Installed %s", tray)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := user.User.Sid.String()

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	cfg := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Nsi", "TcpIp"},
		DisplayName:  "splitwire manager",
		Description:  "Runs splitwire tunnels for the splitwire tray app.",
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	s, err := m.OpenService(ServiceName)
	if err == nil {
		log.Printf("Updating the existing %s service", ServiceName)
		if err := stopService(s); err != nil {
			s.Close()
			return err
		}
		cfg.BinaryPathName = windows.EscapeArg(exe) + " " + RunCommand + " " + sid
		if err := s.UpdateConfig(cfg); err != nil {
			s.Close()
			return fmt.Errorf("update %s service: %w", ServiceName, err)
		}
	} else {
		s, err = m.CreateService(ServiceName, exe, cfg, RunCommand, sid)
		if err != nil {
			return fmt.Errorf("create %s service: %w", ServiceName, err)
		}
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60)
	if err := s.Start(); err != nil {
		return fmt.Errorf("start %s: %w", ServiceName, err)
	}
	log.Printf("Installed and started the %s service", ServiceName)
	return nil
}

func stopService(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stop %s: %w", s.Name, err)
	}
	deadline := time.Now().Add(time.Minute)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not stop within a minute", s.Name)
		}
		time.Sleep(100 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

// Uninstall stops and deletes the manager service.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	if err := stopService(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return err
	}
	if dir, err := bootstrap.ConfigsDir(); err == nil {
		os.Remove(filepath.Join(dir, autostartName))
		os.Remove(filepath.Join(dir, autostartConf))
	}
	log.Printf("Removed the %s service", ServiceName)
	return nil
}

// Installed reports whether the manager service exists.
func Installed() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

type manager struct {
	ring *logx.Ring

	// op serializes bringing tunnels up and down.
	op   sync.Mutex
	stop chan struct{}

	// tunMu guards tunnel. Statistics readers hold it shared, so teardown
	// never closes the adapter under them.
	tunMu  sync.RWMutex
	tunnel *engine.Tunnel

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
		status:   ipc.Status{State: ipc.StateDown},
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

	m.status.Autostart = m.autostartName()
	if name, text := m.autostart(); name != "" {
		go func() {
			if err := m.up(name, text); err != nil {
				log.Printf("Autostart of %s failed: %v", name, err)
			}
		}()
	}
	go m.serve(ln)

	for req := range r {
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ln.Close()
			m.down()
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
			st := m.snapshot(true)
			rep.Status = &st
		case ipc.OpUp:
			if err := m.up(req.Name, req.Config); err != nil {
				rep.Error = err.Error()
			}
			st := m.snapshot(false)
			rep.Status = &st
		case ipc.OpDown:
			m.down()
			st := m.snapshot(false)
			rep.Status = &st
		case ipc.OpAutostart:
			if err := m.setAutostart(req.Name, req.Config); err != nil {
				rep.Error = err.Error()
			}
			st := m.snapshot(false)
			rep.Status = &st
		case ipc.OpLog:
			rep.Log = m.ring.Lines()
		case ipc.OpWatch:
			m.watch(c)
			return
		default:
			rep.Error = fmt.Sprintf("unknown operation %q", req.Op)
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
	first := m.status
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

// publish replaces the status and hands it to every watcher, dropping a
// status a slow watcher has not taken yet.
func (m *manager) publish(update func(*ipc.Status)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	update(&m.status)
	for ch := range m.watchers {
		select {
		case <-ch:
		default:
		}
		ch <- m.status
	}
}

func (m *manager) snapshot(refreshPeers bool) ipc.Status {
	if refreshPeers {
		m.refreshPeers()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *manager) refreshPeers() {
	m.tunMu.RLock()
	var peers []stats.Peer
	var err error
	if m.tunnel != nil {
		peers, err = m.tunnel.Peers()
	}
	m.tunMu.RUnlock()
	if err != nil || peers == nil {
		return
	}
	m.publish(func(s *ipc.Status) {
		if s.State == ipc.StateUp {
			s.Peers = peers
		}
	})
}

func (m *manager) up(name, text string) error {
	c, err := config.Parse(text, name)
	if err != nil {
		return err
	}
	m.op.Lock()
	defer m.op.Unlock()
	m.downLocked()

	apps := len(c.Apps)
	m.publish(func(s *ipc.Status) {
		*s = ipc.Status{State: ipc.StateStarting, Tunnel: name, Mode: c.Mode.String(), Apps: apps,
			ConfigHash: ipc.ConfigHash(text), Autostart: s.Autostart}
	})
	log.Printf("Starting tunnel %s (mode %s)", name, c.Mode)
	t, err := engine.Up(context.Background(), c)
	if err != nil {
		log.Printf("Tunnel %s failed: %v", name, err)
		m.publish(func(s *ipc.Status) {
			s.State, s.Error = ipc.StateError, err.Error()
		})
		return err
	}
	m.tunMu.Lock()
	m.tunnel = t
	m.tunMu.Unlock()
	m.stop = make(chan struct{})
	go m.tick(m.stop)
	log.Printf("Tunnel %s is up", name)
	m.publish(func(s *ipc.Status) {
		s.State, s.Since = ipc.StateUp, time.Now()
	})
	return nil
}

// tick refreshes peer statistics for watchers while the tunnel runs.
func (m *manager) tick(stop chan struct{}) {
	tk := time.NewTicker(statsInterval)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			m.mu.Lock()
			watched := len(m.watchers) > 0
			m.mu.Unlock()
			if watched {
				m.refreshPeers()
			}
		}
	}
}

func (m *manager) down() {
	m.op.Lock()
	defer m.op.Unlock()
	m.downLocked()
}

func (m *manager) downLocked() {
	m.tunMu.Lock()
	t := m.tunnel
	m.tunnel = nil
	m.tunMu.Unlock()
	if t == nil {
		m.publish(func(s *ipc.Status) {
			if s.State == ipc.StateError {
				*s = ipc.Status{State: ipc.StateDown, Autostart: s.Autostart}
			}
		})
		return
	}
	m.mu.Lock()
	name := m.status.Tunnel
	m.mu.Unlock()
	m.publish(func(s *ipc.Status) { s.State = ipc.StateStopping })
	close(m.stop)
	t.Down()
	log.Printf("Tunnel %s is down", name)
	m.publish(func(s *ipc.Status) {
		*s = ipc.Status{State: ipc.StateDown, Autostart: s.Autostart}
	})
}

func (m *manager) autostartName() string {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, autostartName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (m *manager) autostart() (name, text string) {
	name = m.autostartName()
	if name == "" {
		return "", ""
	}
	dir, _ := bootstrap.ConfigsDir()
	b, err := os.ReadFile(filepath.Join(dir, autostartConf))
	if err != nil {
		log.Printf("Autostart configuration missing: %v", err)
		return "", ""
	}
	return name, string(b)
}

// setAutostart stores the tunnel to bring up at boot. The configs folder
// is readable only by SYSTEM and Administrators.
func (m *manager) setAutostart(name, text string) error {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return err
	}
	if name == "" {
		os.Remove(filepath.Join(dir, autostartName))
		os.Remove(filepath.Join(dir, autostartConf))
		log.Printf("Autostart cleared")
	} else {
		if _, err := config.Parse(text, name); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, autostartConf), []byte(text), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, autostartName), []byte(name), 0o600); err != nil {
			return err
		}
		log.Printf("Autostart set to %s", name)
	}
	m.publish(func(s *ipc.Status) { s.Autostart = name })
	return nil
}
