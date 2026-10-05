// Package service installs tunnels as Windows services and runs them.
package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/engine"
	"splitwire/internal/logx"
)

// Prefix starts the name of every tunnel service.
const Prefix = "splitwire$"

// RunCommand is the hidden CLI command a tunnel service executes.
const RunCommand = "service-run"

// Name is the service name of a tunnel.
func Name(tunnel string) string { return Prefix + tunnel }

// Install copies the configuration into the install root, with App entries
// expanded for the installing user, and registers and starts an
// auto-start service for it.
func Install(confPath string) error {
	c, err := config.Load(confPath)
	if err != nil {
		return err
	}
	text, err := c.WithExpandedApps()
	if err != nil {
		return err
	}
	if err := bootstrap.EnsureDirs(); err != nil {
		return err
	}
	exe, err := bootstrap.InstallExe()
	if err != nil {
		return err
	}
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return err
	}
	stored := filepath.Join(dir, c.WG.Name+".conf")
	if err := os.WriteFile(stored, []byte(text), 0o600); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	name := Name(c.WG.Name)
	if s, err := m.OpenService(name); err == nil {
		s.Close()
		return fmt.Errorf("tunnel %s is already installed; uninstall it first", c.WG.Name)
	}
	s, err := m.CreateService(name, exe, mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Nsi", "TcpIp"},
		DisplayName:  "SplitWire tunnel: " + c.WG.Name,
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, RunCommand, stored)
	if err != nil {
		return fmt.Errorf("create service %s: %w", name, err)
	}
	defer s.Close()
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, 24*60*60); err != nil {
		log.Printf("Warning: set recovery actions: %v", err)
	}
	// Failed starts, such as endpoint lookups before the network is up at
	// boot, exit cleanly with an error code; this makes them count for recovery.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		log.Printf("Warning: set recovery on failure exits: %v", err)
	}
	log.Printf("Installed service %s with configuration %s", name, stored)
	if err := s.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	log.Printf("Started %s; its log is in %s", name, mustLogPath(c.WG.Name))
	return nil
}

// Uninstall stops and deletes a tunnel service and its stored configuration.
func Uninstall(tunnel string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	name := Name(tunnel)
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer s.Close()
	if err := stop(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	if dir, err := bootstrap.ConfigsDir(); err == nil {
		os.Remove(filepath.Join(dir, tunnel+".conf"))
	}
	log.Printf("Uninstalled %s", name)
	return nil
}

func stop(s *mgr.Service) error {
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
		time.Sleep(200 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

// Start starts an installed tunnel service.
func Start(tunnel string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name(tunnel))
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

// Stop stops an installed tunnel service.
func Stop(tunnel string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name(tunnel))
	if err != nil {
		return err
	}
	defer s.Close()
	return stop(s)
}

// Installed describes an installed tunnel service.
type Installed struct {
	Tunnel string
	State  svc.State
}

// List returns installed tunnel services.
func List() ([]Installed, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	var out []Installed
	for _, n := range names {
		if !strings.HasPrefix(strings.ToLower(n), strings.ToLower(Prefix)) {
			continue
		}
		in := Installed{Tunnel: n[len(Prefix):]}
		if s, err := m.OpenService(n); err == nil {
			if st, err := s.Query(); err == nil {
				in.State = st.State
			}
			s.Close()
		}
		out = append(out, in)
	}
	return out, nil
}

func logPath(tunnel string) (string, error) {
	dir, err := bootstrap.LogsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, tunnel+".log"), nil
}

func mustLogPath(tunnel string) string {
	p, _ := logPath(tunnel)
	return p
}

type handler struct {
	confPath string
}

// Run executes the tunnel service for a stored configuration.
func Run(confPath string) error {
	name := strings.TrimSuffix(filepath.Base(confPath), filepath.Ext(confPath))
	return svc.Run(Name(name), &handler{confPath: confPath})
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	name := strings.TrimSuffix(filepath.Base(h.confPath), filepath.Ext(h.confPath))
	if p, err := logPath(name); err == nil {
		if f, err := logx.Setup(p); err == nil {
			defer f.Close()
		}
	}

	fail := func(err error) (bool, uint32) {
		log.Printf("Error: %v", err)
		changes <- svc.Status{State: svc.StopPending}
		return true, 1
	}
	c, err := config.Load(h.confPath)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Up starts other services (the WireGuardNT and split tunnel drivers).
	// At boot the service manager holds those starts until this service
	// leaves the start-pending state, so it reports running first.
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	t, err := engine.Up(ctx, c)
	if err != nil {
		return fail(err)
	}
	log.Printf("Tunnel %s is up (mode %s)", c.WG.Name, c.Mode)
	for req := range r {
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			log.Printf("Shutting down tunnel %s", c.WG.Name)
			t.Down()
			return false, 0
		case svc.Interrogate:
			changes <- req.CurrentStatus
		}
	}
	t.Down()
	return false, 0
}
