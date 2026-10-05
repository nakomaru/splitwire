// Package manager is the splitwire service that runs tunnels for the tray app.
// It runs as LocalSystem and serves the ipc protocol on a pipe that only
// SYSTEM, Administrators and the installing user can open.
package manager

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"splitwire/internal/bootstrap"
	"splitwire/internal/ipc"
	"splitwire/internal/shortcut"
	"splitwire/internal/tray"
)

// ServiceName is the manager service.
const ServiceName = ipc.ServiceName

// RunCommand is the hidden CLI command the service executes.
const RunCommand = "manager-run"

// statsInterval is how often watchers get fresh peer statistics.
const statsInterval = 2 * time.Second

// bootFile holds the tunnels to bring up at boot, with their configuration
// text, in the configs folder that only SYSTEM and Administrators can read.
const bootFile = "boot.json"

// Files of the single boot tunnel that bootFile replaces.
const (
	legacyBootName = "autostart.name"
	legacyBootConf = "autostart.conf"
)

// Choice is an install setting: kept as it is, turned on or turned off.
type Choice int

const (
	Keep Choice = iota
	On
	Off
)

// Options are the choices of a manager install.
type Options struct {
	// StartMenu adds or removes the Start menu shortcut. Kept, an existing
	// shortcut is rewritten.
	StartMenu Choice
	// Boot turns bringing running tunnels back up at boot on, keeping a
	// list of boot tunnels that exists already, or off.
	Boot Choice
}

// Install copies the executable into the install root and registers and
// starts the manager service for the calling user. Installing again
// updates the executable and restarts the service.
func Install(opts Options) error {
	if n, err := bootstrap.CancelPendingDeletes(); err != nil {
		log.Printf("Warning: cancel deletions left by an uninstall: %v", err)
	} else if n > 0 {
		log.Printf("Canceled %d deletions an uninstall left for the next restart", n)
	}
	if err := bootstrap.EnsureDirs(); err != nil {
		return err
	}
	exe, err := bootstrap.InstallExe()
	if err != nil {
		return err
	}
	bootstrap.RemoveLegacyTray()
	if lnk, err := shortcut.StartMenu(tray.StartMenuName); err == nil {
		_, statErr := os.Stat(lnk)
		switch {
		case opts.StartMenu == Off:
			if statErr == nil {
				os.Remove(lnk)
				log.Printf("Removed the Start menu shortcut")
			}
		case opts.StartMenu == On || statErr == nil:
			if err := shortcut.Create(lnk, exe, tray.Command, "WireGuard with per-app split tunneling"); err != nil {
				log.Printf("Warning: Start menu shortcut: %v", err)
			} else {
				log.Printf("Start menu shortcut: %s", lnk)
			}
		}
	}
	if dir, err := bootstrap.ConfigsDir(); err == nil && opts.Boot != Keep {
		path := filepath.Join(dir, bootFile)
		_, statErr := os.Stat(path)
		switch {
		case opts.Boot == On && os.IsNotExist(statErr):
			if err := writeBoot(path, nil); err != nil {
				log.Printf("Warning: turn on reconnecting at boot: %v", err)
			}
		case opts.Boot == Off && statErr == nil:
			os.Remove(path)
		}
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
		for _, f := range []string{bootFile, legacyBootName, legacyBootConf} {
			os.Remove(filepath.Join(dir, f))
		}
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
