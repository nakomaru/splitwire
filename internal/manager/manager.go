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

// runningFile holds the running tunnels with their configuration text,
// and resumeFile marks a stop for an update, after which the manager
// brings those tunnels back.
const (
	runningFile = "running.json"
	resumeFile  = "resume"
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
	// Boot turns bringing running tunnels back up at boot on, keeping a
	// list of boot tunnels that exists already, or off.
	Boot Choice
	// User is the SID of the user to allow, by default the one this
	// process runs as. An app elevated with another account's password
	// passes its own user here.
	User string
}

// Install copies the executable into the install root, adds the user to
// the users who may control the manager, and registers and starts the
// manager service. Installing again updates the executable and restarts
// the service.
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
	if opts.User == "" {
		if opts.User, err = CurrentUser(); err != nil {
			return err
		}
	}
	if err := addUser(opts.User); err != nil {
		return err
	}

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
		DisplayName:  "SplitWire manager",
		Description:  "Runs SplitWire tunnels for the SplitWire app.",
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	s, err := m.OpenService(ServiceName)
	if err == nil {
		log.Printf("Updating the existing %s service", ServiceName)
		if dir, err := bootstrap.ConfigsDir(); err == nil {
			if err := os.WriteFile(filepath.Join(dir, resumeFile), nil, 0o600); err != nil {
				log.Printf("Warning: running tunnels will not reconnect: %v", err)
			}
		}
		if err := stopService(s); err != nil {
			s.Close()
			return err
		}
		cfg.BinaryPathName = windows.EscapeArg(exe) + " " + RunCommand
		if err := s.UpdateConfig(cfg); err != nil {
			s.Close()
			return fmt.Errorf("update %s service: %w", ServiceName, err)
		}
	} else {
		s, err = m.CreateService(ServiceName, exe, cfg, RunCommand)
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
		for _, f := range []string{bootFile, runningFile, resumeFile, usersFile} {
			os.Remove(filepath.Join(dir, f))
		}
	}
	log.Printf("Removed the %s service", ServiceName)
	return nil
}

// Installed reports whether the manager service exists. It asks only for
// the right to query the service, which every user has.
func Installed() bool {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(m)
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return false
	}
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(s)
	return true
}
