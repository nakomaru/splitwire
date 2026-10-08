package bootstrap

import (
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

	"splitwire/internal/stdriver"
	"splitwire/internal/svcwait"
)

// MullvadDaemonService is the Mullvad app's daemon, which claims the driver.
const MullvadDaemonService = "MullvadVPN"

// ntPath turns a Win32 path into the \??\ form that kernel driver services use.
func ntPath(p string) string { return `\??\` + p }

// imageFile turns a driver service's image path into a file path. Kernel
// services name it as \??\C:\..., \SystemRoot\... or relative to the
// Windows folder.
func imageFile(configured string) string {
	c := strings.Trim(configured, `"`)
	c = strings.TrimPrefix(c, `\??\`)
	root := os.Getenv("SystemRoot")
	switch {
	case len(c) > 12 && strings.EqualFold(c[:12], `\SystemRoot\`):
		return filepath.Join(root, c[12:])
	case !filepath.IsAbs(c):
		return filepath.Join(root, c)
	}
	return c
}

func sameImagePath(configured, want string) bool {
	return strings.EqualFold(filepath.Clean(imageFile(configured)), filepath.Clean(want))
}

// MullvadRunning reports whether the Mullvad daemon service is running.
func MullvadRunning(m *mgr.Mgr) bool {
	s, err := m.OpenService(MullvadDaemonService)
	if err != nil {
		return false
	}
	defer s.Close()
	st, err := s.Query()
	return err == nil && st.State != svc.Stopped
}

// EnsureDriverService registers the driver as a demand-start kernel service
// pointing at sysPath and starts it. A service the Mullvad app installed
// runs as it is, never changed, while the Mullvad daemon is stopped; one
// whose driver file is gone is repointed at sysPath.
func EnsureDriverService(sysPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(stdriver.ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		s, err = createDriverService(m, sysPath)
	}
	if err != nil {
		return fmt.Errorf("open %s service: %w", stdriver.ServiceName, err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("query %s service: %w", stdriver.ServiceName, err)
	}
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query %s service: %w", stdriver.ServiceName, err)
	}
	if !sameImagePath(cfg.BinaryPathName, sysPath) {
		if MullvadRunning(m) {
			return fmt.Errorf("the Mullvad VPN service is running and owns the split tunnel driver; stop it with `sc.exe stop %s`", MullvadDaemonService)
		}
		if other := imageFile(cfg.BinaryPathName); fileExists(other) {
			log.Printf("Using the Mullvad app's split tunnel driver service, which runs %s", other)
			if st.State == svc.Running {
				return nil
			}
			if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
				return fmt.Errorf("start %s driver: %w", stdriver.ServiceName, err)
			}
			return waitState(s, svc.Running)
		}
		log.Printf("Driver service %s points at the missing %s; repointing it", stdriver.ServiceName, cfg.BinaryPathName)
		if st.State == svc.Running {
			log.Printf("Driver service runs %s; restarting it from %s", cfg.BinaryPathName, sysPath)
			if err := stopService(s); err != nil {
				return err
			}
		}
		cfg.BinaryPathName = ntPath(sysPath)
		cfg.StartType = mgr.StartManual
		if err := s.UpdateConfig(cfg); err != nil {
			return fmt.Errorf("update %s service: %w", stdriver.ServiceName, err)
		}
		st.State = svc.Stopped
	}
	if st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start %s driver: %w", stdriver.ServiceName, err)
	}
	return waitState(s, svc.Running)
}

func createDriverService(m *mgr.Mgr, sysPath string) (*mgr.Service, error) {
	name, err := windows.UTF16PtrFromString(stdriver.ServiceName)
	if err != nil {
		return nil, err
	}
	display, err := windows.UTF16PtrFromString("Mullvad Split Tunnel Service")
	if err != nil {
		return nil, err
	}
	// mgr.CreateService quotes the image path, which kernel driver services
	// do not accept, so this calls the API directly.
	image, err := windows.UTF16PtrFromString(ntPath(sysPath))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateService(m.Handle, name, display, windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_KERNEL_DRIVER, windows.SERVICE_DEMAND_START, windows.SERVICE_ERROR_NORMAL,
		image, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	log.Printf("Registered driver service %s", stdriver.ServiceName)
	return &mgr.Service{Name: stdriver.ServiceName, Handle: h}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func stopService(s *mgr.Service) error {
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop %s: %w", s.Name, err)
	}
	return waitState(s, svc.Stopped)
}

func waitState(s *mgr.Service, want svc.State) error {
	st, err := svcwait.WaitState(s.Name, uint32(want), 30*time.Second)
	if errors.Is(err, svcwait.ErrTimeout) {
		return fmt.Errorf("%s did not reach state %d within 30 seconds (state %d)", s.Name, want, st.CurrentState)
	}
	if err != nil {
		return fmt.Errorf("wait for %s: %w", s.Name, err)
	}
	return nil
}

// RemoveDriverService stops and deletes the driver service when it points at
// splitwire's copy of the driver. A service owned by the Mullvad app stays.
func RemoveDriverService() error {
	sysPath, err := DriverPath()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(stdriver.ServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	if !sameImagePath(cfg.BinaryPathName, sysPath) {
		log.Printf("Leaving driver service %s in place; it runs %s", stdriver.ServiceName, cfg.BinaryPathName)
		return nil
	}
	stopped := true
	if err := stopService(s); err != nil {
		log.Printf("Warning: %v; the driver stays loaded until the next restart", err)
		stopped = false
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete %s service: %w", stdriver.ServiceName, err)
	}
	if stopped {
		log.Printf("Removed driver service %s", stdriver.ServiceName)
	} else {
		log.Printf("Driver service %s goes at the next restart", stdriver.ServiceName)
	}
	return nil
}
