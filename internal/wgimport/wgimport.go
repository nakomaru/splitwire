// Package wgimport copies tunnels from the WireGuard app into the splitwire
// configuration folder.
//
// The WireGuard app stores each tunnel as Data\Configurations\<name>.conf.dpapi,
// encrypted with DPAPI by its manager service running as LocalSystem, so only
// code running as LocalSystem can decrypt them. Import registers a one-shot
// service that runs this executable as LocalSystem to decrypt the files into
// a folder only SYSTEM and Administrators can read, then copies them out and
// removes the folder and the service.
package wgimport

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/conf/dpapi"

	"splitwire/internal/bootstrap"
	"splitwire/internal/userconf"
)

// HelperCommand is the hidden CLI command the one-shot service runs.
const HelperCommand = "wg-decrypt-helper"

const (
	helperService = "splitwire-wg-import"
	encSuffix     = ".conf.dpapi"
	errorsFile    = "errors.txt"
)

// template is appended to imported configurations.
const template = `
# Uncomment to split this tunnel by app (see splitwire's example.conf):
# [Splitwire]
# Mode = include
# App = C:\Windows\System32\curl.exe
`

func wireguardConfigDir() (string, error) {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(pf, "WireGuard", "Data", "Configurations"), nil
}

// AppInstalled reports whether the WireGuard app is installed.
func AppInstalled() bool {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(pf, "WireGuard", "wireguard.exe"))
	return err == nil
}

// RemoveHelperService deletes the decryption service when an interrupted
// import left it behind.
func RemoveHelperService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(helperService)
	if err != nil {
		return nil
	}
	defer s.Close()
	s.Control(svc.Stop)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete %s: %w", helperService, err)
	}
	return nil
}

// Available lists the tunnel names stored by the WireGuard app.
func Available() ([]string, error) {
	dir, err := wireguardConfigDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(strings.ToLower(e.Name()), encSuffix) {
			names = append(names, e.Name()[:len(e.Name())-len(encSuffix)])
		}
	}
	sort.Strings(names)
	return names, nil
}

// Result reports what Import did with each tunnel.
type Result struct {
	Imported, Skipped []string
}

// Import copies the named tunnels, or all when names is empty, into the
// configuration folder. Existing files stay unless overwrite is set.
func Import(names []string, overwrite bool) (Result, error) {
	var res Result
	available, err := Available()
	if err != nil {
		return res, err
	}
	if len(names) == 0 {
		names = available
	}
	if len(names) == 0 {
		return res, errors.New("the WireGuard app has no tunnels")
	}
	have := make(map[string]string, len(available))
	for _, n := range available {
		have[strings.ToLower(n)] = n
	}
	dst, err := userconf.EnsureDir()
	if err != nil {
		return res, err
	}
	var todo []string
	for _, n := range names {
		stored, ok := have[strings.ToLower(n)]
		if !ok {
			return res, fmt.Errorf("the WireGuard app has no tunnel named %s", n)
		}
		if _, err := os.Stat(filepath.Join(dst, stored+".conf")); err == nil && !overwrite {
			res.Skipped = append(res.Skipped, stored)
			continue
		}
		todo = append(todo, stored)
	}
	if len(todo) == 0 {
		return res, nil
	}

	if err := bootstrap.EnsureDirs(); err != nil {
		return res, err
	}
	root, err := bootstrap.Root()
	if err != nil {
		return res, err
	}
	suffix := make([]byte, 8)
	rand.Read(suffix)
	tmp := filepath.Join(root, "import-"+hex.EncodeToString(suffix))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	if err := bootstrap.Restrict(tmp); err != nil {
		return res, err
	}

	if err := runHelper(tmp, todo); err != nil {
		return res, err
	}
	for _, n := range todo {
		b, err := os.ReadFile(filepath.Join(tmp, n+".conf"))
		if err != nil {
			return res, fmt.Errorf("decrypted %s missing: %w", n, err)
		}
		text := strings.TrimRight(string(b), "\r\n") + "\n" + template
		if err := os.WriteFile(filepath.Join(dst, n+".conf"), []byte(text), 0o600); err != nil {
			return res, err
		}
		res.Imported = append(res.Imported, n)
	}
	return res, nil
}

func runHelper(outDir string, names []string) error {
	exe, err := bootstrap.InstallExe()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if old, err := m.OpenService(helperService); err == nil {
		old.Delete()
		old.Close()
	}
	args := append([]string{HelperCommand, outDir}, names...)
	s, err := m.CreateService(helperService, exe, mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorIgnore,
		DisplayName:  "splitwire WireGuard import (temporary)",
	}, args...)
	if err != nil {
		return fmt.Errorf("create %s service: %w", helperService, err)
	}
	defer func() {
		s.Delete()
		s.Close()
	}()
	if err := s.Start(); err != nil {
		return fmt.Errorf("start %s service: %w", helperService, err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			if st.ServiceSpecificExitCode != 0 {
				detail, _ := os.ReadFile(filepath.Join(outDir, errorsFile))
				return fmt.Errorf("could not decrypt %d tunnel(s): %s", st.ServiceSpecificExitCode, strings.TrimSpace(string(detail)))
			}
			if st.Win32ExitCode != 0 && st.Win32ExitCode != uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
				return fmt.Errorf("%s service failed: %w", helperService, windows.Errno(st.Win32ExitCode))
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s service did not finish within a minute", helperService)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type helper struct {
	outDir string
	names  []string
}

// RunHelper is the one-shot service body: it decrypts the named tunnels into outDir.
func RunHelper(outDir string, names []string) error {
	return svc.Run(helperService, &helper{outDir: outDir, names: names})
}

func (h *helper) Execute(_ []string, _ <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running}
	failures := h.decrypt()
	changes <- svc.Status{State: svc.StopPending}
	if len(failures) == 0 {
		return false, 0
	}
	os.WriteFile(filepath.Join(h.outDir, errorsFile), []byte(strings.Join(failures, "\n")), 0o600)
	return true, uint32(len(failures))
}

func (h *helper) decrypt() (failures []string) {
	src, err := wireguardConfigDir()
	if err != nil {
		return []string{err.Error()}
	}
	for _, n := range h.names {
		if err := decryptOne(filepath.Join(src, n+encSuffix), filepath.Join(h.outDir, n+".conf"), n); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", n, err))
		}
	}
	return failures
}

func decryptOne(src, dst, name string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	plain, err := dpapi.Decrypt(b, name)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, plain, 0o600)
}
