// Package bootstrap installs the components splitwire runs on: wireguard.dll from
// WireGuardNT and the Mullvad split tunnel driver, each pinned by SHA-256.
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Layout of the install root, %ProgramFiles%\splitwire.
const (
	binDir     = "bin"
	configsDir = "configs"
	logsDir    = "logs"
)

// adminOnlySDDL grants full control to SYSTEM and Administrators and nothing
// to anyone else, with inheritance to children.
const adminOnlySDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// Root is the install root.
func Root() (string, error) {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", fmt.Errorf("locate Program Files: %w", err)
	}
	return filepath.Join(pf, "splitwire"), nil
}

func subdir(name string) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name), nil
}

// BinDir holds the service copy of splitwire.exe, wireguard.dll and the driver.
func BinDir() (string, error) { return subdir(binDir) }

// ConfigsDir holds tunnel configurations of installed services.
func ConfigsDir() (string, error) { return subdir(configsDir) }

// LogsDir holds service logs.
func LogsDir() (string, error) { return subdir(logsDir) }

// EnsureDirs creates the install root and its subdirectories, restricting
// configs and logs to SYSTEM and Administrators since configs hold private keys.
func EnsureDirs() error {
	root, err := Root()
	if err != nil {
		return err
	}
	for _, d := range []struct {
		name       string
		restricted bool
	}{{binDir, false}, {configsDir, true}, {logsDir, true}} {
		p := filepath.Join(root, d.name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			return err
		}
		if d.restricted {
			if err := Restrict(p); err != nil {
				return fmt.Errorf("restrict %s: %w", p, err)
			}
		}
	}
	return nil
}

// Restrict limits path to SYSTEM and Administrators.
func Restrict(path string) error {
	sd, err := windows.SecurityDescriptorFromString(adminOnlySDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fileMatches reports whether path exists with the given SHA-256.
func fileMatches(path, wantSHA256 string) bool {
	b, err := os.ReadFile(path)
	return err == nil && sha256Hex(b) == wantSHA256
}

// writeVerified writes b to path through a temporary file after checking its hash.
func writeVerified(path string, b []byte, wantSHA256 string) error {
	if got := sha256Hex(b); got != wantSHA256 {
		return fmt.Errorf("%s: SHA-256 %s, want %s", filepath.Base(path), got, wantSHA256)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ExePath is the installed splitwire.exe, which the services run.
func ExePath() (string, error) {
	bin, err := BinDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(bin, "splitwire.exe"), nil
}

// InstallExe copies the running executable into the install root, so the
// service never runs from a user-writable location. A running copy is moved
// aside, which Windows permits for executables in use.
func InstallExe() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	dst, err := ExePath()
	if err != nil {
		return "", err
	}
	if strings.EqualFold(filepath.Clean(self), dst) {
		return dst, nil
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	return dst, replaceFile(dst, b)
}

// ReplaceExe makes b the installed executable, moving a running copy aside.
func ReplaceExe(b []byte) error {
	dst, err := ExePath()
	if err != nil {
		return err
	}
	return replaceFile(dst, b)
}

// legacyTrayExe is the separate tray executable of earlier installs.
const legacyTrayExe = "splitwire-tray.exe"

// RemoveLegacyTray deletes the separate tray executable, or schedules it
// for deletion at the next restart while it runs.
func RemoveLegacyTray() {
	bin, err := BinDir()
	if err != nil {
		return
	}
	path := filepath.Join(bin, legacyTrayExe)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		deleteAtRestart(path)
	}
}

// RemoveRoot deletes the install root. Files in use, such as the running
// tray app, are scheduled for deletion at the next restart along with
// their folders; it reports how many.
func RemoveRoot() (pending int, err error) {
	root, err := Root()
	if err != nil {
		return 0, err
	}
	if os.RemoveAll(root) == nil {
		return 0, nil
	}
	var left []string
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil {
			left = append(left, path)
		}
		return nil
	})
	// Children before their folders.
	for i := len(left) - 1; i >= 0; i-- {
		if err := deleteAtRestart(left[i]); err != nil {
			return pending, fmt.Errorf("schedule %s for deletion: %w", left[i], err)
		}
		pending++
	}
	return pending, nil
}

func deleteAtRestart(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

// replaceFile writes b to dst unless dst already holds it, moving a running
// copy aside. The new file is written in full before dst moves, so a failed
// write leaves dst as it was.
func replaceFile(dst string, b []byte) error {
	if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, b) {
		return nil
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		aside := dst + ".old"
		os.Remove(aside)
		if err := os.Rename(dst, aside); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("move aside %s: %w", dst, err)
		}
	}
	return os.Rename(tmp, dst)
}
