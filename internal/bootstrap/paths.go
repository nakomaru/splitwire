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

// InstallExe copies the running executable into the install root, so the
// service never runs from a user-writable location. A running copy is moved
// aside, which Windows permits for executables in use.
func InstallExe() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	bin, err := BinDir()
	if err != nil {
		return "", err
	}
	dst := filepath.Join(bin, "splitwire.exe")
	if strings.EqualFold(filepath.Clean(self), dst) {
		return dst, nil
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	return dst, replaceFile(dst, b)
}

// TrayExe is the file name of the tray app, built next to splitwire.exe.
const TrayExe = "splitwire-tray.exe"

// InstallTray copies the tray app from beside the running executable into
// the install root. It reports an empty path when there is none to copy.
func InstallTray() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	src := filepath.Join(filepath.Dir(self), TrayExe)
	b, err := os.ReadFile(src)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	bin, err := BinDir()
	if err != nil {
		return "", err
	}
	dst := filepath.Join(bin, TrayExe)
	if strings.EqualFold(filepath.Clean(src), dst) {
		return dst, nil
	}
	return dst, replaceFile(dst, b)
}

// replaceFile writes b to dst unless dst already holds it, moving a running
// copy aside first.
func replaceFile(dst string, b []byte) error {
	if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, b) {
		return nil
	}
	if _, err := os.Stat(dst); err == nil {
		aside := dst + ".old"
		os.Remove(aside)
		if err := os.Rename(dst, aside); err != nil {
			return fmt.Errorf("move aside %s: %w", dst, err)
		}
	}
	return os.WriteFile(dst, b, 0o755)
}
