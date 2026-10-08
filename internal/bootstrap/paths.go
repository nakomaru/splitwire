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

// RemoveRoot deletes the install root, except the file keep and the
// folders holding it when keep is set. Files in use, such as the running
// tray app, are scheduled for deletion at the next restart along with
// their folders; it reports how many.
func RemoveRoot(keep string) (pending int, err error) {
	root, err := Root()
	if err != nil {
		return 0, err
	}
	return removeTree(root, keep)
}

// removeTree deletes root as RemoveRoot does.
func removeTree(root, keep string) (pending int, err error) {
	if keep == "" && os.RemoveAll(root) == nil {
		return 0, nil
	}
	var paths []string
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil {
			paths = append(paths, path)
		}
		return nil
	})
	// Children before their folders.
	for i := len(paths) - 1; i >= 0; i-- {
		p := paths[i]
		if keep != "" && (strings.EqualFold(p, keep) || hasPathPrefix(keep, p)) {
			continue
		}
		if err := os.Remove(p); err == nil || os.IsNotExist(err) {
			continue
		}
		if err := deleteAtRestart(p); err != nil {
			return pending, fmt.Errorf("schedule %s for deletion: %w", p, err)
		}
		pending++
	}
	return pending, nil
}

// hasPathPrefix reports whether path lies inside the folder dir.
func hasPathPrefix(path, dir string) bool {
	return len(path) > len(dir) && strings.EqualFold(path[:len(dir)], dir) && os.IsPathSeparator(path[len(dir)])
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
		aside := asidePath(dst)
		if err := os.Rename(dst, aside); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("move aside %s: %w", dst, err)
		}
	}
	return os.Rename(tmp, dst)
}

// asidePath deletes the copies of dst that earlier replacements moved aside
// and that no process runs anymore, and returns a free name to move dst to.
// Windows renames a running executable but neither deletes nor replaces it,
// so a copy still running keeps its name and dst takes the next one.
func asidePath(dst string) string {
	dir, base := filepath.Split(dst)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base+".old") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	aside := dst + ".old"
	for i := 1; ; i++ {
		if _, err := os.Lstat(aside); os.IsNotExist(err) {
			return aside
		}
		aside = fmt.Sprintf("%s.old%d", dst, i)
	}
}
