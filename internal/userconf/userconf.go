// Package userconf locates tunnel configurations in %APPDATA%\splitwire.
package userconf

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

// Dir is the configuration folder, %APPDATA%\splitwire.
func Dir() (string, error) {
	appData, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil {
		return "", fmt.Errorf("locate AppData: %w", err)
	}
	return filepath.Join(appData, "splitwire"), nil
}

// EnsureDir creates the configuration folder.
func EnsureDir() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return dir, os.MkdirAll(dir, 0o700)
}

// IsPath reports whether arg names a file rather than a tunnel.
func IsPath(arg string) bool {
	return strings.ContainsAny(arg, `\/:`) || strings.EqualFold(filepath.Ext(arg), ".conf")
}

// Resolve turns a tunnel argument into a configuration path. %VARIABLES%
// expand, since PowerShell leaves them alone. A bare name means
// <Dir>\<name>.conf; a bare file name such as home.conf is looked up in the
// current folder first and then in Dir; anything else is a path.
func Resolve(arg string) (string, error) {
	arg, err := expandEnv(arg)
	if err != nil {
		return "", err
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	if !IsPath(arg) {
		return filepath.Join(dir, arg+".conf"), nil
	}
	abs, err := filepath.Abs(arg)
	if err != nil {
		return "", err
	}
	if filepath.Base(arg) == arg {
		if _, err := os.Stat(abs); os.IsNotExist(err) {
			return filepath.Join(dir, arg), nil
		}
	}
	return abs, nil
}

func expandEnv(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	src, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return "", err
	}
	n, err := windows.ExpandEnvironmentStrings(src, nil, 0)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, n)
	if _, err := windows.ExpandEnvironmentStrings(src, &buf[0], n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

// Names lists the tunnels in the configuration folder.
func Names() ([]string, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.EqualFold(filepath.Ext(e.Name()), ".conf") {
			names = append(names, strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())))
		}
	}
	sort.Strings(names)
	return names, nil
}
