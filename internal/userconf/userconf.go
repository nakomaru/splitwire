// Package userconf locates tunnel configurations in %APPDATA%\splitwire.
package userconf

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"splitwire/internal/config"
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

// FirstProxyPort is the lowest port EnsureProxy assigns.
const FirstProxyPort = 1080

// claimedPorts lists the Proxy ports of the tunnels in Dir other than the
// one at path, by tunnel name.
func claimedPorts(path string) map[uint16]string {
	claimed := make(map[uint16]string)
	names, _ := Names()
	for _, n := range names {
		other, err := Resolve(n)
		if err != nil || strings.EqualFold(other, path) {
			continue
		}
		if oc, err := config.Load(other); err == nil && oc.Proxy.IsValid() {
			claimed[oc.Proxy.Port()] = n
		}
	}
	return claimed
}

func portFree(ap netip.AddrPort) bool {
	ln, err := net.Listen("tcp", ap.String())
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// EnsureProxy returns the Proxy address of the configuration at path. A
// configuration without one gets the lowest port from FirstProxyPort up
// that no other tunnel in Dir claims and nothing listens on, written to its
// [Splitwire] section so apps can keep using that address.
func EnsureProxy(path string) (netip.AddrPort, error) {
	c, err := config.Load(path)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if c.Proxy.IsValid() {
		return c.Proxy, nil
	}
	claimed := claimedPorts(path)
	for port := FirstProxyPort; port <= 65535; port++ {
		ap := netip.AddrPortFrom(config.ProxyHost, uint16(port))
		if claimed[uint16(port)] != "" || !portFree(ap) {
			continue
		}
		if err := setKey(path, "Proxy", strconv.Itoa(port)); err != nil {
			return netip.AddrPort{}, err
		}
		return ap, nil
	}
	return netip.AddrPort{}, fmt.Errorf("no free port for the proxy")
}

// SetProxyPort changes the port of the configuration's Proxy address,
// keeping its IP address. running tells that the tunnel's own proxy holds
// the current port, which then counts as free.
func SetProxyPort(path string, port uint16, running bool) error {
	if port == 0 {
		return fmt.Errorf("the port must be 1 to 65535")
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	host := config.ProxyHost
	if c.Proxy.IsValid() {
		host = c.Proxy.Addr()
		if c.Proxy.Port() == port {
			return nil
		}
	}
	if other := claimedPorts(path)[port]; other != "" {
		return fmt.Errorf("port %d belongs to %s", port, other)
	}
	ap := netip.AddrPortFrom(host, port)
	if !portFree(ap) && !(running && c.Proxy == ap) {
		return fmt.Errorf("another program is using port %d", port)
	}
	val := strconv.Itoa(int(port))
	if host != config.ProxyHost {
		val = ap.String()
	}
	return setKey(path, "Proxy", val)
}

// setKey sets key = val in the file's [Splitwire] sections: it replaces the
// key's line when one exists, and otherwise adds the line to the first
// section, or to a new one at the end.
func setKey(path, key, val string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(b)
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
	}
	lines := strings.Split(text, nl)
	entry := key + " = " + val
	first := -1
	inSection := false
	for i, line := range lines {
		code, _, _ := strings.Cut(line, "#")
		stripped := strings.TrimSpace(code)
		if strings.HasPrefix(stripped, "[") && !strings.Contains(stripped, "=") {
			inSection = strings.EqualFold(stripped, "[Splitwire]")
			if inSection && first < 0 {
				first = i
			}
			continue
		}
		if k, _, ok := strings.Cut(stripped, "="); inSection && ok && strings.EqualFold(strings.TrimSpace(k), key) {
			lines[i] = entry
			return os.WriteFile(path, []byte(strings.Join(lines, nl)), 0o600)
		}
	}
	if first >= 0 {
		lines = append(lines[:first+1], append([]string{entry}, lines[first+1:]...)...)
		return os.WriteFile(path, []byte(strings.Join(lines, nl)), 0o600)
	}
	text = strings.TrimRight(text, "\r\n") + nl + nl + "[Splitwire]" + nl + entry + nl
	return os.WriteFile(path, []byte(text), 0o600)
}
