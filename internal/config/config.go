// Package config reads tunnel configurations: a WireGuard .conf file with an
// optional [SplitWire] section. Without that section the file is an ordinary
// WireGuard configuration, and the WireGuard app ignores nothing it needs.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
)

// Mode selects which traffic uses the tunnel.
type Mode int

const (
	// ModeFull routes by AllowedIPs, like the WireGuard app.
	ModeFull Mode = iota
	// ModeInclude sends only the listed apps through the tunnel.
	ModeInclude
	// ModeExclude sends everything but the listed apps through the tunnel.
	ModeExclude
)

func (m Mode) String() string {
	switch m {
	case ModeInclude:
		return "include"
	case ModeExclude:
		return "exclude"
	}
	return "full"
}

// ProxyHost is the address a proxy given only a port listens on.
var ProxyHost = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// ParseProxy parses a Proxy value: a port, or an IP address and port.
func ParseProxy(v string) (netip.AddrPort, error) {
	if port, err := strconv.ParseUint(v, 10, 16); err == nil {
		if port == 0 {
			return netip.AddrPort{}, fmt.Errorf("Proxy port must be 1 to 65535")
		}
		return netip.AddrPortFrom(ProxyHost, uint16(port)), nil
	}
	ap, err := netip.ParseAddrPort(v)
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("Proxy must be a port or an address and port, not %q", v)
	}
	return ap, nil
}

// Config is a parsed tunnel configuration.
type Config struct {
	WG *conf.Config

	Mode Mode
	// ModeSet reports that the text sets Mode. A Mode = full setting keeps
	// App entries for a later switch to include or exclude.
	ModeSet bool
	// Apps are App entries as written: absolute paths, optionally with
	// %VARIABLE% references and glob patterns.
	Apps []string

	// Proxy is the address the tunnel's SOCKS5 and HTTP proxy listens on
	// when it runs as a proxy. It is invalid when unset.
	Proxy netip.AddrPort

	wgText string
}

const sectionName = "[splitwire]"

// Load reads a configuration file. The tunnel takes its name from the file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return Parse(string(b), name)
}

// Parse parses configuration text for the tunnel called name.
func Parse(text, name string) (*Config, error) {
	text = strings.TrimPrefix(text, string(rune(0xFEFF)))
	c := &Config{}

	var wgLines []string
	inSection := false
	for i, line := range strings.Split(text, "\n") {
		code, _, _ := strings.Cut(line, "#")
		stripped := strings.TrimSpace(code)
		if strings.HasPrefix(stripped, "[") && !strings.Contains(stripped, "=") {
			inSection = strings.EqualFold(stripped, sectionName)
			if inSection {
				wgLines = append(wgLines, "")
				continue
			}
		}
		if !inSection {
			wgLines = append(wgLines, line)
			continue
		}
		// Keep line numbers aligned for WireGuard parse errors.
		wgLines = append(wgLines, "")
		if stripped == "" {
			continue
		}
		key, val, ok := strings.Cut(stripped, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '=' in %q", i+1, stripped)
		}
		if err := c.set(strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}

	c.wgText = strings.Join(wgLines, "\n")
	wg, err := conf.FromWgQuick(c.wgText, name)
	if err != nil {
		return nil, err
	}
	wg.DeduplicateNetworkEntries()
	c.WG = wg
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) set(key, val string) error {
	switch key {
	case "mode":
		c.ModeSet = true
		switch strings.ToLower(val) {
		case "full":
			c.Mode = ModeFull
		case "include":
			c.Mode = ModeInclude
		case "exclude":
			c.Mode = ModeExclude
		default:
			return fmt.Errorf("Mode must be full, include or exclude, not %q", val)
		}
	case "app":
		if val == "" {
			return fmt.Errorf("App needs a path")
		}
		c.Apps = append(c.Apps, val)
	case "killswitch", "allowlan", "strictdns":
		// Accepted and ignored: the kill switch, its local network exception
		// and the DNS restriction are machine-wide settings.
	case "proxy":
		ap, err := ParseProxy(val)
		if err != nil {
			return err
		}
		c.Proxy = ap
	case "proxyvia":
		// Accepted and ignored: proxies connect directly to their endpoints.
	default:
		return fmt.Errorf("unknown [SplitWire] key %q", key)
	}
	return nil
}

func (c *Config) validate() error {
	if c.Mode != ModeFull && len(c.Apps) == 0 {
		return fmt.Errorf("Mode = %s needs at least one App", c.Mode)
	}
	if c.Mode == ModeFull && len(c.Apps) > 0 && !c.ModeSet {
		return fmt.Errorf("App entries need Mode = include or Mode = exclude")
	}
	if c.Mode == ModeInclude && c.WG.Interface.TableOff {
		return fmt.Errorf("Mode = include manages routes and cannot combine with Table = off")
	}
	if c.Mode != ModeFull && !hasAddress(c.WG, true) && !hasAddress(c.WG, false) {
		return fmt.Errorf("Mode = %s needs an [Interface] Address", c.Mode)
	}
	return nil
}

func hasAddress(wg *conf.Config, v4 bool) bool {
	for _, a := range wg.Interface.Addresses {
		if a.Addr().Is4() == v4 {
			return true
		}
	}
	return false
}

// TunnelAddress is the first interface address of the family, if any.
func (c *Config) TunnelAddress(v4 bool) netip.Addr {
	for _, a := range c.WG.Interface.Addresses {
		if a.Addr().Is4() == v4 {
			return a.Addr()
		}
	}
	return netip.Addr{}
}

// IsDefaultRoute reports whether an AllowedIPs prefix spans at least half of
// its address space, which wg-quick style configs use to override the
// system default route (0.0.0.0/1 and 128.0.0.0/1).
func IsDefaultRoute(p netip.Prefix) bool { return p.Bits() <= 1 }

// HasDefaultRoute reports whether any peer's AllowedIPs contain a default route.
func (c *Config) HasDefaultRoute() bool {
	for _, peer := range c.WG.Peers {
		for _, ip := range peer.AllowedIPs {
			if IsDefaultRoute(ip) {
				return true
			}
		}
	}
	return false
}

// ScopedDNS reports whether the tunnel's DNS servers answer only for the
// domains its DNS line names: it carries every app's traffic to its own
// ranges, without a default route, and names both servers and domains.
// Lookups of those names then travel through the tunnel, and every other
// name goes to the system's servers.
func (c *Config) ScopedDNS() bool {
	return c.Mode == ModeFull && !c.WG.Interface.TableOff && !c.HasDefaultRoute() &&
		len(c.WG.Interface.DNS) > 0 && len(c.WG.Interface.DNSSearch) > 0
}

func expandEnv(s string) (string, error) {
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

// ExpandApps expands environment variables and globs in App entries. Paths
// without glob characters pass through even when the file does not exist
// yet. Warnings report patterns that matched nothing.
func (c *Config) ExpandApps() (paths []string, warnings []string, err error) {
	seen := make(map[string]bool)
	for _, a := range c.Apps {
		matches, err := ExpandApp(a)
		if err != nil {
			return nil, nil, err
		}
		if len(matches) == 0 {
			warnings = append(warnings, fmt.Sprintf("App %s matches no files", a))
		}
		for _, m := range matches {
			if k := strings.ToLower(m); !seen[k] {
				seen[k] = true
				paths = append(paths, m)
			}
		}
	}
	return paths, warnings, nil
}

// ExpandApp expands one App entry to the paths it names: itself with
// environment variables expanded, or the files its glob matches.
func ExpandApp(a string) ([]string, error) {
	p, err := expandEnv(a)
	if err != nil {
		return nil, fmt.Errorf("App %s: %w", a, err)
	}
	if strings.Contains(p, "%") {
		return nil, fmt.Errorf("App %s: undefined variable in %s", a, p)
	}
	if !filepath.IsAbs(p) {
		return nil, fmt.Errorf("App %s: path must be absolute", a)
	}
	if !strings.ContainsAny(p, "*?[") {
		return []string{filepath.Clean(p)}, nil
	}
	matches, err := filepath.Glob(p)
	if err != nil {
		return nil, fmt.Errorf("App %s: %w", a, err)
	}
	return matches, nil
}

// WithExpandedApps returns the configuration text with each App entry
// replaced by its expanded paths, for running as another user.
func (c *Config) WithExpandedApps() (string, error) {
	var paths []string
	if c.Mode != ModeFull {
		var err error
		if paths, _, err = c.ExpandApps(); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(c.wgText, "\r\n \t"))
	b.WriteString("\n\n[SplitWire]\n")
	fmt.Fprintf(&b, "Mode = %s\n", c.Mode)
	for _, p := range paths {
		fmt.Fprintf(&b, "App = %s\n", p)
	}
	if c.Proxy.IsValid() {
		fmt.Fprintf(&b, "Proxy = %s\n", c.Proxy)
	}
	return b.String(), nil
}
