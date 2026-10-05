// Package config reads tunnel configurations: a WireGuard .conf file with an
// optional [Splitwire] section. Without that section the file is an ordinary
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

// Switch is a setting that may be left to a mode-dependent default.
type Switch int

const (
	Auto Switch = iota
	On
	Off
)

func (s Switch) String() string {
	switch s {
	case On:
		return "on"
	case Off:
		return "off"
	}
	return "auto"
}

// Via is the path a proxy tunnel's WireGuard packets take.
type Via int

const (
	// ViaAuto follows the system routes, which include a running VPN tunnel's.
	ViaAuto Via = iota
	// ViaVPN sends them only through the running VPN tunnel, and drops them
	// while none runs.
	ViaVPN
)

func (v Via) String() string {
	if v == ViaVPN {
		return "vpn"
	}
	return "auto"
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
	// Apps are App entries as written: absolute paths, optionally with
	// %VARIABLE% references and glob patterns.
	Apps []string
	// KillSwitch blocks traffic that bypasses the tunnel in full and exclude
	// modes. Auto means on when AllowedIPs contain a default route.
	KillSwitch Switch
	// AllowLAN exempts private networks from the kill switch.
	AllowLAN bool
	// StrictDNS limits DNS (port 53) to the tunnel's DNS servers whenever
	// [Interface] sets DNS.
	StrictDNS bool

	// Proxy is the address the tunnel's SOCKS5 and HTTP proxy listens on
	// when it runs as a proxy. It is invalid when unset.
	Proxy netip.AddrPort
	// ProxyVia selects the path of the proxy's own WireGuard packets.
	ProxyVia Via

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
	c := &Config{StrictDNS: true}

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

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	}
	return false, fmt.Errorf("%q is not on or off", v)
}

func (c *Config) set(key, val string) error {
	switch key {
	case "mode":
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
	case "killswitch":
		if strings.EqualFold(val, "auto") {
			c.KillSwitch = Auto
			return nil
		}
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("KillSwitch: %w", err)
		}
		c.KillSwitch = map[bool]Switch{true: On, false: Off}[b]
	case "allowlan":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("AllowLAN: %w", err)
		}
		c.AllowLAN = b
	case "strictdns":
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("StrictDNS: %w", err)
		}
		c.StrictDNS = b
	case "proxy":
		ap, err := ParseProxy(val)
		if err != nil {
			return err
		}
		c.Proxy = ap
	case "proxyvia":
		switch strings.ToLower(val) {
		case "auto":
			c.ProxyVia = ViaAuto
		case "vpn":
			c.ProxyVia = ViaVPN
		default:
			return fmt.Errorf("ProxyVia must be auto or vpn, not %q", val)
		}
	default:
		return fmt.Errorf("unknown [Splitwire] key %q", key)
	}
	return nil
}

func (c *Config) validate() error {
	if c.Mode != ModeFull && len(c.Apps) == 0 {
		return fmt.Errorf("Mode = %s needs at least one App", c.Mode)
	}
	if c.Mode == ModeFull && len(c.Apps) > 0 {
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

// KillSwitchOn resolves KillSwitch for the full and exclude modes.
func (c *Config) KillSwitchOn() bool {
	if c.Mode == ModeInclude || c.WG.Interface.TableOff {
		return false
	}
	switch c.KillSwitch {
	case On:
		return true
	case Off:
		return false
	}
	return c.HasDefaultRoute()
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
		p, err := expandEnv(a)
		if err != nil {
			return nil, nil, fmt.Errorf("App %s: %w", a, err)
		}
		if strings.Contains(p, "%") {
			return nil, nil, fmt.Errorf("App %s: undefined variable in %s", a, p)
		}
		if !filepath.IsAbs(p) {
			return nil, nil, fmt.Errorf("App %s: path must be absolute", a)
		}
		matches := []string{filepath.Clean(p)}
		if strings.ContainsAny(p, "*?[") {
			matches, err = filepath.Glob(p)
			if err != nil {
				return nil, nil, fmt.Errorf("App %s: %w", a, err)
			}
			if len(matches) == 0 {
				warnings = append(warnings, fmt.Sprintf("App %s matches no files", a))
			}
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

// WithExpandedApps returns the configuration text with each App entry
// replaced by its expanded paths, for running as another user.
func (c *Config) WithExpandedApps() (string, error) {
	paths, _, err := c.ExpandApps()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(c.wgText, "\r\n \t"))
	b.WriteString("\n\n[Splitwire]\n")
	fmt.Fprintf(&b, "Mode = %s\n", c.Mode)
	for _, p := range paths {
		fmt.Fprintf(&b, "App = %s\n", p)
	}
	fmt.Fprintf(&b, "KillSwitch = %s\n", c.KillSwitch)
	fmt.Fprintf(&b, "AllowLAN = %t\n", c.AllowLAN)
	fmt.Fprintf(&b, "StrictDNS = %t\n", c.StrictDNS)
	if c.Proxy.IsValid() {
		fmt.Fprintf(&b, "Proxy = %s\n", c.Proxy)
	}
	fmt.Fprintf(&b, "ProxyVia = %s\n", c.ProxyVia)
	return b.String(), nil
}
