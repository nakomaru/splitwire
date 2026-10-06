// Package settings holds the machine-wide choices every tunnel follows,
// kept in the configs folder that only SYSTEM and Administrators can read.
package settings

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
)

const file = "settings.json"

// Settings are the machine-wide choices.
type Settings struct {
	// KillSwitch blocks traffic outside the tunnels while a tunnel carries
	// every address, so nothing leaks if it drops.
	KillSwitch bool
	// AllowLAN exempts private networks from the kill switch.
	AllowLAN bool
	// StrictDNS blocks DNS servers other than the running tunnels' while
	// any tunnel sets DNS servers.
	StrictDNS bool
	// Direct is the Always direct list: address ranges, addresses and host
	// names whose traffic leaves through the physical link, outside every
	// tunnel except for the apps an include mode Split VPN carries.
	Direct []string `json:",omitempty"`
}

func path() (string, error) {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, file), nil
}

// Defaults are the settings before any change.
func Defaults() Settings {
	return Settings{KillSwitch: true, StrictDNS: true}
}

// Load reads the settings; missing settings are the defaults.
func Load() (Settings, error) {
	s := Defaults()
	p, err := path()
	if err != nil {
		return s, err
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// Save writes the settings.
func Save(s Settings) error {
	p, err := path()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// lookupTimeout bounds resolving one Always direct host name.
const lookupTimeout = 5 * time.Second

// DirectPrefixes resolves the Always direct list to prefixes, host names to
// their current addresses. A name that does not resolve is logged and left
// out.
func (s Settings) DirectPrefixes() []netip.Prefix {
	d, err := config.ParseDirect(s.Direct)
	if err != nil {
		log.Printf("Always direct: %v", err)
		return nil
	}
	out := d.Prefixes
	for _, h := range d.Hosts {
		ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		cancel()
		if err != nil {
			log.Printf("Always direct: resolve %s: %v", h, err)
			continue
		}
		for _, a := range addrs {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	// A stable order lets callers tell when the resolved list changed.
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(out)
}

// LoadOrDefaults loads the settings, logging a failure and returning the
// defaults instead.
func LoadOrDefaults() Settings {
	s, err := Load()
	if err != nil {
		log.Printf("Settings: %v", err)
		return Defaults()
	}
	return s
}
