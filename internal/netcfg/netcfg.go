// Package netcfg configures the tunnel interface and watches the physical
// default-route interface.
package netcfg

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"splitwire/internal/config"
)

// IncludeDefaultMetric is the route metric of the tunnel's default route in
// include mode. It ranks below any physical default route, so only sockets
// the split tunnel driver binds to the tunnel address use it.
const IncludeDefaultMetric = 9000

func familyOf(a netip.Addr) winipcfg.AddressFamily {
	if a.Unmap().Is4() {
		return windows.AF_INET
	}
	return windows.AF_INET6
}

func defaultPrefix(family winipcfg.AddressFamily) netip.Prefix {
	if family == windows.AF_INET {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

func unspecified(family winipcfg.AddressFamily) netip.Addr {
	if family == windows.AF_INET {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// Routes computes the tunnel routes of one address family.
//
// Full and exclude modes install AllowedIPs as they are. Include mode
// replaces default-like prefixes with a single default route at
// IncludeDefaultMetric and adds host routes for DNS servers that only a
// default route would carry, so the system resolver reaches them through the
// tunnel.
func Routes(c *config.Config, family winipcfg.AddressFamily) (routes []*winipcfg.RouteData, warnings []string) {
	seen := make(map[winipcfg.RouteData]bool)
	add := func(r winipcfg.RouteData) {
		if !seen[r] {
			seen[r] = true
			rr := r
			routes = append(routes, &rr)
		}
	}
	var specific []netip.Prefix
	hasDefault := false
	for _, peer := range c.WG.Peers {
		for _, ip := range peer.AllowedIPs {
			if familyOf(ip.Addr()) != family {
				continue
			}
			if c.Mode == config.ModeInclude && config.IsDefaultRoute(ip) {
				hasDefault = true
				continue
			}
			specific = append(specific, ip.Masked())
			add(winipcfg.RouteData{Destination: ip.Masked(), NextHop: unspecified(family)})
		}
	}
	if c.Mode != config.ModeInclude {
		return routes, nil
	}
	if hasDefault {
		add(winipcfg.RouteData{Destination: defaultPrefix(family), NextHop: unspecified(family), Metric: IncludeDefaultMetric})
	}
	for _, dns := range c.WG.Interface.DNS {
		if familyOf(dns) != family {
			continue
		}
		covered := false
		for _, p := range specific {
			if p.Contains(dns) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		if !hasDefault {
			warnings = append(warnings, fmt.Sprintf("DNS server %s is outside AllowedIPs, so the tunnel cannot carry its queries", dns))
			continue
		}
		add(winipcfg.RouteData{Destination: netip.PrefixFrom(dns, dns.BitLen()), NextHop: unspecified(family)})
	}
	return routes, warnings
}

func usesFamily(c *config.Config, family winipcfg.AddressFamily) bool {
	for _, a := range c.WG.Interface.Addresses {
		if familyOf(a.Addr()) == family {
			return true
		}
	}
	for _, peer := range c.WG.Peers {
		for _, ip := range peer.AllowedIPs {
			if familyOf(ip.Addr()) == family {
				return true
			}
		}
	}
	return false
}

// WaitForInterfaces blocks until the adapter's IP interface exists for each
// address family the configuration uses. A missing IPv6 interface, as on
// systems with IPv6 disabled, is logged and skipped.
func WaitForInterfaces(c *config.Config, luid winipcfg.LUID, timeout time.Duration) ([]winipcfg.AddressFamily, error) {
	arrived := make(chan winipcfg.AddressFamily, 4)
	cb, err := winipcfg.RegisterInterfaceChangeCallback(func(nt winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if nt == winipcfg.MibAddInstance && iface.InterfaceLUID == luid {
			select {
			case arrived <- iface.Family:
			default:
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("watch interfaces: %w", err)
	}
	defer cb.Unregister()

	pending := make(map[winipcfg.AddressFamily]bool)
	for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		if !usesFamily(c, f) {
			continue
		}
		if _, err := luid.IPInterface(f); err == nil {
			continue
		}
		pending[f] = true
	}
	ready := func() []winipcfg.AddressFamily {
		var out []winipcfg.AddressFamily
		for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			if usesFamily(c, f) && !pending[f] {
				out = append(out, f)
			}
		}
		return out
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for len(pending) > 0 {
		select {
		case f := <-arrived:
			delete(pending, f)
		case <-deadline.C:
			if pending[windows.AF_INET] {
				return nil, errors.New("tunnel IPv4 interface did not appear")
			}
			log.Printf("Tunnel IPv6 interface did not appear; continuing without IPv6")
			return ready(), nil
		}
	}
	return ready(), nil
}

// WithoutDirect removes the Always direct prefixes from routes. Include
// mode's default route stays whole: it carries only the Split VPN's apps,
// which keep every destination.
func WithoutDirect(routes []*winipcfg.RouteData, direct []netip.Prefix) []*winipcfg.RouteData {
	if len(direct) == 0 {
		return routes
	}
	var out []*winipcfg.RouteData
	for _, r := range routes {
		if r.Metric == IncludeDefaultMetric {
			out = append(out, r)
			continue
		}
		for _, p := range config.SubtractAll(r.Destination, direct) {
			rr := *r
			rr.Destination = p
			out = append(out, &rr)
		}
	}
	return out
}

// SetRoutes installs the tunnel's routes of one family without the Always
// direct prefixes.
func SetRoutes(c *config.Config, luid winipcfg.LUID, family winipcfg.AddressFamily, direct []netip.Prefix) error {
	if c.WG.Interface.TableOff {
		return nil
	}
	routes, warnings := Routes(c, family)
	for _, w := range warnings {
		log.Printf("Warning: %s", w)
	}
	if err := luid.SetRoutesForFamily(family, WithoutDirect(routes, direct)); err != nil {
		return fmt.Errorf("set routes: %w", err)
	}
	return nil
}

// Configure applies addresses, routes, MTU, metric and DNS of one family.
func Configure(c *config.Config, luid winipcfg.LUID, family winipcfg.AddressFamily, direct []netip.Prefix) error {
	if err := SetRoutes(c, luid, family, direct); err != nil {
		return err
	}

	var addrs []netip.Prefix
	for _, a := range c.WG.Interface.Addresses {
		if familyOf(a.Addr()) == family {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) > 0 {
		err := luid.SetIPAddressesForFamily(family, addrs)
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			cleanupStaleAddresses(family, addrs)
			err = luid.SetIPAddressesForFamily(family, addrs)
		}
		if err != nil {
			return fmt.Errorf("set addresses: %w", err)
		}
	}

	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	if c.WG.Interface.MTU > 0 {
		ipif.NLMTU = uint32(c.WG.Interface.MTU)
	}
	if c.Mode != config.ModeInclude && !c.WG.Interface.TableOff && hasDefaultRoute(c, family) {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	if err := ipif.Set(); err != nil {
		return fmt.Errorf("set metric and MTU: %w", err)
	}

	// Scoped DNS servers answer only their domains, through a DNS policy
	// rule; the adapter keeps just the search domains.
	servers := c.WG.Interface.DNS
	if c.ScopedDNS() {
		servers = nil
	}
	if err := luid.SetDNS(family, servers, c.WG.Interface.DNSSearch); err != nil {
		return fmt.Errorf("set DNS: %w", err)
	}
	return nil
}

func hasDefaultRoute(c *config.Config, family winipcfg.AddressFamily) bool {
	for _, peer := range c.WG.Peers {
		for _, ip := range peer.AllowedIPs {
			if familyOf(ip.Addr()) == family && ip.Bits() == 0 {
				return true
			}
		}
	}
	return false
}

// cleanupStaleAddresses removes the tunnel's addresses from interfaces that
// are down, where an earlier unclean exit can leave them.
func cleanupStaleAddresses(family winipcfg.AddressFamily, addresses []netip.Prefix) {
	want := make(map[netip.Addr]bool, len(addresses))
	for _, a := range addresses {
		want[a.Addr()] = true
	}
	ifaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for a := iface.FirstUnicastAddress; a != nil; a = a.Next {
			if ip, ok := netip.AddrFromSlice(a.Address.IP()); ok && want[ip] {
				p := netip.PrefixFrom(ip, int(a.OnLinkPrefixLength))
				log.Printf("Removing stale address %s from interface %s", p, iface.FriendlyName())
				iface.LUID.DeleteIPAddress(p)
			}
		}
	}
}

// Flush removes everything Configure applied.
func Flush(luid winipcfg.LUID) {
	for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		luid.FlushRoutes(f)
		luid.FlushIPAddresses(f)
		luid.FlushDNS(f)
	}
}
