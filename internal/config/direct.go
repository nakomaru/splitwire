package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// Direct is the Always direct list: destinations whose traffic leaves
// through the physical link, outside every tunnel. Entries are address
// ranges, addresses or host names.
type Direct struct {
	Prefixes []netip.Prefix
	Hosts    []string
}

// ParseDirect parses Always direct entries.
func ParseDirect(entries []string) (Direct, error) {
	var d Direct
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			d.Prefixes = append(d.Prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			d.Prefixes = append(d.Prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		if !validHost(e) {
			return Direct{}, fmt.Errorf("%q is not an address range, address or host name", e)
		}
		d.Hosts = append(d.Hosts, strings.ToLower(e))
	}
	return d, nil
}

// validHost reports whether h is a host name with a domain. Its last label
// is never all digits, which tells it apart from a mistyped address.
func validHost(h string) bool {
	if len(h) > 253 || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || !strings.Contains(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Subtract returns p without the addresses in d, as the fewest prefixes.
func Subtract(p, d netip.Prefix) []netip.Prefix {
	p, d = p.Masked(), d.Masked()
	if p.Addr().BitLen() != d.Addr().BitLen() || !p.Overlaps(d) {
		return []netip.Prefix{p}
	}
	if d.Bits() <= p.Bits() {
		return nil
	}
	// Split p in halves until the half holding d is d itself; each other
	// half lies wholly outside d.
	var out []netip.Prefix
	for p.Bits() < d.Bits() {
		lo, hi := halves(p)
		if lo.Contains(d.Addr()) {
			out = append(out, hi)
			p = lo
		} else {
			out = append(out, lo)
			p = hi
		}
	}
	return out
}

func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	b := p.Addr().AsSlice()
	b[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	hiAddr, _ := netip.AddrFromSlice(b)
	return lo, netip.PrefixFrom(hiAddr, bits)
}

// SubtractAll returns p without the addresses in every prefix of ds.
func SubtractAll(p netip.Prefix, ds []netip.Prefix) []netip.Prefix {
	out := []netip.Prefix{p}
	for _, d := range ds {
		var next []netip.Prefix
		for _, q := range out {
			next = append(next, Subtract(q, d)...)
		}
		out = next
	}
	return out
}
