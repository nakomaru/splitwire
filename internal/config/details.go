package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.zx2c4.com/wireguard/windows/conf"
)

// Details are a tunnel's WireGuard settings as the window edits them: text
// fields, with lists separated by commas.
type Details struct {
	PrivateKey, Addresses, ListenPort, MTU, DNS string
	Peers                                       []PeerDetails
}

// PeerDetails are a peer's settings as text.
type PeerDetails struct {
	PublicKey, PresharedKey, Endpoint, Keepalive, AllowedIPs string
	// From is the peer's place among the file's peers, or -1 for a peer
	// that the file lacks.
	From int
}

// Keys of the WireGuard settings, as Details errors name them and as they
// are written.
const (
	KeyPrivateKey   = "PrivateKey"
	KeyAddress      = "Address"
	KeyListenPort   = "ListenPort"
	KeyMTU          = "MTU"
	KeyDNS          = "DNS"
	KeyPublicKey    = "PublicKey"
	KeyPresharedKey = "PresharedKey"
	KeyEndpoint     = "Endpoint"
	KeyKeepalive    = "PersistentKeepalive"
	KeyAllowedIPs   = "AllowedIPs"
)

// DetailError is a problem with one field of Details. Peer is the peer's
// index, or -1 for the interface.
type DetailError struct {
	Peer int
	Key  string
	Err  error
}

// DetailsOf formats the WireGuard settings of c.
func DetailsOf(c *Config) Details {
	i := c.WG.Interface
	d := Details{PrivateKey: i.PrivateKey.String(), Addresses: joinPrefixes(i.Addresses)}
	if i.ListenPort != 0 {
		d.ListenPort = strconv.Itoa(int(i.ListenPort))
	}
	if i.MTU != 0 {
		d.MTU = strconv.Itoa(int(i.MTU))
	}
	var dns []string
	for _, a := range i.DNS {
		dns = append(dns, a.String())
	}
	d.DNS = strings.Join(append(dns, i.DNSSearch...), ", ")
	for _, p := range c.WG.Peers {
		pd := PeerDetails{PublicKey: p.PublicKey.String(), AllowedIPs: joinPrefixes(p.AllowedIPs), From: len(d.Peers)}
		if !p.PresharedKey.IsZero() {
			pd.PresharedKey = p.PresharedKey.String()
		}
		if !p.Endpoint.IsEmpty() {
			pd.Endpoint = p.Endpoint.String()
		}
		if p.PersistentKeepalive != 0 {
			pd.Keepalive = strconv.Itoa(int(p.PersistentKeepalive))
		}
		d.Peers = append(d.Peers, pd)
	}
	return d
}

// Clone returns a copy of d that shares no peers with it.
func (d Details) Clone() Details {
	d.Peers = slices.Clone(d.Peers)
	return d
}

// Equal reports whether d and o hold the same text.
func (d Details) Equal(o Details) bool {
	return d.PrivateKey == o.PrivateKey && d.Addresses == o.Addresses && d.ListenPort == o.ListenPort &&
		d.MTU == o.MTU && d.DNS == o.DNS && slices.Equal(d.Peers, o.Peers)
}

// Clean checks d and returns it in canonical form, with the problems of the
// fields that have one.
func (d Details) Clean() (Details, []DetailError) {
	var errs []DetailError
	field := func(peer int, key string, v *string, clean func(string) (string, error)) {
		out, err := clean(strings.TrimSpace(*v))
		if err != nil {
			errs = append(errs, DetailError{peer, key, err})
			return
		}
		*v = out
	}
	out := d.Clone()
	field(-1, KeyPrivateKey, &out.PrivateKey, cleanKey(true))
	field(-1, KeyAddress, &out.Addresses, cleanPrefixes(false))
	field(-1, KeyListenPort, &out.ListenPort, cleanNumber(0, 65535, "a port from 1 to 65535"))
	field(-1, KeyMTU, &out.MTU, cleanNumber(576, 65535, "from 576 to 65535"))
	field(-1, KeyDNS, &out.DNS, cleanDNS)
	if out.MTU != "" && !hasErr(errs, -1, KeyAddress) && !hasErr(errs, -1, KeyMTU) {
		if mtu, _ := strconv.Atoi(out.MTU); mtu < 1280 && strings.Contains(out.Addresses, ":") {
			errs = append(errs, DetailError{-1, KeyMTU, errors.New("IPv6 addresses need at least 1280")})
		}
	}
	for i := range out.Peers {
		p := &out.Peers[i]
		field(i, KeyPublicKey, &p.PublicKey, cleanKey(true))
		field(i, KeyPresharedKey, &p.PresharedKey, cleanKey(false))
		field(i, KeyEndpoint, &p.Endpoint, cleanEndpoint)
		field(i, KeyKeepalive, &p.Keepalive, cleanNumber(0, 65535, "seconds from 1 to 65535"))
		field(i, KeyAllowedIPs, &p.AllowedIPs, cleanPrefixes(true))
		for j := range i {
			if p.PublicKey != "" && p.PublicKey == out.Peers[j].PublicKey && !hasErr(errs, i, KeyPublicKey) {
				errs = append(errs, DetailError{i, KeyPublicKey, fmt.Errorf("peer %d has the same key", j+1)})
			}
		}
	}
	return out, errs
}

func hasErr(errs []DetailError, peer int, key string) bool {
	for _, e := range errs {
		if e.Peer == peer && e.Key == key {
			return true
		}
	}
	return false
}

// ApplyDetails writes the fields of d that differ from old into text, each
// replacing its key's lines in its section. A peer of old that d lacks
// loses its section, and a peer new in d gets one after the last WireGuard
// section. Both are clean.
func ApplyDetails(text string, old, d Details) string {
	set := func(peer int, key, was, now string) {
		if was != now {
			text = setWG(text, peer, key, now)
		}
	}
	set(-1, KeyPrivateKey, old.PrivateKey, d.PrivateKey)
	set(-1, KeyAddress, old.Addresses, d.Addresses)
	set(-1, KeyListenPort, old.ListenPort, d.ListenPort)
	set(-1, KeyMTU, old.MTU, d.MTU)
	set(-1, KeyDNS, old.DNS, d.DNS)
	kept := make([]bool, len(old.Peers))
	for _, p := range d.Peers {
		i := p.From
		if i < 0 || i >= len(old.Peers) {
			continue
		}
		kept[i] = true
		o := old.Peers[i]
		set(i, KeyPublicKey, o.PublicKey, p.PublicKey)
		set(i, KeyPresharedKey, o.PresharedKey, p.PresharedKey)
		set(i, KeyEndpoint, o.Endpoint, p.Endpoint)
		set(i, KeyKeepalive, o.Keepalive, p.Keepalive)
		set(i, KeyAllowedIPs, o.AllowedIPs, p.AllowedIPs)
	}
	for i := len(old.Peers) - 1; i >= 0; i-- {
		if !kept[i] {
			text = removePeer(text, i)
		}
	}
	for _, p := range d.Peers {
		if p.From < 0 {
			text = addPeer(text, p)
		}
	}
	return text
}

// peerSpan finds the lines of the peer'th [Peer] section, from its header
// to the next section; start is -1 when there is none.
func peerSpan(lines []string, peer int) (start, end int) {
	start, peers := -1, -1
	for i, line := range lines {
		header, _ := sectionLine(line)
		if header == "" {
			continue
		}
		if start >= 0 {
			return start, i
		}
		if strings.EqualFold(header, "[peer]") {
			peers++
			if peers == peer {
				start = i
			}
		}
	}
	return start, len(lines)
}

// removePeer drops the peer'th [Peer] section of text.
func removePeer(text string, peer int) string {
	lines, nl := lineSplit(text)
	start, end := peerSpan(lines, peer)
	if start < 0 {
		return text
	}
	return strings.Join(append(lines[:start:start], lines[end:]...), nl)
}

// addPeer puts a [Peer] section for p after the last line of the last
// WireGuard section of text.
func addPeer(text string, p PeerDetails) string {
	lines, nl := lineSplit(text)
	last, in := len(lines)-1, false
	for i, line := range lines {
		if header, _ := sectionLine(line); header != "" {
			in = strings.EqualFold(header, "[interface]") || strings.EqualFold(header, "[peer]")
		}
		if in && strings.TrimSpace(line) != "" {
			last = i
		}
	}
	entries := []string{"", "[Peer]"}
	for _, kv := range [][2]string{{KeyPublicKey, p.PublicKey}, {KeyPresharedKey, p.PresharedKey},
		{KeyAllowedIPs, p.AllowedIPs}, {KeyEndpoint, p.Endpoint}, {KeyKeepalive, p.Keepalive}} {
		if kv[1] != "" {
			entries = append(entries, kv[0]+" = "+kv[1])
		}
	}
	if last+1 < len(lines) && strings.TrimSpace(lines[last+1]) != "" {
		entries = append(entries, "")
	}
	return strings.Join(insertAt(lines, last+1, entries), nl)
}

// setWG sets key = val in the first [Interface] section of text when peer
// is -1, or in the peer'th [Peer] section: it replaces the key's first line
// and drops its repeats, or drops them all when val is empty. A key the
// section lacks goes after its last setting.
func setWG(text string, peer int, key, val string) string {
	lines, nl := lineSplit(text)
	lower := strings.ToLower(key)
	var at []int
	insert, peers, in, first := -1, -1, false, false
	for i, line := range lines {
		header, k := sectionLine(line)
		if header != "" {
			h := strings.ToLower(header)
			in = false
			switch {
			case h == "[interface]" && peer < 0:
				in = true
			case h == "[peer]":
				peers++
				in = peers == peer
			}
			first = in && insert < 0
			if first {
				insert = i + 1
			}
			continue
		}
		if !in || k == "" {
			continue
		}
		if k == lower {
			at = append(at, i)
		}
		if first {
			insert = i + 1
		}
	}
	entry := key + " = " + val
	switch {
	case len(at) > 0 && val == "":
		lines = without(lines, at)
	case len(at) > 0:
		lines[at[0]] = entry
		lines = without(lines, at[1:])
	case val != "" && insert >= 0:
		lines = insertAt(lines, insert, []string{entry})
	}
	return strings.Join(lines, nl)
}

// splitItems splits a list at commas and white space.
func splitItems(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
}

func joinPrefixes(ps []netip.Prefix) string {
	items := make([]string, len(ps))
	for i, p := range ps {
		items[i] = p.String()
	}
	return strings.Join(items, ", ")
}

func cleanKey(required bool) func(string) (string, error) {
	return func(s string) (string, error) {
		if s == "" {
			if required {
				return "", errors.New("needed")
			}
			return "", nil
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(b) != conf.KeyLength {
			return "", errors.New("must be a key of 44 base64 characters")
		}
		return base64.StdEncoding.EncodeToString(b), nil
	}
}

// parsePrefix parses an address range, or an address as a range of one.
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q is not an address or range", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// cleanPrefixes checks a list of ranges; masked clears the bits past each
// prefix, for routes, and drops repeats.
func cleanPrefixes(masked bool) func(string) (string, error) {
	return func(s string) (string, error) {
		var out []netip.Prefix
		for _, item := range splitItems(s) {
			p, err := parsePrefix(item)
			if err != nil {
				return "", err
			}
			if masked {
				p = p.Masked()
			}
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		return joinPrefixes(out), nil
	}
}

// cleanNumber checks a number from lo to hi, with "" and 0 meaning unset.
func cleanNumber(lo, hi int, want string) func(string) (string, error) {
	return func(s string) (string, error) {
		if s == "" || s == "0" || strings.EqualFold(s, "off") {
			return "", nil
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < max(lo, 1) || n > hi {
			return "", errors.New("must be " + want)
		}
		return strconv.Itoa(n), nil
	}
}

// validName reports whether s is a host name, with or without a domain.
func validName(s string) bool {
	if validHost(s) {
		return true
	}
	return !strings.Contains(s, ".") && strings.Trim(s, "0123456789") != "" && validHost(s+".x")
}

// cleanDNS checks DNS servers and search domains.
func cleanDNS(s string) (string, error) {
	var out []string
	for _, item := range splitItems(s) {
		if a, err := netip.ParseAddr(item); err == nil {
			item = a.String()
		} else if !validName(item) {
			return "", fmt.Errorf("%q is neither an address nor a domain", item)
		}
		if !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	return strings.Join(out, ", "), nil
}

// cleanEndpoint checks a host and port; an IPv6 address goes in brackets.
func cleanEndpoint(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return "", errors.New("needs a port from 1 to 65535")
		}
		return ap.String(), nil
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", errors.New("needs a port, as in host:51820")
	}
	host, port := s[:i], s[i+1:]
	if _, err := netip.ParseAddr(host); err == nil && strings.Contains(host, ":") {
		return "", errors.New("an IPv6 address goes in brackets, as in [2001:db8::1]:51820")
	}
	if !validName(host) {
		return "", fmt.Errorf("%q is not a host name or address", host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("needs a port from 1 to 65535")
	}
	return strings.ToLower(host) + ":" + strconv.Itoa(n), nil
}

var (
	allIPv4 = netip.MustParsePrefix("0.0.0.0/0")
	// privateIPv4 are the ranges that excluding private IPs leaves out: the
	// private networks of RFC 1918, and multicast and reserved addresses.
	privateIPv4 = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/3")}
	// publicIPv4 is every IPv4 address outside privateIPv4, in order.
	publicIPv4 = func() []netip.Prefix {
		out := []netip.Prefix{allIPv4}
		for _, h := range privateIPv4 {
			var next []netip.Prefix
			for _, p := range out {
				next = append(next, Subtract(p, h)...)
			}
			out = next
		}
		slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
		return out
	}()
)

// PrivateIPs reports whether excluding private IPs applies to an AllowedIPs
// list, which it does when the list routes every IPv4 address or every
// public one, and whether the list excludes them.
func PrivateIPs(allowed string) (applies, excluded bool) {
	ps, err := parsePrefixes(allowed)
	if err != nil {
		return false, false
	}
	all := slices.Contains(ps, allIPv4)
	public := true
	for _, p := range publicIPv4 {
		public = public && slices.Contains(ps, p)
	}
	return all || public, public && !all
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var ps []netip.Prefix
	for _, item := range splitItems(s) {
		p, err := parsePrefix(item)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p.Masked())
	}
	return ps, nil
}

// ExcludePrivateIPs returns an AllowedIPs list with the private IPv4 ranges
// left out, or brought back. The IPv4 DNS servers among dns that lie in
// private ranges stay routed through the tunnel.
func ExcludePrivateIPs(allowed, dns string, exclude bool) (string, error) {
	ps, err := parsePrefixes(allowed)
	if err != nil {
		return "", err
	}
	var servers []netip.Prefix
	for _, item := range splitItems(dns) {
		a, err := netip.ParseAddr(item)
		if err != nil || !a.Is4() {
			continue
		}
		for _, h := range privateIPv4 {
			if h.Contains(a) {
				servers = append(servers, netip.PrefixFrom(a, 32))
			}
		}
	}
	var out []netip.Prefix
	placed := false
	for _, p := range ps {
		switch {
		case exclude && p == allIPv4:
			out = append(out, publicIPv4...)
			out = append(out, servers...)
		case !exclude && (slices.Contains(publicIPv4, p) || slices.Contains(servers, p)):
			if !placed {
				out = append(out, allIPv4)
				placed = true
			}
		default:
			out = append(out, p)
		}
	}
	var uniq []netip.Prefix
	for _, p := range out {
		if !slices.Contains(uniq, p) {
			uniq = append(uniq, p)
		}
	}
	return joinPrefixes(uniq), nil
}
