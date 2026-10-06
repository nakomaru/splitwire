package config

import (
	"net/netip"
	"slices"
	"testing"
)

func TestParseDirect(t *testing.T) {
	d, err := ParseDirect([]string{"203.0.113.0/24", " 198.51.100.7 ", "2001:db8::/32", "VPN.Office.example", ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("198.51.100.7/32"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !slices.Equal(d.Prefixes, want) || !slices.Equal(d.Hosts, []string{"vpn.office.example"}) {
		t.Fatalf("parsed %+v", d)
	}
	for _, bad := range []string{"office", "-a.example", "a..example", "a_b.example", "300.1.1.1"} {
		if _, err := ParseDirect([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSubtract(t *testing.T) {
	pfx := netip.MustParsePrefix
	cases := []struct {
		p, d string
		want []string
	}{
		{"10.0.0.0/8", "192.168.0.0/16", []string{"10.0.0.0/8"}},
		{"10.0.0.0/8", "10.0.0.0/8", nil},
		{"10.1.0.0/16", "10.0.0.0/8", nil},
		{"10.0.0.0/8", "10.128.0.0/9", []string{"10.0.0.0/9"}},
		{"0.0.0.0/0", "128.0.0.0/2", []string{"0.0.0.0/1", "192.0.0.0/2"}},
		{"::/0", "10.0.0.0/8", []string{"::/0"}},
	}
	for _, c := range cases {
		var want []netip.Prefix
		for _, w := range c.want {
			want = append(want, pfx(w))
		}
		if got := Subtract(pfx(c.p), pfx(c.d)); !slices.Equal(got, want) {
			t.Errorf("Subtract(%s, %s) = %v, want %v", c.p, c.d, got, want)
		}
	}

	// The pieces of a /0 without a /32 cover everything but that address.
	hole := netip.MustParseAddr("203.0.113.9")
	rest := Subtract(pfx("0.0.0.0/0"), netip.PrefixFrom(hole, 32))
	if len(rest) != 32 {
		t.Fatalf("%d pieces", len(rest))
	}
	for _, a := range []string{"0.0.0.0", "203.0.113.8", "203.0.113.10", "255.255.255.255"} {
		covered := 0
		for _, p := range rest {
			if p.Contains(netip.MustParseAddr(a)) {
				covered++
			}
		}
		if covered != 1 {
			t.Errorf("%s covered %d times", a, covered)
		}
	}
	for _, p := range rest {
		if p.Contains(hole) {
			t.Errorf("%s still holds %s", p, hole)
		}
	}

	got := SubtractAll(pfx("10.0.0.0/8"), []netip.Prefix{pfx("10.0.0.0/9"), pfx("10.128.0.0/10")})
	if !slices.Equal(got, []netip.Prefix{pfx("10.192.0.0/10")}) {
		t.Fatalf("SubtractAll = %v", got)
	}
}
