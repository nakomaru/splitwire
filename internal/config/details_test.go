package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDetailsRoundTrip(t *testing.T) {
	c, err := Parse(base, "home")
	if err != nil {
		t.Fatal(err)
	}
	d := DetailsOf(c)
	if d.Addresses != "10.8.0.2/32, fd00:8::2/128" || d.DNS != "10.8.0.1" || d.MTU != "" || len(d.Peers) != 1 ||
		d.Peers[0].Endpoint != "203.0.113.7:51820" || d.Peers[0].PresharedKey != "" {
		t.Fatalf("details %+v", d)
	}
	clean, errs := d.Clean()
	if len(errs) > 0 || !clean.Equal(d) {
		t.Fatalf("clean %+v, %v", clean, errs)
	}
	if got := ApplyDetails(base, d, clean); got != base {
		t.Fatalf("unchanged details changed the text:\n%s", got)
	}
}

func TestDetailsClean(t *testing.T) {
	d := Details{
		PrivateKey: " yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk= ",
		Addresses:  "10.8.0.2,  fd00::2/64\n10.8.0.2",
		ListenPort: "0",
		MTU:        "1420",
		DNS:        "1.1.1.1 corp.example,2606:4700:4700:0::1111",
		Peers: []PeerDetails{{
			PublicKey:  "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
			Endpoint:   "VPN.Example.com:51820",
			Keepalive:  "off",
			AllowedIPs: "10.1.2.3/16, ::/0",
		}},
	}
	got, errs := d.Clean()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	want := Details{
		PrivateKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
		Addresses:  "10.8.0.2/32, fd00::2/64",
		MTU:        "1420",
		DNS:        "1.1.1.1, corp.example, 2606:4700:4700::1111",
		Peers: []PeerDetails{{
			PublicKey:  "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
			Endpoint:   "vpn.example.com:51820",
			AllowedIPs: "10.1.0.0/16, ::/0",
		}},
	}
	if !got.Equal(want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}

	bad := []struct {
		edit func(*Details)
		peer int
		key  string
	}{
		{func(d *Details) { d.PrivateKey = "short" }, -1, KeyPrivateKey},
		{func(d *Details) { d.PrivateKey = "" }, -1, KeyPrivateKey},
		{func(d *Details) { d.Addresses = "10.8.0.300" }, -1, KeyAddress},
		{func(d *Details) { d.ListenPort = "70000" }, -1, KeyListenPort},
		{func(d *Details) { d.MTU = "500" }, -1, KeyMTU},
		{func(d *Details) { d.MTU = "1200" }, -1, KeyMTU}, // with an IPv6 address
		{func(d *Details) { d.DNS = "bad_name" }, -1, KeyDNS},
		{func(d *Details) { d.Peers[0].Endpoint = "2001:db8::1:51820" }, 0, KeyEndpoint},
		{func(d *Details) { d.Peers[0].Endpoint = "host" }, 0, KeyEndpoint},
		{func(d *Details) { d.Peers[0].Endpoint = "host:0" }, 0, KeyEndpoint},
		{func(d *Details) { d.Peers[0].Keepalive = "-5" }, 0, KeyKeepalive},
		{func(d *Details) { d.Peers[0].PresharedKey = "AAAA" }, 0, KeyPresharedKey},
		{func(d *Details) { d.Peers[0].AllowedIPs = "everything" }, 0, KeyAllowedIPs},
	}
	for i, b := range bad {
		e := want.Clone()
		b.edit(&e)
		_, errs := e.Clean()
		if len(errs) != 1 || errs[0].Peer != b.peer || errs[0].Key != b.key {
			t.Errorf("case %d: %v", i, errs)
		}
	}
	e := want.Clone()
	e.Peers[0].Endpoint = "[2001:db8::1]:51820"
	if _, errs := e.Clean(); len(errs) > 0 {
		t.Errorf("bracketed IPv6 endpoint: %v", errs)
	}
}

func TestApplyDetails(t *testing.T) {
	text := "# home\r\n[Interface]\r\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\r\n" +
		"Address = 10.8.0.2/32\r\nAddress = fd00:8::2/128 # v6\r\nDNS = 10.8.0.1\r\n\r\n" +
		"[Peer]\r\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\r\nAllowedIPs = 10.0.0.0/8\r\n\r\n" +
		"[Peer]\r\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\r\nEndpoint = 203.0.113.7:51820\r\n" +
		"PersistentKeepalive = 25\r\nAllowedIPs = 0.0.0.0/0\r\n\r\n[SplitWire]\r\nProxy = 1080\r\n"
	c, err := Parse(normalizeTest(text), "home")
	if err != nil {
		t.Fatal(err)
	}
	old := DetailsOf(c)
	d := old.Clone()
	d.Addresses = "10.8.0.3/32"
	d.MTU = "1280"
	d.DNS = ""
	d.Peers[1].Keepalive = ""
	d.Peers[1].PresharedKey = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
	got := ApplyDetails(text, old, d)
	want := "# home\r\n[Interface]\r\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\r\n" +
		"Address = 10.8.0.3/32\r\nMTU = 1280\r\n\r\n" +
		"[Peer]\r\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\r\nAllowedIPs = 10.0.0.0/8\r\n\r\n" +
		"[Peer]\r\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\r\nEndpoint = 203.0.113.7:51820\r\n" +
		"AllowedIPs = 0.0.0.0/0\r\nPresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=\r\n\r\n[SplitWire]\r\nProxy = 1080\r\n"
	if got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
	if _, err := Parse(normalizeTest(got), "home"); err != nil {
		t.Fatal(err)
	}
}

func normalizeTest(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

func TestPublicIPv4(t *testing.T) {
	in := func(s string) bool {
		a := netip.MustParseAddr(s)
		for _, p := range publicIPv4 {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "100.64.0.1", "172.15.255.255", "172.32.0.0", "192.169.0.1", "223.255.255.255"} {
		if !in(s) {
			t.Errorf("%s missing", s)
		}
	}
	for _, s := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "224.0.0.1", "255.255.255.255"} {
		if in(s) {
			t.Errorf("%s included", s)
		}
	}
	if len(publicIPv4) != 30 {
		t.Errorf("%d ranges: %v", len(publicIPv4), publicIPv4)
	}
}

func TestExcludePrivateIPs(t *testing.T) {
	applies, on := PrivateIPs("0.0.0.0/0, ::/0")
	if !applies || on {
		t.Fatalf("full: %v %v", applies, on)
	}
	if applies, _ := PrivateIPs("10.0.0.0/8"); applies {
		t.Fatal("applies to a private range")
	}
	ex, err := ExcludePrivateIPs("0.0.0.0/0, ::/0", "192.168.1.1, 1.1.1.1, fd00::1", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ex, "0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8,") || !strings.HasSuffix(ex, "208.0.0.0/4, 192.168.1.1/32, ::/0") {
		t.Fatalf("excluded: %s", ex)
	}
	if applies, on := PrivateIPs(ex); !applies || !on {
		t.Fatalf("excluded: %v %v", applies, on)
	}
	back, err := ExcludePrivateIPs(ex, "192.168.1.1", false)
	if err != nil || back != "0.0.0.0/0, ::/0" {
		t.Fatalf("back: %s, %v", back, err)
	}
}

func TestApplyDetailsPeers(t *testing.T) {
	text := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.0.2/32\n\n" +
		"[Peer]\n# office\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/8\n\n" +
		"[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 10.9.0.0/16\n" +
		"[SplitWire]\nProxy = 1080\n"
	c, err := Parse(text, "home")
	if err != nil {
		t.Fatal(err)
	}
	old := DetailsOf(c)
	d := old.Clone()
	d.Peers = []PeerDetails{d.Peers[1], {PublicKey: "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=",
		AllowedIPs: "10.7.0.0/16", Endpoint: "198.51.100.1:51820", Keepalive: "25", From: -1}}
	d.Peers[0].Endpoint = "203.0.113.7:51820"
	got := ApplyDetails(text, old, d)
	want := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.0.2/32\n\n" +
		"[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\nAllowedIPs = 10.9.0.0/16\nEndpoint = 203.0.113.7:51820\n\n" +
		"[Peer]\nPublicKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=\nAllowedIPs = 10.7.0.0/16\n" +
		"Endpoint = 198.51.100.1:51820\nPersistentKeepalive = 25\n\n[SplitWire]\nProxy = 1080\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	c, err = Parse(got, "home")
	if err != nil {
		t.Fatal(err)
	}
	if again := DetailsOf(c); len(again.Peers) != 2 || again.Peers[1].Keepalive != "25" {
		t.Fatalf("reparsed %+v", again)
	}

	// No peers, then one.
	bare := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n"
	got = ApplyDetails(bare, Details{}, Details{Peers: []PeerDetails{{PublicKey: "a", From: -1}}})
	if got != bare+"\n[Peer]\nPublicKey = a\n" {
		t.Fatalf("added to a bare interface: %q", got)
	}

	// Two peers with one key.
	dup := old.Clone()
	dup.Peers[1].PublicKey = dup.Peers[0].PublicKey
	if _, errs := dup.Clean(); len(errs) != 1 || errs[0].Peer != 1 || errs[0].Key != KeyPublicKey {
		t.Fatalf("duplicate key: %v", errs)
	}
}
