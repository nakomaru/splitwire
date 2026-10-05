package config

import "testing"

func TestParseProxy(t *testing.T) {
	c, err := Parse(base+"\n[Splitwire]\nProxy = 1081\nProxyVia = vpn\n", "warp")
	if err != nil {
		t.Fatal(err)
	}
	if c.Proxy.String() != "127.0.0.1:1081" || c.ProxyVia != ViaVPN {
		t.Fatalf("Proxy %s via %s", c.Proxy, c.ProxyVia)
	}
	text, err := c.WithExpandedApps()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(text, "warp")
	if err != nil || again.Proxy != c.Proxy || again.ProxyVia != ViaVPN {
		t.Fatalf("expanded text lost the proxy: %v\n%s", err, text)
	}

	for v, want := range map[string]string{
		"0.0.0.0:1080":   "0.0.0.0:1080",
		"[::1]:9050":     "[::1]:9050",
		"65535":          "127.0.0.1:65535",
		"127.0.0.1:1080": "127.0.0.1:1080",
	} {
		ap, err := ParseProxy(v)
		if err != nil || ap.String() != want {
			t.Errorf("ParseProxy(%s) = %s, %v", v, ap, err)
		}
	}
	for _, v := range []string{"0", "65536", "localhost:1080", "127.0.0.1:0", "port"} {
		if _, err := ParseProxy(v); err == nil {
			t.Errorf("ParseProxy(%s) accepted", v)
		}
	}
	if _, err := Parse(base+"\n[Splitwire]\nProxyVia = maybe\n", "x"); err == nil {
		t.Error("ProxyVia = maybe accepted")
	}
}
