package netcfg

import (
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"splitwire/internal/config"
)

const conf = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32
DNS = 1.1.1.1, 192.168.50.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.7:51820
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, 192.168.50.0/24
`

func routeSet(t *testing.T, text string) map[string]uint32 {
	t.Helper()
	c, err := config.Parse(text, "home")
	if err != nil {
		t.Fatal(err)
	}
	routes, warnings := Routes(c, windows.AF_INET)
	if len(warnings) != 0 {
		t.Fatalf("warnings %v", warnings)
	}
	got := make(map[string]uint32)
	for _, r := range routes {
		got[r.Destination.String()] = r.Metric
	}
	return got
}

func TestRoutesFull(t *testing.T) {
	got := routeSet(t, conf)
	want := map[string]uint32{"0.0.0.0/1": 0, "128.0.0.0/1": 0, "192.168.50.0/24": 0}
	if len(got) != len(want) {
		t.Fatalf("routes %v", got)
	}
	for d, m := range want {
		if gm, ok := got[d]; !ok || gm != m {
			t.Fatalf("routes %v, want %v", got, want)
		}
	}
}

func TestRoutesInclude(t *testing.T) {
	got := routeSet(t, conf+"[SplitWire]\nMode = include\nApp = C:\\x.exe\n")
	want := map[string]uint32{
		"0.0.0.0/0":       IncludeDefaultMetric,
		"192.168.50.0/24": 0,
		// Public DNS server reached through the tunnel; the private one is
		// already inside 192.168.50.0/24.
		"1.1.1.1/32": 0,
	}
	if len(got) != len(want) {
		t.Fatalf("routes %v, want %v", got, want)
	}
	for d, m := range want {
		if gm, ok := got[d]; !ok || gm != m {
			t.Fatalf("routes %v, want %v", got, want)
		}
	}
}

func TestRoutesIncludeWithoutDefault(t *testing.T) {
	c, err := config.Parse(strings.Replace(conf, "0.0.0.0/1, 128.0.0.0/1, ", "", 1)+"[SplitWire]\nMode = include\nApp = C:\\x.exe\n", "home")
	if err != nil {
		t.Fatal(err)
	}
	routes, warnings := Routes(c, windows.AF_INET)
	if len(routes) != 1 || len(warnings) != 1 {
		t.Fatalf("routes %v warnings %v", routes, warnings)
	}
}

func TestPhysicalLinks(t *testing.T) {
	p := PhysicalLinks(0)
	if !p.V4.Addr.IsValid() && !p.V6.Addr.IsValid() {
		t.Skip("no default route on this machine")
	}
	t.Logf("physical IPv4 %+v IPv6 %+v", p.V4, p.V6)
}

func TestRouteOf(t *testing.T) {
	iface, tunnel, err := RouteOf(netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Skipf("no route on this machine: %v", err)
	}
	t.Logf("1.1.1.1 goes out of %q, tunnel %v", iface, tunnel)
	if iface == "" {
		t.Fatal("no interface name")
	}
}
