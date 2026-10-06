package manager

import (
	"net/netip"
	"strings"
	"testing"

	"splitwire/internal/config"
	"splitwire/internal/ipc"
)

const tunnelBase = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.7:51820
`

func parse(t *testing.T, text string) *config.Config {
	t.Helper()
	c, err := config.Parse(text, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClaims(t *testing.T) {
	warp := parse(t, tunnelBase+"AllowedIPs = 0.0.0.0/0, ::/0\n")
	if got := claims(warp); len(got) != 2 {
		t.Fatalf("full tunnel claims %v", got)
	}
	// Include mode's default route carries only the Split VPN's apps.
	include := parse(t, tunnelBase+"AllowedIPs = 0.0.0.0/0, 10.1.0.0/16\n\n[SplitWire]\nMode = include\nApp = C:\\a.exe\n")
	got := claims(include)
	if len(got) != 1 || got[0] != netip.MustParsePrefix("10.1.0.0/16") {
		t.Fatalf("include tunnel claims %v", got)
	}
	off := parse(t, strings.Replace(tunnelBase, "[Peer]", "Table = off\n\n[Peer]", 1)+"AllowedIPs = 0.0.0.0/0\n")
	if got := claims(off); len(got) != 0 {
		t.Fatalf("Table = off claims %v", got)
	}
}

func TestConflict(t *testing.T) {
	running := map[string][]netip.Prefix{
		"WARP":   {netip.MustParsePrefix("0.0.0.0/0")},
		"Office": {netip.MustParsePrefix("10.0.0.0/8")},
	}
	// A narrower range beside a wider one is not a conflict: Windows picks
	// the most specific route.
	if name, p, ok := conflict(running, []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}); ok {
		t.Fatalf("nested range conflicts with %s on %s", name, p)
	}
	name, p, ok := conflict(running, []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24"), netip.MustParsePrefix("10.0.0.0/8")})
	if !ok || name != "Office" || p != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("conflict = %s %s %v", name, p, ok)
	}
}

func TestAdapterRole(t *testing.T) {
	if got := adapterRole(tunnelBase + "AllowedIPs = 0.0.0.0/0\n"); got != ipc.AsVPN {
		t.Fatalf("full tunnel boots as %s", got)
	}
	if got := adapterRole(tunnelBase + "AllowedIPs = 0.0.0.0/0\n\n[SplitWire]\nMode = exclude\nApp = C:\\a.exe\n"); got != ipc.AsSplit {
		t.Fatalf("exclude tunnel boots as %s", got)
	}
}
