package manager

import (
	"net/netip"
	"path/filepath"
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
	if got := claims(warp, nil); len(got) != 2 {
		t.Fatalf("full tunnel claims %v", got)
	}
	// Always direct ranges leave the claims.
	got := claims(warp, []netip.Prefix{netip.MustParsePrefix("128.0.0.0/1")})
	if len(got) != 2 || got[0] != netip.MustParsePrefix("0.0.0.0/1") {
		t.Fatalf("full tunnel with Always direct claims %v", got)
	}
	// Include mode's default route carries only the Split VPN's apps.
	include := parse(t, tunnelBase+"AllowedIPs = 0.0.0.0/0, 10.1.0.0/16\n\n[SplitWire]\nMode = include\nApp = C:\\a.exe\n")
	got = claims(include, nil)
	if len(got) != 1 || got[0] != netip.MustParsePrefix("10.1.0.0/16") {
		t.Fatalf("include tunnel claims %v", got)
	}
	off := parse(t, strings.Replace(tunnelBase, "[Peer]", "Table = off\n\n[Peer]", 1)+"AllowedIPs = 0.0.0.0/0\n")
	if got := claims(off, nil); len(got) != 0 {
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

func TestReadEntries(t *testing.T) {
	split := tunnelBase + "AllowedIPs = 0.0.0.0/0\n\n[SplitWire]\nMode = exclude\nApp = C:\a.exe\n"
	entries := []bootEntry{
		{Name: "proxy", As: ipc.AsProxy, Config: tunnelBase + "AllowedIPs = 0.0.0.0/0\n"},
		{Name: "office", As: ipc.AsVPN, Config: tunnelBase + "AllowedIPs = 10.0.0.0/8\n"},
		{Name: "games", As: ipc.AsVPN, Config: split},
	}
	path := filepath.Join(t.TempDir(), runningFile)
	if err := writeBoot(path, entries); err != nil {
		t.Fatal(err)
	}
	got, err := readEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, e := range got {
		order = append(order, e.Name+"="+e.As)
	}
	// A saved VPN that picks apps comes back as the Split VPN, which starts
	// first.
	if want := "games=split office=vpn proxy=proxy"; strings.Join(order, " ") != want {
		t.Fatalf("entries %v, want %s", order, want)
	}
}
