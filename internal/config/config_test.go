package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const base = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32, fd00:8::2/128
DNS = 10.8.0.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
`

func TestParseInclude(t *testing.T) {
	c, err := Parse(base+`
[SplitWire]
Mode = include  # comment
App = C:\Program Files\Mozilla Firefox\firefox.exe
App = %SystemRoot%\System32\curl.exe
`, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeInclude || len(c.Apps) != 2 {
		t.Fatalf("parsed %+v", c)
	}
	if c.WG.Name != "home" || len(c.WG.Peers) != 1 {
		t.Fatalf("WireGuard part %+v", c.WG)
	}
	if got := c.TunnelAddress(true).String(); got != "10.8.0.2" {
		t.Fatalf("tunnel IPv4 %s", got)
	}
	paths, warnings, err := c.ExpandApps()
	if err != nil || len(warnings) != 0 {
		t.Fatal(err, warnings)
	}
	if want := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe"); paths[1] != want {
		t.Fatalf("expanded %s, want %s", paths[1], want)
	}
}

func TestByteOrderMark(t *testing.T) {
	if _, err := Parse(string(rune(0xFEFF))+base, "home"); err != nil {
		t.Fatal(err)
	}
}

func TestSectionBeforePeer(t *testing.T) {
	text := strings.Replace(base, "[Peer]", "[SplitWire]\nMode = exclude\nApp = C:\\x.exe\n\n[Peer]", 1)
	c, err := Parse(text, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeExclude || len(c.WG.Peers) != 1 {
		t.Fatalf("parsed %+v", c)
	}
}

func TestPlainWireGuardConfig(t *testing.T) {
	c, err := Parse(base, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeFull || !c.HasDefaultRoute() {
		t.Fatalf("parsed %+v", c)
	}
	split, err := Parse(strings.Replace(base, "0.0.0.0/0, ::/0", "192.168.50.0/24", 1), "home")
	if err != nil {
		t.Fatal(err)
	}
	if split.HasDefaultRoute() {
		t.Fatal("default route without one in AllowedIPs")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":          "[SplitWire]\nColor = blue\n",
		"include without apps": "[SplitWire]\nMode = include\n",
		"apps in full mode":    "[SplitWire]\nApp = C:\\x.exe\n",
		"bad mode":             "[SplitWire]\nMode = sideways\n",
	}
	for name, section := range cases {
		if _, err := Parse(base+section, "home"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse(strings.Replace(base, "[Interface]", "[Interface]\nTable = off", 1)+"[SplitWire]\nMode = include\nApp = C:\\x.exe\n", "home"); err == nil {
		t.Error("include mode with Table = off accepted")
	}
}

func TestExpandGlobs(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.exe", "b.exe", "c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := Parse(base+"[SplitWire]\nMode = include\nApp = "+filepath.Join(dir, "*.exe")+"\nApp = "+filepath.Join(dir, "none*.exe")+"\n", "home")
	if err != nil {
		t.Fatal(err)
	}
	paths, warnings, err := c.ExpandApps()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || len(warnings) != 1 {
		t.Fatalf("paths %v warnings %v", paths, warnings)
	}
}

func TestWithExpandedApps(t *testing.T) {
	c, err := Parse(base+"[SplitWire]\nMode = include\nApp = %SystemRoot%\\notepad.exe\n", "home")
	if err != nil {
		t.Fatal(err)
	}
	text, err := c.WithExpandedApps()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(text, "home")
	if err != nil {
		t.Fatal(err)
	}
	if again.Mode != ModeInclude || len(again.Apps) != 1 || strings.Contains(again.Apps[0], "%") {
		t.Fatalf("round trip %+v", again)
	}
}

func TestScopedDNS(t *testing.T) {
	office := strings.Replace(strings.Replace(base, "DNS = 10.8.0.1", "DNS = 10.8.0.1, corp.example", 1),
		"0.0.0.0/0, ::/0", "10.8.0.0/16", 1)
	for _, c := range []struct {
		name, text string
		want       bool
	}{
		{"routed with a domain", office, true},
		{"routed without a domain", strings.Replace(office, ", corp.example", "", 1), false},
		{"default route", strings.Replace(base, "DNS = 10.8.0.1", "DNS = 10.8.0.1, corp.example", 1), false},
		{"Split VPN", office + "\n[SplitWire]\nMode = include\nApp = C:\a.exe\n", false},
	} {
		cfg, err := Parse(c.text, "home")
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.ScopedDNS(); got != c.want {
			t.Errorf("%s: ScopedDNS %v, want %v", c.name, got, c.want)
		}
	}
}
