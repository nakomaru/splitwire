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
[Splitwire]
Mode = include  # comment
App = C:\Program Files\Mozilla Firefox\firefox.exe
App = %SystemRoot%\System32\curl.exe
AllowLAN = yes
`, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeInclude || len(c.Apps) != 2 || !c.AllowLAN || !c.StrictDNS {
		t.Fatalf("parsed %+v", c)
	}
	if c.WG.Name != "home" || len(c.WG.Peers) != 1 {
		t.Fatalf("WireGuard part %+v", c.WG)
	}
	if c.KillSwitchOn() {
		t.Fatal("kill switch on in include mode")
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
	text := strings.Replace(base, "[Peer]", "[Splitwire]\nMode = exclude\nApp = C:\\x.exe\n\n[Peer]", 1)
	c, err := Parse(text, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeExclude || len(c.WG.Peers) != 1 || !c.KillSwitchOn() {
		t.Fatalf("parsed %+v", c)
	}
}

func TestPlainWireGuardConfig(t *testing.T) {
	c, err := Parse(base, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeFull || !c.KillSwitchOn() {
		t.Fatalf("parsed %+v", c)
	}
	split, err := Parse(strings.Replace(base, "0.0.0.0/0, ::/0", "192.168.50.0/24", 1), "home")
	if err != nil {
		t.Fatal(err)
	}
	if split.KillSwitchOn() {
		t.Fatal("kill switch on without a default route")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":          "[Splitwire]\nColor = blue\n",
		"include without apps": "[Splitwire]\nMode = include\n",
		"apps in full mode":    "[Splitwire]\nApp = C:\\x.exe\n",
		"bad mode":             "[Splitwire]\nMode = sideways\n",
		"bad switch":           "[Splitwire]\nAllowLAN = maybe\n",
	}
	for name, section := range cases {
		if _, err := Parse(base+section, "home"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse(strings.Replace(base, "[Interface]", "[Interface]\nTable = off", 1)+"[Splitwire]\nMode = include\nApp = C:\\x.exe\n", "home"); err == nil {
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
	c, err := Parse(base+"[Splitwire]\nMode = include\nApp = "+filepath.Join(dir, "*.exe")+"\nApp = "+filepath.Join(dir, "none*.exe")+"\n", "home")
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
	c, err := Parse(base+"[Splitwire]\nMode = include\nApp = %SystemRoot%\\notepad.exe\n", "home")
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
