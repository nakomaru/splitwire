package config

import (
	"strings"
	"testing"
)

func TestSetValue(t *testing.T) {
	cases := []struct {
		in, key, val string
		isDefault    bool
		want         string
	}{
		{"[Interface]\n", "Mode", "include", false, "[Interface]\n\n[SplitWire]\nMode = include\n"},
		{"[Interface]\n", "KillSwitch", "auto", true, "[Interface]\n"},
		{"[SplitWire]\nMode = include\n# AllowLAN = off\n", "AllowLAN", "on", false,
			"[SplitWire]\nMode = include\nAllowLAN = on\n# AllowLAN = off\n"},
		{"[SplitWire]\r\nAllowLAN = on\r\nallowlan = off\r\n", "AllowLAN", "off", true, "[SplitWire]\r\nAllowLAN = off\r\n"},
		{"[SplitWire]\n# Mode = include\n", "Mode", "exclude", false, "[SplitWire]\nMode = exclude\n# Mode = include\n"},
	}
	for i, c := range cases {
		if got := SetValue(c.in, c.key, c.val, c.isDefault); got != c.want {
			t.Errorf("case %d:\n%q\nwant\n%q", i, got, c.want)
		}
	}
}

func TestSetApps(t *testing.T) {
	cases := []struct {
		in   string
		apps []string
		want string
	}{
		{"[SplitWire]\nMode = include\nApp = C:\\a.exe\nKillSwitch = on\nApp = C:\\b.exe\n", []string{`C:\c.exe`},
			"[SplitWire]\nMode = include\nApp = C:\\c.exe\nKillSwitch = on\n"},
		{"[SplitWire]\nAllowLAN = on\nMode = exclude\n# App = C:\\x.exe\n", []string{`C:\a.exe`, `C:\b.exe`},
			"[SplitWire]\nAllowLAN = on\nMode = exclude\nApp = C:\\a.exe\nApp = C:\\b.exe\n# App = C:\\x.exe\n"},
		{"[SplitWire]\nMode = include\nApp = C:\\a.exe\n", nil, "[SplitWire]\nMode = include\n"},
		{"[Interface]\n", []string{`C:\a.exe`}, "[Interface]\n\n[SplitWire]\nApp = C:\\a.exe\n"},
	}
	for i, c := range cases {
		if got := SetApps(c.in, c.apps); got != c.want {
			t.Errorf("case %d:\n%q\nwant\n%q", i, got, c.want)
		}
	}
}

// TestEditExample edits a tunnel with the example section the way the
// window does, keeping every example line.
func TestEditExample(t *testing.T) {
	text := base + "\n" + ExampleSection
	text = SetValue(text, "Mode", "include", false)
	text = SetApps(text, []string{`C:\Windows\System32\curl.exe`})
	text = SetValue(text, "Proxy", "1081", false)
	c, err := Parse(text, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeInclude || len(c.Apps) != 1 || c.Proxy.Port() != 1081 {
		t.Fatalf("parsed %+v", c)
	}
	want := "[SplitWire]\nMode = include\nApp = C:\\Windows\\System32\\curl.exe\nProxy = 1081\n# Settings for splitwire"
	if !strings.Contains(text, want) {
		t.Fatalf("settings not at the top of the section:\n%s", text)
	}
	for _, line := range strings.Split(ExampleSection, "\n") {
		if !strings.Contains(text, line) {
			t.Fatalf("lost example line %q", line)
		}
	}
}

// TestFullKeepsApps checks that an explicit Mode = full keeps App entries
// unused, while App entries without a Mode stay an error.
func TestFullKeepsApps(t *testing.T) {
	c, err := Parse(base+"\n[SplitWire]\nMode = full\nApp = C:\\a.exe\n", "home")
	if err != nil {
		t.Fatal(err)
	}
	text, err := c.WithExpandedApps()
	if err != nil || strings.Contains(text, "App =") {
		t.Fatalf("expanded %q, %v", text, err)
	}
	if _, err := Parse(base+"\n[SplitWire]\nApp = C:\\a.exe\n", "home"); err == nil {
		t.Fatal("App without Mode parsed")
	}
}
