package apps

import (
	"os"
	"testing"
	"time"
)

func TestPattern(t *testing.T) {
	cases := map[string]string{
		`C:\Users\a\AppData\Local\Discord\app-1.0.9163\Discord.exe`:             `C:\Users\a\AppData\Local\Discord\app-*\Discord.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\130.0.2849.80\x.exe`: `C:\Program Files (x86)\Microsoft\Edge\Application\*\x.exe`,
		`C:\Program Files\Mozilla Firefox\firefox.exe`:                          `C:\Program Files\Mozilla Firefox\firefox.exe`,
		`C:\Python313\python.exe`:                                               `C:\Python313\python.exe`,
		`C:\tools\1.2.exe`:                                                      `C:\tools\1.2.exe`,
	}
	for in, want := range cases {
		if got := Pattern(in); got != want {
			t.Errorf("Pattern(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestRot13(t *testing.T) {
	if got := rot13("{6Q809377-6NS0}\\Zbmvyyn.rkr"); got != "{6D809377-6AF0}\\Mozilla.exe" {
		t.Fatal(got)
	}
}

func TestFind(t *testing.T) {
	start := time.Now()
	all := Find()
	t.Logf("%d programs in %s", len(all), time.Since(start).Round(time.Millisecond))
	self, _ := os.Executable()
	for _, c := range all {
		if c.Path == self {
			t.Fatal("found the test itself")
		}
		if c.Name == "" {
			t.Errorf("%s has no name", c.Path)
		}
	}
	for i, c := range all {
		if i < 15 {
			t.Logf("%-28s running=%t start=%t used=%s %s", c.Name, c.Running, c.StartMenu, c.LastUsed.Format("2006-01-02"), c.Path)
		}
	}
}
