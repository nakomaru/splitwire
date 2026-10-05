package config

import (
	"strings"
	"testing"
)

func TestExampleSection(t *testing.T) {
	c, err := Parse(base+"\n"+ExampleSection, "home")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeFull || len(c.Apps) != 0 || c.Proxy.IsValid() {
		t.Fatalf("commented examples took effect: %+v", c)
	}

	// Each example block parses once uncommented.
	for _, mode := range []string{"Mode = include", "Mode = exclude"} {
		var lines []string
		on := false
		for _, l := range strings.Split(ExampleSection, "\n") {
			switch {
			case l == "# "+mode:
				on = true
			case on && strings.HasPrefix(l, "# App = "):
			default:
				on = false
			}
			if on {
				l = strings.TrimPrefix(l, "# ")
			}
			lines = append(lines, l)
		}
		c, err := Parse(base+"\n"+strings.Join(lines, "\n"), "home")
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if c.Mode.String() != strings.TrimPrefix(mode, "Mode = ") || len(c.Apps) != 2 {
			t.Fatalf("%s parsed as %s with %d apps", mode, c.Mode, len(c.Apps))
		}
	}
}
