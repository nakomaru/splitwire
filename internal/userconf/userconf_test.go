package userconf

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Resolve("home")
	if err != nil || got != filepath.Join(dir, "home.conf") {
		t.Fatalf("Resolve(home) = %s, %v", got, err)
	}
	for _, arg := range []string{`C:\x\home.conf`, `.\home.conf`, "home.conf", "sub/home"} {
		if !IsPath(arg) {
			t.Errorf("%s not treated as a path", arg)
		}
	}
	// Not in the current folder, so it falls back to Dir.
	got, err = Resolve("no-such-tunnel.conf")
	if err != nil || got != filepath.Join(dir, "no-such-tunnel.conf") {
		t.Fatalf("Resolve(no-such-tunnel.conf) = %s, %v", got, err)
	}
	got, err = Resolve(`%APPDATA%\splitwire\home.conf`)
	if err != nil || got != filepath.Join(dir, "home.conf") {
		t.Fatalf("Resolve(%%APPDATA%%...) = %s, %v", got, err)
	}
	got, err = Resolve(`.\sub\home.conf`)
	if err != nil || strings.HasPrefix(got, dir) || !filepath.IsAbs(got) {
		t.Fatalf(`Resolve(.\sub\home.conf) = %s, %v`, got, err)
	}
}
