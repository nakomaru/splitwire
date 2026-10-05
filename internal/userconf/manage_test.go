package userconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"splitwire/internal/config"
)

func TestImportName(t *testing.T) {
	cases := map[string]string{
		"vpn US-WA#23":                    "vpn-US-WA-23",
		"wg0":                                "wg0",
		".hidden":                            "hidden",
		"a-very-long-file-name-for-a-tunnel": "a-very-long-file-name-for-a-t",
		"\u65E5\u672C":                       "--",
	}
	for in, want := range cases {
		if got := importName(in); got != want {
			t.Errorf("importName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewEmptyAndImport(t *testing.T) {
	UseDir(t.TempDir())
	defer UseDir("")
	name, err := NewEmpty()
	if err != nil {
		t.Fatal(err)
	}
	path, _ := Resolve(name)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("new tunnel %s does not parse: %v", name, err)
	}

	src := filepath.Join(t.TempDir(), "home office.conf")
	b, _ := os.ReadFile(path)
	text := strings.Split(string(b), "\n# Address")[0] + "\n"
	os.WriteFile(src, []byte(text), 0o600)
	got, err := Import(src)
	if err != nil {
		t.Fatal(err)
	}
	if got != "home-office" {
		t.Fatalf("imported as %s", got)
	}
	imported, _ := os.ReadFile(filepath.Join(filepath.Dir(path), got+".conf"))
	if !strings.Contains(string(imported), "[SplitWire]") {
		t.Fatal("import lacks the example section")
	}
	if err := Rename(got, "office"); err != nil {
		t.Fatal(err)
	}
	if err := Rename("office", "bad name"); err == nil {
		t.Fatal("renamed to an invalid name")
	}
}
