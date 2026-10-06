package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveTreeKeeps(t *testing.T) {
	root := filepath.Join(t.TempDir(), "splitwire")
	keep := filepath.Join(root, "configs", "settings.json")
	for _, f := range []string{keep, filepath.Join(root, "configs", "boot.json"), filepath.Join(root, "bin", "splitwire.exe"),
		filepath.Join(root, "logs", "manager.log")} {
		os.MkdirAll(filepath.Dir(f), 0o700)
		os.WriteFile(f, []byte("x"), 0o600)
	}
	if pending, err := removeTree(root, keep); err != nil || pending != 0 {
		t.Fatalf("pending %d, %v", pending, err)
	}
	var left []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, p)
		left = append(left, rel)
		return nil
	})
	if want := []string{".", "configs", filepath.Join("configs", "settings.json")}; len(left) != len(want) ||
		left[0] != want[0] || left[1] != want[1] || left[2] != want[2] {
		t.Fatalf("left %v, want %v", left, want)
	}
	if _, err := removeTree(root, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("root remains: %v", err)
	}
}
