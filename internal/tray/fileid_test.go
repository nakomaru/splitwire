package tray

import (
	"os"
	"path/filepath"
	"testing"
)

// A file keeps its identity when renamed, and a new file at its path has
// another.
func TestFileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.exe")
	os.WriteFile(path, []byte("v1"), 0o600)
	first, err := fileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if moved, err := fileIdentity(path + ".old"); err != nil || moved != first {
		t.Fatalf("renamed %v, %v; was %v", moved, err, first)
	}
	os.WriteFile(path, []byte("v2"), 0o600)
	if next, err := fileIdentity(path); err != nil || next == first {
		t.Fatalf("replaced %v, %v; was %v", next, err, first)
	}
}
