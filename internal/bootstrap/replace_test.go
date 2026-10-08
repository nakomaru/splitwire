package bootstrap

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// TestMain doubles as a process that runs until its stdin closes, to hold an
// executable in use.
func TestMain(m *testing.M) {
	if os.Getenv("BOOTSTRAP_TEST_HOLD") == "1" {
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A copy moved aside that still runs leaves the next replacement another
// name, and goes once it stops.
func TestReplaceFileOldRunning(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "app.exe")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst+".old", b, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dst, []byte("v1"), 0o755)
	cmd := exec.Command(dst+".old", "-test.run=^$")
	cmd.Env = append(os.Environ(), "BOOTSTRAP_TEST_HOLD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer stdin.Close()

	if err := replaceFile(dst, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst + ".old1"); string(got) != "v1" {
		t.Fatalf("moved aside %q", got)
	}

	stdin.Close()
	cmd.Wait()
	if err := replaceFile(dst, []byte("v3")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"app.exe", "app.exe.old"}; !slices.Equal(names, want) {
		t.Fatalf("files %v, want %v", names, want)
	}
	cur, _ := os.ReadFile(dst)
	old, _ := os.ReadFile(dst + ".old")
	if string(cur) != "v3" || string(old) != "v2" {
		t.Fatalf("file %q, moved aside %q", cur, old)
	}
}
