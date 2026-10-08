package bootstrap

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
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

// hold copies the test binary to path and runs it until the returned
// function ends it.
func hold(t *testing.T, path string) (end func()) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=^$")
	cmd.Env = append(os.Environ(), "BOOTSTRAP_TEST_HOLD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	end = func() {
		once.Do(func() {
			stdin.Close()
			cmd.Wait()
		})
	}
	t.Cleanup(end)
	return end
}

// A copy moved aside that still runs leaves the next replacement another
// name, and goes once it stops.
func TestReplaceFileOldRunning(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "app.exe")
	end := hold(t, dst+".old")
	os.WriteFile(dst, []byte("v1"), 0o755)

	if err := replaceFile(dst, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst + ".old1"); string(got) != "v1" {
		t.Fatalf("moved aside %q", got)
	}

	end()
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

// DeleteAside waits for the process running a copy moved aside, then
// deletes it.
func TestDeleteAside(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "app.exe")
	end := hold(t, dst)
	if err := replaceFile(dst, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- deleteAside(dst) }()
	if _, err := os.Stat(dst + ".old"); err != nil {
		t.Fatalf("the running copy is gone: %v", err)
	}
	end()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("deleteAside outlived the process")
	}
	if _, err := os.Stat(dst + ".old"); !os.IsNotExist(err) {
		t.Fatalf("the copy moved aside remains: %v", err)
	}
}
