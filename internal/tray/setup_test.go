package tray

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDeleteSetup(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "installed.exe")
	same := filepath.Join(dir, "same.exe")
	other := filepath.Join(dir, "other.exe")
	os.WriteFile(installed, []byte("build 2"), 0o644)
	os.WriteFile(same, []byte("build 2"), 0o644)
	os.WriteFile(other, []byte("build 1"), 0o644)

	cmd := exec.Command("cmd", "/c", "exit")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := uint32(cmd.Process.Pid)
	deleteSetup(same, pid, installed)
	cmd.Wait()
	deleteSetup(other, pid, installed)
	deleteSetup(installed, pid, installed)

	if _, err := os.Stat(same); !os.IsNotExist(err) {
		t.Error("identical setup file kept")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("different file deleted")
	}
	if _, err := os.Stat(installed); err != nil {
		t.Error("installed copy deleted")
	}
}
