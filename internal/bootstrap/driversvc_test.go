package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImageFile(t *testing.T) {
	root := os.Getenv("SystemRoot")
	for in, want := range map[string]string{
		`\??\C:\Program Files\splitwire\bin\mullvad-split-tunnel.sys`:           `C:\Program Files\splitwire\bin\mullvad-split-tunnel.sys`,
		`"\??\C:\Program Files\Mullvad VPN\resources\mullvad-split-tunnel.sys"`: `C:\Program Files\Mullvad VPN\resources\mullvad-split-tunnel.sys`,
		`\SystemRoot\System32\drivers\x.sys`:                                    filepath.Join(root, `System32\drivers\x.sys`),
		`System32\drivers\x.sys`:                                                filepath.Join(root, `System32\drivers\x.sys`),
	} {
		if got := imageFile(in); got != want {
			t.Errorf("imageFile(%s) = %s, want %s", in, got, want)
		}
	}
	if !sameImagePath(`\??\C:\PROGRAM FILES\splitwire\bin\x.sys`, `C:\Program Files\splitwire\bin\x.sys`) {
		t.Error("case-insensitive match failed")
	}
}
