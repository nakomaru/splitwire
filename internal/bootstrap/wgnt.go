package bootstrap

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/windows/driver"
)

// WireGuardNTInstalled reports whether the WireGuardNT kernel driver is
// installed.
func WireGuardNTInstalled() bool {
	_, err := os.Stat(filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "wireguard.sys"))
	return err == nil
}

// SplitDriverInstalled reports whether splitwire's copy of the split
// tunnel driver is in place.
func SplitDriverInstalled() bool {
	p, err := DriverPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// EnsureWireGuardNT installs the WireGuardNT driver. wireguard.dll installs
// it when it creates the first adapter, so this creates a temporary adapter
// and closes it, which deletes it.
func EnsureWireGuardNT(ctx context.Context) error {
	dll, err := EnsureWireGuardDLL(ctx)
	if err != nil {
		return err
	}
	if err := LoadWireGuardDLL(dll); err != nil {
		return err
	}
	if WireGuardNTInstalled() {
		return nil
	}
	a, err := driver.CreateAdapter("splitwire setup", "splitwire", nil)
	if err != nil {
		return fmt.Errorf("install the WireGuardNT driver: %w", err)
	}
	if v, err := driver.RunningVersion(); err == nil {
		log.Printf("Installed WireGuardNT %d.%d", (v>>16)&0xffff, v&0xffff)
	}
	a.Close()
	return nil
}
