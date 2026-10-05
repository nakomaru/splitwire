package bootstrap

import (
	"context"
	"testing"
	"time"
)

// These tests download from the pinned URLs; -short skips them.

func TestFetchDriver(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	for arch, pin := range pins {
		t.Run(arch, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			sys, fetched, err := fetchDriver(ctx, pin)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256Hex(sys); got != pin.driverSHA256 {
				t.Fatalf("SHA-256 %s, want %s", got, pin.driverSHA256)
			}
			t.Logf("%s: %d bytes, %d KiB fetched", arch, len(sys), fetched>>10)
		})
	}
}

func TestFetchDLL(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	for arch, pin := range pins {
		t.Run(arch, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			dll, err := fetchDLL(ctx, pin)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256Hex(dll); got != pin.dllSHA256 {
				t.Fatalf("SHA-256 %s, want %s", got, pin.dllSHA256)
			}
		})
	}
}
