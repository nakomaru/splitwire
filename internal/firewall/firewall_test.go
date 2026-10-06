package firewall

import (
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// The WFP functions return their error codes rather than setting the last
// error; a failure, here for lack of administrator rights, carries its code.
func TestErrorCodes(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("registering the sublayers as an administrator succeeds")
	}
	err := EnsureSublayers()
	t.Logf("EnsureSublayers: %v", err)
	if err == nil {
		t.Fatal("registered the sublayers without administrator rights")
	}
	if errors.Is(err, syscall.EINVAL) {
		t.Fatalf("error code lost: %v", err)
	}
}
