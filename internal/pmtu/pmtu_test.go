package pmtu

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// TestProbe pings the addresses in $SPLITWIRE_PMTU_HOSTS, separated by
// commas, which must answer pings. IPv6 needs administrator rights.
func TestProbe(t *testing.T) {
	hosts := os.Getenv("SPLITWIRE_PMTU_HOSTS")
	if hosts == "" {
		t.Skip("set SPLITWIRE_PMTU_HOSTS to addresses that answer pings")
	}
	for _, h := range strings.Split(hosts, ",") {
		addr := netip.MustParseAddr(h)
		size, err := Probe(context.Background(), addr)
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		t.Logf("%s carries %d-byte packets: MTU %d", addr, size, size-Overhead(addr))
	}
}
