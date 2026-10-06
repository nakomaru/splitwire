package engine

import (
	"net/netip"
	"testing"

	"splitwire/internal/config"
	"splitwire/internal/netcfg"
)

func TestDriverAddresses(t *testing.T) {
	wg4 := netip.MustParseAddr("10.8.0.2")
	phys := netcfg.Physical{V4: netcfg.Link{Addr: netip.MustParseAddr("192.168.1.20")}, V6: netcfg.Link{Addr: netip.MustParseAddr("2001:db8::20")}}

	inc := driverAddresses(config.ModeInclude, wg4, netip.Addr{}, phys)
	if inc.TunnelIPv4 != phys.V4.Addr || inc.InternetIPv4 != wg4 {
		t.Fatalf("include IPv4 %+v", inc)
	}
	// No tunnel IPv6: the physical IPv6 address stays in the Tunnel slot so
	// the driver blocks it for listed apps.
	if inc.TunnelIPv6 != phys.V6.Addr || inc.InternetIPv6.IsValid() {
		t.Fatalf("include IPv6 %+v", inc)
	}

	exc := driverAddresses(config.ModeExclude, wg4, netip.Addr{}, phys)
	if exc.TunnelIPv4 != wg4 || exc.InternetIPv4 != phys.V4.Addr || exc.TunnelIPv6.IsValid() || exc.InternetIPv6 != phys.V6.Addr {
		t.Fatalf("exclude %+v", exc)
	}
}

func TestAdapterGUIDStable(t *testing.T) {
	a, b := adapterGUID("home"), adapterGUID("home")
	if *a != *b || *a == *adapterGUID("work") {
		t.Fatal("adapter GUID not stable per name")
	}
	if a.Data3>>12 != 5 || a.Data4[0]>>6 != 2 {
		t.Fatalf("GUID version/variant bits %v", a)
	}
}
