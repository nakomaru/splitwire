package netcfg

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var procGetBestRoute2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")

// RouteOf asks Windows which route it picks for traffic to addr, and
// reports the interface's name and whether it is a tunnel adapter.
func RouteOf(addr netip.Addr) (iface string, tunnel bool, err error) {
	var dest, src winipcfg.RawSockaddrInet
	if err := dest.SetAddr(addr.Unmap()); err != nil {
		return "", false, err
	}
	var row winipcfg.MibIPforwardRow2
	r, _, _ := procGetBestRoute2.Call(0, 0, 0, uintptr(unsafe.Pointer(&dest)), 0,
		uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&src)))
	if r != 0 {
		return "", false, windows.Errno(r)
	}
	ifrow, err := row.InterfaceLUID.Interface()
	if err != nil {
		return "", false, err
	}
	return ifrow.Alias(), ifrow.Type == winipcfg.IfTypePropVirtual, nil
}
