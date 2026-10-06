// Package pmtu finds the largest packet that a path carries whole, by
// pinging with packets that may not be split.
package pmtu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// ipOptions is IP_OPTION_INFORMATION.
type ipOptions struct {
	ttl, tos, flags, size uint8
	data                  uintptr
}

// echoReply is ICMP_ECHO_REPLY.
type echoReply struct {
	address, status, rtt uint32
	dataSize, reserved   uint16
	data                 uintptr
	options              ipOptions
}

const (
	ipFlagDF      = 0x2
	ipv6DontFrag  = 14 // IPV6_DONTFRAG
	icmpv6Echo    = 128
	icmpv6Reply   = 129
	timeout       = time.Second
	ipv4Header    = 20
	ipv6Header    = 40
	icmpHeader    = 8
	ethernetMTU   = 1500
	ipv4MinMTU    = 576
	ipv6MinMTU    = 1280
	timeoutMillis = uint32(timeout / time.Millisecond)
)

// Probe finds the largest packet, up to Ethernet's 1500 bytes, that reaches
// addr and draws a reply without being split. A lost packet counts as too
// big, so a lossy path reads low. It fails when addr does not answer the
// smallest packet the address family allows.
func Probe(ctx context.Context, addr netip.Addr) (int, error) {
	addr = addr.Unmap()
	if addr.Is4() {
		return probe4(ctx, addr)
	}
	return probe6(ctx, addr)
}

// search finds the largest size from lo to hi that fits, given that lo
// does.
func search(ctx context.Context, lo, hi int, fits func(int) bool) (int, error) {
	if fits(hi) {
		return hi, nil
	}
	for hi-lo > 1 { // lo fits; hi does not
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		mid := (lo + hi) / 2
		if fits(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}

func probe4(ctx context.Context, addr netip.Addr) (int, error) {
	h, _, err := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return 0, err
	}
	defer procIcmpCloseHandle.Call(h)

	ip := addr.As4()
	dst := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
	reply := make([]byte, int(unsafe.Sizeof(echoReply{}))+ethernetMTU+64)
	fits := func(size int) bool {
		payload := make([]byte, size-ipv4Header-icmpHeader)
		opts := ipOptions{ttl: 128, flags: ipFlagDF}
		n, _, _ := procIcmpSendEcho.Call(h, uintptr(dst), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
			uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeoutMillis))
		r := (*echoReply)(unsafe.Pointer(&reply[0]))
		return n > 0 && r.status == 0 && r.address == dst
	}
	if !fits(ipv4MinMTU) {
		return 0, fmt.Errorf("%s does not answer pings", addr)
	}
	return search(ctx, ipv4MinMTU, ethernetMTU, fits)
}

// probe6 pings through a raw ICMPv6 socket with IPV6_DONTFRAG, since
// Windows splits the IPv6 pings of its ping functions whatever their
// flags. A packet bigger than the path fails to send, or draws a Packet
// Too Big message in place of a reply.
func probe6(ctx context.Context, addr netip.Addr) (int, error) {
	s, err := windows.Socket(windows.AF_INET6, windows.SOCK_RAW, windows.IPPROTO_ICMPV6)
	if err != nil {
		if errors.Is(err, windows.WSAEACCES) {
			return 0, errors.New("Windows denied the IPv6 ping socket")
		}
		return 0, err
	}
	defer windows.Closesocket(s)
	if err := windows.SetsockoptInt(s, windows.IPPROTO_IPV6, ipv6DontFrag, 1); err != nil {
		return 0, err
	}
	if err := windows.SetsockoptInt(s, windows.SOL_SOCKET, windows.SO_RCVTIMEO, int(timeoutMillis)); err != nil {
		return 0, err
	}
	to := &windows.SockaddrInet6{Addr: addr.As16()}
	id := uint16(os.Getpid())
	var seq uint16
	buf := make([]byte, 64<<10)
	fits := func(size int) bool {
		seq++
		packet := make([]byte, size-ipv6Header)
		packet[0] = icmpv6Echo
		binary.BigEndian.PutUint16(packet[4:], id)
		binary.BigEndian.PutUint16(packet[6:], seq)
		if err := windows.Sendto(s, packet, 0, to); err != nil {
			return false
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			n, from, err := windows.Recvfrom(s, buf, 0)
			if err != nil {
				return false
			}
			sa, ok := from.(*windows.SockaddrInet6)
			if !ok || netip.AddrFrom16(sa.Addr) != addr || n < icmpHeader || buf[0] != icmpv6Reply {
				continue
			}
			if binary.BigEndian.Uint16(buf[4:]) == id && binary.BigEndian.Uint16(buf[6:]) == seq {
				return true
			}
		}
		return false
	}
	if !fits(ipv6MinMTU) {
		return 0, fmt.Errorf("%s does not answer pings", addr)
	}
	return search(ctx, ipv6MinMTU, ethernetMTU, fits)
}

// Overhead is what WireGuard adds to a packet carried over addr's family:
// the IP and UDP headers and its own 32 bytes.
func Overhead(addr netip.Addr) int {
	if addr.Unmap().Is4() {
		return ipv4Header + 8 + 32
	}
	return ipv6Header + 8 + 32
}
