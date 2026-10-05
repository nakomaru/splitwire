// Package stdriver controls the Mullvad split tunnel driver (mullvad-split-tunnel.sys,
// interface version 1.3) through its IOCTL interface.
//
// Buffer layouts mirror the driver's x64 structures in src/defs/*.h of
// https://github.com/mullvad/win-split-tunnel. SIZE_T and HANDLE are 8 bytes.
package stdriver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	headerSize           = 16 // SIZE_T NumEntries, SIZE_T TotalLength
	configEntrySize      = 16 // SIZE_T ImageNameOffset, USHORT ImageNameLength, padding
	processEntrySize     = 32 // HANDLE ProcessId, HANDLE ParentProcessId, SIZE_T ImageNameOffset, USHORT ImageNameLength, padding
	ipAddressesSize      = 40 // IN_ADDR TunnelIpv4, IN_ADDR InternetIpv4, IN6_ADDR TunnelIpv6, IN6_ADDR InternetIpv6
	sublayerGUIDsSize    = 32 // GUID Baseline, GUID Dns
	eventHeaderDataStart = 16 // ST_EVENT_ID EventId, padding, SIZE_T EventSize
)

func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func utf16String(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func putGUID(b []byte, g windows.GUID) {
	binary.LittleEndian.PutUint32(b[0:], g.Data1)
	binary.LittleEndian.PutUint16(b[4:], g.Data2)
	binary.LittleEndian.PutUint16(b[6:], g.Data3)
	copy(b[8:16], g.Data4[:])
}

func encodeSublayerGUIDs(baseline, dns windows.GUID) []byte {
	b := make([]byte, sublayerGUIDsSize)
	putGUID(b[0:], baseline)
	putGUID(b[16:], dns)
	return b
}

// Addresses is the address pair per family that the driver redirects between:
// sockets of split processes bound to Tunnel (or unbound) are rebound to Internet.
// An invalid netip.Addr leaves that slot empty.
type Addresses struct {
	TunnelIPv4, InternetIPv4 netip.Addr
	TunnelIPv6, InternetIPv6 netip.Addr
}

func encodeAddresses(a Addresses) ([]byte, error) {
	b := make([]byte, ipAddressesSize)
	put := func(off int, addr netip.Addr, v6 bool) error {
		if !addr.IsValid() {
			return nil
		}
		addr = addr.Unmap()
		if addr.Is4() == v6 {
			return fmt.Errorf("address %s is in the wrong family", addr)
		}
		copy(b[off:], addr.AsSlice())
		return nil
	}
	if err := errors.Join(
		put(0, a.TunnelIPv4, false),
		put(4, a.InternetIPv4, false),
		put(8, a.TunnelIPv6, true),
		put(24, a.InternetIPv6, true),
	); err != nil {
		return nil, err
	}
	return b, nil
}

func decodeAddresses(b []byte) (Addresses, error) {
	if len(b) < ipAddressesSize {
		return Addresses{}, fmt.Errorf("short address buffer: %d bytes", len(b))
	}
	get4 := func(off int) netip.Addr {
		a := netip.AddrFrom4([4]byte(b[off : off+4]))
		if a.IsUnspecified() {
			return netip.Addr{}
		}
		return a
	}
	get6 := func(off int) netip.Addr {
		a := netip.AddrFrom16([16]byte(b[off : off+16]))
		if a.IsUnspecified() {
			return netip.Addr{}
		}
		return a
	}
	return Addresses{
		TunnelIPv4:   get4(0),
		InternetIPv4: get4(4),
		TunnelIPv6:   get6(8),
		InternetIPv6: get6(24),
	}, nil
}

// encodeConfiguration builds ST_CONFIGURATION_HEADER, its entries and the
// string region from NT device paths.
func encodeConfiguration(devicePaths []string) ([]byte, error) {
	names := make([][]byte, len(devicePaths))
	total := headerSize + configEntrySize*len(devicePaths)
	for i, p := range devicePaths {
		names[i] = utf16Bytes(p)
		if len(names[i]) > 0xffff {
			return nil, fmt.Errorf("path too long: %s", p)
		}
		total += len(names[i])
	}
	b := make([]byte, total)
	binary.LittleEndian.PutUint64(b[0:], uint64(len(devicePaths)))
	binary.LittleEndian.PutUint64(b[8:], uint64(total))
	strings := b[headerSize+configEntrySize*len(devicePaths):]
	offset := 0
	for i, n := range names {
		e := b[headerSize+configEntrySize*i:]
		binary.LittleEndian.PutUint64(e[0:], uint64(offset))
		binary.LittleEndian.PutUint16(e[8:], uint16(len(n)))
		copy(strings[offset:], n)
		offset += len(n)
	}
	return b, nil
}

// Process is one entry of the initial process registration.
type Process struct {
	PID, ParentPID uint32
	DevicePath     string
}

func encodeProcesses(procs []Process) ([]byte, error) {
	names := make([][]byte, len(procs))
	total := headerSize + processEntrySize*len(procs)
	for i, p := range procs {
		names[i] = utf16Bytes(p.DevicePath)
		if len(names[i]) > 0xffff {
			return nil, fmt.Errorf("path too long: %s", p.DevicePath)
		}
		total += len(names[i])
	}
	b := make([]byte, total)
	binary.LittleEndian.PutUint64(b[0:], uint64(len(procs)))
	binary.LittleEndian.PutUint64(b[8:], uint64(total))
	strings := b[headerSize+processEntrySize*len(procs):]
	offset := 0
	for i, p := range procs {
		e := b[headerSize+processEntrySize*i:]
		binary.LittleEndian.PutUint64(e[0:], uint64(p.PID))
		binary.LittleEndian.PutUint64(e[8:], uint64(p.ParentPID))
		if len(names[i]) > 0 {
			binary.LittleEndian.PutUint64(e[16:], uint64(offset))
			binary.LittleEndian.PutUint16(e[24:], uint16(len(names[i])))
			copy(strings[offset:], names[i])
			offset += len(names[i])
		}
	}
	return b, nil
}

// EventKind identifies a driver event.
type EventKind uint32

const (
	EventStartSplitting      EventKind = 0
	EventStopSplitting       EventKind = 1
	EventErrorStartSplitting EventKind = 0x80000001
	EventErrorStopSplitting  EventKind = 0x80000002
	EventErrorMessage        EventKind = 0x80000003
)

// Reason flags of splitting events.
const (
	ReasonByInheritance    = 1
	ReasonByConfig         = 2
	ReasonProcessArriving  = 4
	ReasonProcessDeparting = 8
)

// Event is a decoded driver event. Fields not carried by Kind are zero.
type Event struct {
	Kind      EventKind
	PID       uint32
	Reason    uint32
	ImageName string
	Status    uint32
	Message   string
}

func decodeEvent(b []byte) (Event, error) {
	if len(b) < eventHeaderDataStart {
		return Event{}, fmt.Errorf("short event: %d bytes", len(b))
	}
	ev := Event{Kind: EventKind(binary.LittleEndian.Uint32(b[0:]))}
	size := binary.LittleEndian.Uint64(b[8:])
	data := b[eventHeaderDataStart:]
	if uint64(len(data)) < size {
		return Event{}, fmt.Errorf("truncated event: %d of %d bytes", len(data), size)
	}
	data = data[:size]
	str := func(lengthOff, strOff int) (string, error) {
		if len(data) < strOff {
			return "", fmt.Errorf("short event payload: %d bytes", len(data))
		}
		n := int(binary.LittleEndian.Uint16(data[lengthOff:]))
		if len(data) < strOff+n {
			return "", fmt.Errorf("event string overruns payload")
		}
		return utf16String(data[strOff : strOff+n]), nil
	}
	var err error
	switch ev.Kind {
	case EventStartSplitting, EventStopSplitting:
		// HANDLE ProcessId, enum Reason, USHORT ImageNameLength, WCHAR ImageName[]
		if len(data) >= 12 {
			ev.PID = uint32(binary.LittleEndian.Uint64(data[0:]))
			ev.Reason = binary.LittleEndian.Uint32(data[8:])
		}
		ev.ImageName, err = str(12, 14)
	case EventErrorStartSplitting, EventErrorStopSplitting:
		// HANDLE ProcessId, USHORT ImageNameLength, WCHAR ImageName[]
		if len(data) >= 8 {
			ev.PID = uint32(binary.LittleEndian.Uint64(data[0:]))
		}
		ev.ImageName, err = str(8, 10)
	case EventErrorMessage:
		// NTSTATUS Status, USHORT ErrorMessageLength, WCHAR ErrorMessage[]
		if len(data) >= 4 {
			ev.Status = binary.LittleEndian.Uint32(data[0:])
		}
		ev.Message, err = str(4, 6)
	default:
		return Event{}, fmt.Errorf("unknown event id 0x%08x", uint32(ev.Kind))
	}
	return ev, err
}
