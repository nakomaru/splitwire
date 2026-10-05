package stdriver

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCtlCodes(t *testing.T) {
	// CTL_CODE(0x8000, n, method, FILE_ANY_ACCESS)
	cases := []struct{ got, want uint32 }{
		{ioctlInitialize, 0x80000004},
		{ioctlRegisterProcesses, 0x8000000c},
		{ioctlClearConfig, 0x80000023},
		{ioctlReset, 0x8000002f},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("ioctl code 0x%08x, want 0x%08x", c.got, c.want)
		}
	}
}

func TestEncodeSublayerGUIDs(t *testing.T) {
	g := windows.GUID{Data1: 0x01020304, Data2: 0x0506, Data3: 0x0708, Data4: [8]byte{9, 10, 11, 12, 13, 14, 15, 16}}
	b := encodeSublayerGUIDs(g, g)
	want := []byte{4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16}
	if !bytes.Equal(b[:16], want) || !bytes.Equal(b[16:], want) {
		t.Fatalf("GUID bytes %x", b)
	}
}

func TestEncodeAddresses(t *testing.T) {
	b, err := encodeAddresses(Addresses{
		TunnelIPv4:   netip.MustParseAddr("10.8.0.2"),
		InternetIPv4: netip.MustParseAddr("192.168.1.20"),
		InternetIPv6: netip.MustParseAddr("2001:db8::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != ipAddressesSize {
		t.Fatalf("size %d", len(b))
	}
	if !bytes.Equal(b[0:4], []byte{10, 8, 0, 2}) || !bytes.Equal(b[4:8], []byte{192, 168, 1, 20}) {
		t.Fatalf("IPv4 bytes %x", b[:8])
	}
	if !bytes.Equal(b[8:24], make([]byte, 16)) {
		t.Fatalf("empty tunnel IPv6 slot is %x", b[8:24])
	}
	if b[24] != 0x20 || b[25] != 0x01 || b[39] != 1 {
		t.Fatalf("internet IPv6 bytes %x", b[24:40])
	}
	back, err := decodeAddresses(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.TunnelIPv4.String() != "10.8.0.2" || back.TunnelIPv6.IsValid() || back.InternetIPv6.String() != "2001:db8::1" {
		t.Fatalf("round trip %+v", back)
	}
	if _, err := encodeAddresses(Addresses{TunnelIPv4: netip.MustParseAddr("::1")}); err == nil {
		t.Fatal("IPv6 address in IPv4 slot accepted")
	}
}

func TestEncodeConfiguration(t *testing.T) {
	paths := []string{`\Device\HarddiskVolume3\a.exe`, `\Device\HarddiskVolume3\bb.exe`}
	b, err := encodeConfiguration(paths)
	if err != nil {
		t.Fatal(err)
	}
	strBase := headerSize + 2*configEntrySize
	wantLen := strBase + 2*(len(paths[0])+len(paths[1]))
	if len(b) != wantLen {
		t.Fatalf("length %d, want %d", len(b), wantLen)
	}
	if n := binary.LittleEndian.Uint64(b[0:]); n != 2 {
		t.Fatalf("NumEntries %d", n)
	}
	if n := binary.LittleEndian.Uint64(b[8:]); n != uint64(wantLen) {
		t.Fatalf("TotalLength %d", n)
	}
	off1 := binary.LittleEndian.Uint64(b[headerSize+configEntrySize:])
	len1 := binary.LittleEndian.Uint16(b[headerSize+configEntrySize+8:])
	if off1 != uint64(2*len(paths[0])) || int(len1) != 2*len(paths[1]) {
		t.Fatalf("entry 1 offset %d length %d", off1, len1)
	}
	if got := utf16String(b[strBase+int(off1) : strBase+int(off1)+int(len1)]); got != paths[1] {
		t.Fatalf("entry 1 string %q", got)
	}
}

func TestEncodeProcesses(t *testing.T) {
	b, err := encodeProcesses([]Process{
		{PID: 4, ParentPID: 0},
		{PID: 1234, ParentPID: 4, DevicePath: `\Device\X\p.exe`},
	})
	if err != nil {
		t.Fatal(err)
	}
	e1 := b[headerSize+processEntrySize:]
	if binary.LittleEndian.Uint64(e1[0:]) != 1234 || binary.LittleEndian.Uint64(e1[8:]) != 4 {
		t.Fatalf("entry 1 ids %x", e1[:16])
	}
	if binary.LittleEndian.Uint64(e1[16:]) != 0 || binary.LittleEndian.Uint16(e1[24:]) != uint16(2*len(`\Device\X\p.exe`)) {
		t.Fatalf("entry 1 string ref %x", e1[16:32])
	}
	e0 := b[headerSize:]
	if binary.LittleEndian.Uint16(e0[24:]) != 0 {
		t.Fatal("entry without path has a length")
	}
}

func TestDecodeEvent(t *testing.T) {
	name := utf16Bytes(`\Device\X\p.exe`)
	payload := make([]byte, 14+len(name))
	binary.LittleEndian.PutUint64(payload[0:], 1234)
	binary.LittleEndian.PutUint32(payload[8:], ReasonByConfig|ReasonProcessArriving)
	binary.LittleEndian.PutUint16(payload[12:], uint16(len(name)))
	copy(payload[14:], name)
	buf := make([]byte, eventHeaderDataStart+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], uint32(EventStartSplitting))
	binary.LittleEndian.PutUint64(buf[8:], uint64(len(payload)))
	copy(buf[eventHeaderDataStart:], payload)

	ev, err := decodeEvent(buf)
	if err != nil {
		t.Fatal(err)
	}
	if ev.PID != 1234 || ev.Reason != ReasonByConfig|ReasonProcessArriving || ev.ImageName != `\Device\X\p.exe` {
		t.Fatalf("event %+v", ev)
	}
	if _, err := decodeEvent(buf[:len(buf)-2]); err == nil {
		t.Fatal("truncated event accepted")
	}
}

func TestDevicePath(t *testing.T) {
	notepad := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	got, err := DevicePath(notepad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, `\Device\`) || !strings.HasSuffix(strings.ToLower(got), `\windows\system32\notepad.exe`) {
		t.Fatalf("DevicePath(%s) = %s", notepad, got)
	}
	missing := filepath.Join(filepath.VolumeName(notepad)+`\`, "no-such-dir", "x.exe")
	got2, err := DevicePath(missing)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got2, `\no-such-dir\x.exe`) || !strings.HasPrefix(got2, `\Device\`) {
		t.Fatalf("DevicePath(%s) = %s", missing, got2)
	}
}

func TestProcesses(t *testing.T) {
	procs, err := Processes()
	if err != nil {
		t.Fatal(err)
	}
	self := uint32(os.Getpid())
	for _, p := range procs {
		if p.PID == self {
			if !strings.HasPrefix(p.DevicePath, `\Device\`) || !filepath.IsAbs(p.DOSPath) {
				t.Fatalf("own process paths %q %q", p.DevicePath, p.DOSPath)
			}
			return
		}
	}
	t.Fatal("own process missing from listing")
}
