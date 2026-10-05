package userconf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"

	"splitwire/internal/config"
)

// ValidName reports why name cannot name a tunnel, or nil. Names follow
// the WireGuard app's rules, so tunnels move between the two.
func ValidName(name string) error {
	if !conf.TunnelNameIsValid(name) {
		return fmt.Errorf("a tunnel name has 1 to 32 letters, digits and the characters _ = + . -")
	}
	return nil
}

// Rename gives the tunnel old the name new.
func Rename(old, new string) error {
	if err := ValidName(new); err != nil {
		return err
	}
	from, err := Resolve(old)
	if err != nil {
		return err
	}
	to, err := Resolve(new)
	if err != nil {
		return err
	}
	if _, err := os.Stat(to); err == nil && !strings.EqualFold(from, to) {
		return fmt.Errorf("a tunnel named %s exists", new)
	}
	return os.Rename(from, to)
}

var procSHFileOperationW = windows.NewLazySystemDLL("shell32.dll").NewProc("SHFileOperationW")

// Recycle moves the tunnel's file to the Recycle Bin.
func Recycle(name string) error {
	path, err := Resolve(name)
	if err != nil {
		return err
	}
	from, err := windows.UTF16FromString(path)
	if err != nil {
		return err
	}
	from = append(from, 0) // the list of paths ends with an empty one
	const foDelete = 3
	const fofSilent, fofNoConfirmation, fofAllowUndo, fofNoErrorUI = 0x4, 0x10, 0x40, 0x400
	op := struct {
		hwnd                 uintptr
		function             uint32
		from, to             *uint16
		flags                uint16
		anyOperationsAborted int32
		nameMappings         uintptr
		progressTitle        *uint16
	}{function: foDelete, from: &from[0], flags: fofSilent | fofNoConfirmation | fofAllowUndo | fofNoErrorUI}
	if r, _, _ := procSHFileOperationW.Call(uintptr(unsafe.Pointer(&op))); r != 0 {
		return fmt.Errorf("move %s to the Recycle Bin: error %#x", path, r)
	}
	if op.anyOperationsAborted != 0 {
		return fmt.Errorf("moving %s to the Recycle Bin was canceled", path)
	}
	return nil
}

// NewEmpty creates a tunnel with a fresh private key and the example
// [Splitwire] section, to fill in with a peer.
func NewEmpty() (string, error) {
	key, err := conf.NewPrivateKey()
	if err != nil {
		return "", err
	}
	text := "[Interface]\nPrivateKey = " + key.String() + "\n# Address = \n# DNS = \n\n" +
		"# [Peer]\n# PublicKey = \n# AllowedIPs = 0.0.0.0/0, ::/0\n# Endpoint = \n\n" + config.ExampleSection
	return CreateNew("tunnel", text)
}

// Import copies a WireGuard configuration file in as a tunnel named after
// the file, adding the example [Splitwire] section when it has none.
func Import(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := strings.TrimPrefix(string(b), "\uFEFF")
	name := importName(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	if _, err := config.Parse(text, name); err != nil {
		return "", err
	}
	if !hasSection(text) {
		text = strings.TrimRight(text, "\r\n") + "\n\n" + config.ExampleSection
	}
	return CreateNew(name, text)
}

// importName turns a file name into a tunnel name, replacing characters
// tunnel names cannot have.
func importName(base string) string {
	name := strings.Map(func(r rune) rune {
		if r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_=+.-", r)) {
			return r
		}
		return '-'
	}, base)
	name = strings.Trim(name, ".")
	// CreateNew may add a suffix such as -2.
	if len(name) > 29 {
		name = name[:29]
	}
	if ValidName(name) != nil {
		return "tunnel"
	}
	return name
}

func hasSection(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.EqualFold(strings.TrimSpace(code), "[Splitwire]") {
			return true
		}
	}
	return false
}
