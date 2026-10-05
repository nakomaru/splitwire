package bootstrap

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bodgit/sevenzip"
	"golang.org/x/sys/windows"

	"splitwire/internal/fetch"
)

// WireGuardNT 1.1 SDK. The zip's hash covers every DLL inside it.
const (
	wgntURL    = "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip"
	wgntSHA256 = "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"
	wgntLimit  = 16 << 20
	DLLName    = "wireguard.dll"
)

// DriverFile is the file name of the split tunnel driver.
const DriverFile = "mullvad-split-tunnel.sys"

type archPins struct {
	wgntDir   string // directory under wireguard-nt/bin
	dllSHA256 string

	installerURL string
	// sevenZipOffset is where the app archive starts inside the installer.
	sevenZipOffset int64
	driverSHA256   string
}

// Mullvad VPN 2026.5 ships driver 1.3.0.0, the interface version stdriver speaks.
var pins = map[string]archPins{
	"amd64": {
		wgntDir:        "amd64",
		dllSHA256:      "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3",
		installerURL:   "https://cdn.mullvad.net/app/desktop/releases/2026.5/MullvadVPN-2026.5_x64.exe",
		sevenZipOffset: 3267010,
		driverSHA256:   "10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201",
	},
	"arm64": {
		wgntDir:        "arm64",
		dllSHA256:      "75bcdc025d6c00e8315af5d62b869d760ca6a253fc82d70f146e789f059a3e0c",
		installerURL:   "https://cdn.mullvad.net/app/desktop/releases/2026.5/MullvadVPN-2026.5_arm64.exe",
		sevenZipOffset: 3123354,
		driverSHA256:   "6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534",
	},
}

func archPin() (archPins, error) {
	p, ok := pins[runtime.GOARCH]
	if !ok {
		return archPins{}, fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}
	return p, nil
}

// DLLPath is the installed location of wireguard.dll.
func DLLPath() (string, error) {
	dir, err := BinDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, DLLName), nil
}

// DriverPath is the installed location of the split tunnel driver.
func DriverPath() (string, error) {
	dir, err := BinDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, DriverFile), nil
}

// EnsureWireGuardDLL installs wireguard.dll if it is missing or differs from
// the pinned build.
func EnsureWireGuardDLL(ctx context.Context) (string, error) {
	pin, err := archPin()
	if err != nil {
		return "", err
	}
	dst, err := DLLPath()
	if err != nil {
		return "", err
	}
	if fileMatches(dst, pin.dllSHA256) {
		return dst, nil
	}
	dll, err := fetchDLL(ctx, pin)
	if err != nil {
		return "", err
	}
	if err := writeVerified(dst, dll, pin.dllSHA256); err != nil {
		return "", err
	}
	log.Printf("Installed %s", dst)
	return dst, nil
}

// LoadWireGuardDLL loads wireguard.dll from its install path. The WireGuard
// driver bindings then resolve the library by name to this loaded module.
func LoadWireGuardDLL(path string) error {
	_, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	return nil
}

var sevenZipSignature = []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}

// findSevenZip locates the app archive in the installer, trying the pinned
// offset before scanning the first 32 MiB.
func findSevenZip(r io.ReaderAt, hint int64) (int64, error) {
	sig := make([]byte, len(sevenZipSignature))
	if _, err := r.ReadAt(sig, hint); err == nil && bytes.Equal(sig, sevenZipSignature) {
		return hint, nil
	}
	const chunk = 1 << 20
	buf := make([]byte, chunk+len(sevenZipSignature))
	for off := int64(0); off < 32<<20; off += chunk {
		n, err := r.ReadAt(buf, off)
		if i := bytes.Index(buf[:n], sevenZipSignature); i >= 0 {
			return off + int64(i), nil
		}
		if err != nil {
			break
		}
	}
	return 0, errors.New("no 7z archive in installer")
}

// EnsureDriver installs the split tunnel driver file if it is missing or
// differs from the pinned build. It reads the driver out of the Mullvad
// installer with range requests, which fetches a few hundred KiB of it.
func EnsureDriver(ctx context.Context) (string, error) {
	pin, err := archPin()
	if err != nil {
		return "", err
	}
	dst, err := DriverPath()
	if err != nil {
		return "", err
	}
	if fileMatches(dst, pin.driverSHA256) {
		return dst, nil
	}
	log.Printf("Extracting %s from %s", DriverFile, pin.installerURL)
	sys, fetched, err := fetchDriver(ctx, pin)
	if err != nil {
		return "", err
	}
	if err := writeVerified(dst, sys, pin.driverSHA256); err != nil {
		return "", err
	}
	log.Printf("Installed %s (downloaded %d KiB of the installer)", dst, fetched>>10)
	return dst, nil
}

func fetchDLL(ctx context.Context, pin archPins) ([]byte, error) {
	log.Printf("Downloading %s", wgntURL)
	zipped, err := fetch.Bytes(ctx, wgntURL, wgntLimit)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(zipped); got != wgntSHA256 {
		return nil, fmt.Errorf("%s: SHA-256 %s, want %s", wgntURL, got, wgntSHA256)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if err != nil {
		return nil, err
	}
	member := "wireguard-nt/bin/" + pin.wgntDir + "/" + DLLName
	f, err := zr.Open(member)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", member, err)
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, wgntLimit))
}

// fetchDriver returns the driver file and the number of installer bytes downloaded.
func fetchDriver(ctx context.Context, pin archPins) ([]byte, int64, error) {
	rr, err := fetch.NewRangeReader(ctx, pin.installerURL)
	if err != nil {
		return nil, 0, err
	}
	start, err := findSevenZip(rr, pin.sevenZipOffset)
	if err != nil {
		return nil, 0, err
	}
	size := rr.Size() - start
	zr, err := sevenzip.NewReader(io.NewSectionReader(rr, start, size), size)
	if err != nil {
		return nil, 0, fmt.Errorf("read app archive: %w", err)
	}
	var sys []byte
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, `\`, "/")
		if !strings.EqualFold(path.Base(name), DriverFile) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, 0, err
		}
		sys, err = io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("extract %s: %w", name, err)
		}
		break
	}
	if sys == nil {
		return nil, 0, fmt.Errorf("%s not found in installer", DriverFile)
	}
	return sys, rr.Fetched, nil
}
