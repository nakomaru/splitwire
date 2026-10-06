// Package update finds and downloads newer releases of splitwire from its
// GitHub releases. A release counts only when its manifest carries a
// signature by one of the release keys built into the executable, so
// control of the GitHub repository alone cannot publish an update.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"runtime"
	"strconv"
	"strings"

	"splitwire/internal/fetch"
)

// releasesURL is the GitHub releases of splitwire. Each release is tagged
// v<version> and holds the manifest, its signature and the executables.
const releasesURL = "https://github.com/nakomaru/splitwire/releases"

// Files of a release besides its executables.
const (
	ManifestFile  = "manifest.json"
	SignatureFile = ManifestFile + ".sig"
)

const manifestLimit = 64 << 10

// ErrNoRelease reports that no signed release is published.
var ErrNoRelease = errors.New("no signed release is published yet")

// publicKeys are the base64 Ed25519 public keys of the release keys. A
// manifest signed by any one of them counts.
var publicKeys = []string{
	"QYv1jxZVRffqn8jBRZkHHnzGfMc9cciHxxnbVey019o=",
}

// Manifest describes a release.
type Manifest struct {
	Version string
	// Files holds the executable for each architecture, by GOARCH.
	Files map[string]File
}

// File is a release executable.
type File struct {
	Name   string
	Size   int64
	SHA256 string
}

// Latest fetches and verifies the manifest of the newest release.
func Latest(ctx context.Context) (*Manifest, error) {
	base := releasesURL + "/latest/download/"
	manifest, err := fetch.Bytes(ctx, base+ManifestFile, manifestLimit)
	if errors.Is(err, fetch.ErrNotFound) {
		return nil, ErrNoRelease
	}
	if err != nil {
		return nil, err
	}
	sig, err := fetch.Bytes(ctx, base+SignatureFile, manifestLimit)
	if err != nil {
		return nil, err
	}
	return Verify(manifest, sig)
}

// Verify checks that sig is a release key's signature of manifest, and
// parses the manifest.
func Verify(manifest, sig []byte) (*Manifest, error) {
	keys, err := releaseKeys()
	if err != nil {
		return nil, err
	}
	return verify(manifest, sig, keys)
}

func verify(manifest, sig []byte, keys []ed25519.PublicKey) (*Manifest, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("the release signature is malformed")
	}
	signed := false
	for _, k := range keys {
		if ed25519.Verify(k, manifest, raw) {
			signed = true
			break
		}
	}
	if !signed {
		return nil, errors.New("the release manifest is not signed by a SplitWire release key")
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	if _, err := parseVersion(m.Version); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	return &m, nil
}

func releaseKeys() ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(publicKeys))
	for _, s := range publicKeys {
		k, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release key %q is not a base64 Ed25519 public key", s)
		}
		keys = append(keys, ed25519.PublicKey(k))
	}
	return keys, nil
}

// Sign signs manifest with a release key, in the form of SignatureFile.
func Sign(manifest []byte, key ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest)) + "\n")
}

// Download fetches the release's executable for this architecture and
// checks it against the manifest.
func (m *Manifest) Download(ctx context.Context) ([]byte, error) {
	f, ok := m.Files[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("release %s has no executable for %s", m.Version, runtime.GOARCH)
	}
	if f.Name == "" || path.Base(f.Name) != f.Name {
		return nil, fmt.Errorf("release %s names its executable %q", m.Version, f.Name)
	}
	u := releasesURL + "/download/v" + url.PathEscape(m.Version) + "/" + url.PathEscape(f.Name)
	b, err := fetch.Bytes(ctx, u, f.Size)
	if err != nil {
		return nil, err
	}
	if err := f.Check(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Check reports whether b is the file's content.
func (f File) Check(b []byte) error {
	if int64(len(b)) != f.Size {
		return fmt.Errorf("%s: %d bytes, want %d", f.Name, len(b), f.Size)
	}
	if got := SHA256(b); got != f.SHA256 {
		return fmt.Errorf("%s: SHA-256 %s, want %s", f.Name, got, f.SHA256)
	}
	return nil
}

// SHA256 is the hex SHA-256 of b, as File.SHA256 holds it.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Newer reports whether version a is later than version b. Versions are
// dotted numbers such as 0.4.1; one that does not parse is never newer.
func Newer(a, b string) bool {
	x, errA := parseVersion(a)
	y, errB := parseVersion(b)
	if errA != nil || errB != nil {
		return false
	}
	for i := 0; i < max(len(x), len(y)); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			return p > q
		}
	}
	return false
}

func parseVersion(v string) ([]int, error) {
	parts := strings.Split(v, ".")
	nums := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p != strconv.Itoa(n) {
			return nil, fmt.Errorf("version %q is not dotted numbers", v)
		}
		nums[i] = n
	}
	return nums, nil
}
