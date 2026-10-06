// Command sign makes the release key and signs release manifests. It runs
// from the repository root.
//
//	go run ./tools/sign keygen
//	go run ./tools/sign manifest <version> <dir>
//
// keygen writes a new private key to keys\release.key and prints its
// public key for internal/update's publicKeys. manifest hashes
// splitwire-amd64.exe and splitwire-arm64.exe in dir and writes
// manifest.json and manifest.json.sig beside them, checking the signature
// against the public keys built into internal/update.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"splitwire/internal/update"
)

// keyPath holds the base64 Ed25519 private key. It is never committed.
var keyPath = filepath.Join("keys", "release.key")

var archs = []string{"amd64", "arm64"}

func main() {
	log.SetFlags(0)
	var err error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "keygen":
		err = keygen()
	case len(os.Args) == 4 && os.Args[1] == "manifest":
		err = manifest(os.Args[2], os.Args[3])
	default:
		err = fmt.Errorf("usage: sign keygen | sign manifest <version> <dir>")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func keygen() error {
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s exists; move it away first to make a new key", keyPath)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s. Its public key, for publicKeys in internal/update/update.go:\n%s\n",
		keyPath, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func manifest(version, dir string) error {
	key, err := readKey()
	if err != nil {
		return err
	}
	m := update.Manifest{Version: version, Files: make(map[string]update.File)}
	for _, arch := range archs {
		name := "splitwire-" + arch + ".exe"
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		m.Files[arch] = update.File{Name: name, Size: int64(len(b)), SHA256: update.SHA256(b)}
	}
	data, err := json.MarshalIndent(m, "", "\t")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	sig := update.Sign(data, key)
	if _, err := update.Verify(data, sig); err != nil {
		return fmt.Errorf("%v; is the public key of %s in internal/update?", err, keyPath)
	}
	if err := os.WriteFile(filepath.Join(dir, update.ManifestFile), data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, update.SignatureFile), sig, 0o644); err != nil {
		return err
	}
	fmt.Printf("Signed %s for version %s\n", filepath.Join(dir, update.ManifestFile), version)
	return nil
}

func readKey() (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w; go run ./tools/sign keygen makes one", err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s does not hold a base64 Ed25519 private key", keyPath)
	}
	return ed25519.PrivateKey(k), nil
}
