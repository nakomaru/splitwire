// Command sign makes the release key and signs release manifests. It runs
// from the repository root.
//
//	go run ./tools/sign keygen
//	go run ./tools/sign passphrase
//	go run ./tools/sign manifest <version> <dir>
//
// keygen writes a new private key to keys\release.key, protected by a
// passphrase it asks for, and prints its public key for internal/update's
// publicKeys. passphrase sets or changes the key's passphrase. manifest
// hashes splitwire-amd64.exe and splitwire-arm64.exe in dir and writes
// manifest.json and manifest.json.sig beside them, checking the signature
// against the public keys built into internal/update.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"splitwire/internal/update"
)

// keyPath holds the Ed25519 private key as an OpenSSH private key, which
// ssh-keygen also reads. It is never committed.
var keyPath = filepath.Join("keys", "release.key")

// keyComment names the key inside its file.
const keyComment = "splitwire release"

var archs = []string{"amd64", "arm64"}

func main() {
	log.SetFlags(0)
	var err error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "keygen":
		err = keygen()
	case len(os.Args) == 2 && os.Args[1] == "passphrase":
		err = passphrase()
	case len(os.Args) == 4 && os.Args[1] == "manifest":
		err = manifest(os.Args[2], os.Args[3])
	default:
		err = fmt.Errorf("usage: sign keygen | sign passphrase | sign manifest <version> <dir>")
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
	pass, err := askNewPassphrase()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := writeKey(priv, pass); err != nil {
		return err
	}
	fmt.Printf("Wrote %s. Its public key, for publicKeys in internal/update/update.go:\n%s\n",
		keyPath, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func passphrase() error {
	key, _, err := readKey()
	if err != nil {
		return err
	}
	pass, err := askNewPassphrase()
	if err != nil {
		return err
	}
	if err := writeKey(key, pass); err != nil {
		return err
	}
	fmt.Printf("Changed the passphrase of %s. Replace your backup of it with this file.\n", keyPath)
	return nil
}

func manifest(version, dir string) error {
	key, protected, err := readKey()
	if err != nil {
		return err
	}
	if !protected {
		fmt.Fprintf(os.Stderr, "Warning: %s has no passphrase; go run ./tools/sign passphrase sets one\n", keyPath)
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

// readKey reads the release key, asking for its passphrase when it has
// one, and reports whether it does.
func readKey() (ed25519.PrivateKey, bool, error) {
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, false, fmt.Errorf("%w; go run ./tools/sign keygen makes one", err)
	}
	k, err := ssh.ParseRawPrivateKey(b)
	var missing *ssh.PassphraseMissingError
	protected := errors.As(err, &missing)
	if protected {
		var pass []byte
		if pass, err = ask("Passphrase for " + keyPath + ": "); err != nil {
			return nil, false, err
		}
		k, err = ssh.ParseRawPrivateKeyWithPassphrase(b, pass)
	}
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", keyPath, err)
	}
	priv, ok := k.(*ed25519.PrivateKey)
	if !ok {
		return nil, false, fmt.Errorf("%s does not hold an Ed25519 key", keyPath)
	}
	return *priv, protected, nil
}

// writeKey replaces the key file with key, encrypted with pass.
func writeKey(key ed25519.PrivateKey, pass []byte) error {
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, keyComment, pass)
	if err != nil {
		return err
	}
	tmp := keyPath + ".new"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(block), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, keyPath)
}

// ask reads a line from the console without showing it.
func ask(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("the passphrase needs a console to type it in")
	}
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return pass, err
}

// askNewPassphrase asks for a passphrase twice, until both match.
func askNewPassphrase() ([]byte, error) {
	for {
		pass, err := ask("New passphrase: ")
		if err != nil {
			return nil, err
		}
		if len(pass) == 0 {
			fmt.Fprintln(os.Stderr, "The passphrase cannot be empty.")
			continue
		}
		again, err := ask("The same passphrase again: ")
		if err != nil {
			return nil, err
		}
		if string(pass) == string(again) {
			return pass, nil
		}
		fmt.Fprintln(os.Stderr, "The passphrases differ.")
	}
}
