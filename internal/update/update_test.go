package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestReleaseKeysDecode(t *testing.T) {
	keys, err := releaseKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("no release keys")
	}
}

func TestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"Version":"0.4.1","Files":{"amd64":{"Name":"splitwire-amd64.exe","Size":3,"SHA256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}}`)
	sig := Sign(manifest, priv)

	m, err := verify(manifest, sig, []ed25519.PublicKey{other, pub})
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.4.1" || m.Files["amd64"].Name != "splitwire-amd64.exe" {
		t.Fatalf("parsed %+v", m)
	}
	if err := m.Files["amd64"].Check([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := m.Files["amd64"].Check([]byte("abd")); err == nil {
		t.Fatal("Check accepted other content")
	}

	if _, err := verify(manifest, sig, []ed25519.PublicKey{other}); err == nil {
		t.Fatal("verified with the wrong key")
	}
	tampered := []byte(strings.Replace(string(manifest), "0.4.1", "0.4.9", 1))
	if _, err := verify(tampered, sig, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("verified a changed manifest")
	}
	if _, err := verify(manifest, []byte("not base64"), []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("verified a malformed signature")
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.4.1", "0.4.0", true},
		{"0.4.0", "0.4.1", false},
		{"0.4.0", "0.4.0", false},
		{"0.10.0", "0.9.9", true},
		{"0.4.0.1", "0.4.0", true},
		{"0.4", "0.4.0", false},
		{"1.0.0", "0.99.99", true},
		{"0.4.x", "0.4.0", false},
		{"0.4.01", "0.4.0", false},
		{"", "0.4.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
