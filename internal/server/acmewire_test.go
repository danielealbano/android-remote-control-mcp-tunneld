package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
)

func TestLoadAccountKey_AbsentGenerates(t *testing.T) {
	dir := t.TempDir()
	key, err := loadAccountKey(dir, acme.CALetsEncrypt, testLogger())
	if err != nil {
		t.Fatalf("absent key must generate, got err: %v", err)
	}
	if key == nil {
		t.Fatal("generated key must be non-nil")
	}
	fi, serr := os.Stat(filepath.Join(dir, acme.CALetsEncrypt+".key"))
	if serr != nil {
		t.Fatalf("key must be persisted: %v", serr)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perm = %v, want 0600", fi.Mode().Perm())
	}
}

func TestLoadAccountKey_SEC1RoundTrip(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadAccountKey(dir, acme.CAGTS, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadAccountKey(dir, acme.CAGTS, testLogger())
	if err != nil {
		t.Fatalf("reload of a SEC1 key must succeed: %v", err)
	}
	if !k1.(*ecdsa.PrivateKey).Equal(k2) {
		t.Error("reloaded key must equal the persisted key")
	}
}

func TestLoadAccountKey_PKCS8Accepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, acme.CAZeroSSL+".key")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	key, err := loadAccountKey(dir, acme.CAZeroSSL, testLogger())
	if err != nil {
		t.Fatalf("a PKCS#8 EC key must load: %v", err)
	}
	if !priv.Equal(key) {
		t.Error("loaded PKCS#8 key must equal the written key")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("a valid existing key must NOT be overwritten")
	}
}

func TestLoadAccountKey_UnparseableIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, acme.CALetsEncrypt+".key")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	junk := []byte("this is not a key")
	if err := os.WriteFile(path, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAccountKey(dir, acme.CALetsEncrypt, testLogger()); err == nil {
		t.Fatal("an unparseable existing key must be fatal")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(junk) {
		t.Error("an unparseable existing key must be left untouched (never overwritten)")
	}
}

func TestBuildACMEChain_CorruptAccountKeyAborts(t *testing.T) {
	dir := t.TempDir()
	accounts := filepath.Join(dir, "accounts")
	if err := os.MkdirAll(accounts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accounts, acme.CALetsEncrypt+".key"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ServeCmd{ACMEAccountDir: dir}
	if _, err := buildACMEChain(cfg, nil, nil, testLogger()); err == nil {
		t.Fatal("a corrupt existing account key must abort buildACMEChain")
	}
}
