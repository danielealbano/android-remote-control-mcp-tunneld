package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// mintSelfCert produces a self-signed cert (PEM) + key (PEM) + CertInfo for host with the given NotAfter.
func mintSelfCert(t *testing.T, host string, notAfter time.Time) (certPEM, keyPEM []byte, info store.CertInfo) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: notAfter.Add(-160 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	info = store.CertInfo{CA: "letsencrypt", Serial: "1", NotBefore: tmpl.NotBefore, NotAfter: notAfter}
	return certPEM, keyPEM, info
}

// countingIssuer is a selfIssuer that records calls and returns a canned cert or error.
type countingIssuer struct {
	mu      sync.Mutex
	calls   int
	certPEM []byte
	keyPEM  []byte
	info    store.CertInfo
	err     error
}

func (c *countingIssuer) obtain(context.Context, string) ([]byte, []byte, store.CertInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.certPEM, c.keyPEM, c.info, c.err
}

func (c *countingIssuer) callCount() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }

func neverRenew(context.Context, store.CertInfo) (bool, time.Time, error) {
	return false, time.Time{}, nil
}

// seedCache writes a persisted cert/key/meta triple under dir/self/<host>/.
func seedCache(t *testing.T, dir, host string, certPEM, keyPEM []byte, info store.CertInfo) {
	t.Helper()
	hd := filepath.Join(dir, "self", host)
	if err := os.MkdirAll(hd, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(info)
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM, "meta.json": meta} {
		if err := os.WriteFile(filepath.Join(hd, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReservedCerts_CacheReused(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour)) // well past the margin
	seedCache(t, dir, host, certPEM, keyPEM, info)

	iss := &countingIssuer{}
	rc := newReservedCerts(context.Background(), dir, []string{host}, iss.obtain, neverRenew, 48*time.Hour, testLogger())

	if iss.callCount() != 0 {
		t.Fatalf("a valid cached pair must NOT trigger ObtainSelf, got %d calls", iss.callCount())
	}
	if _, err := rc.getCertificateFor(host)(nil); err != nil {
		t.Fatalf("cached cert must be served, got %v", err)
	}
}

func TestReservedCerts_ObtainsWhenNoCache(t *testing.T) {
	dir := t.TempDir()
	host := "connect.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}

	rc := newReservedCerts(context.Background(), dir, []string{host}, iss.obtain, neverRenew, 48*time.Hour, testLogger())

	if iss.callCount() != 1 {
		t.Fatalf("no cache must trigger exactly one ObtainSelf, got %d", iss.callCount())
	}
	if _, err := rc.getCertificateFor(host)(nil); err != nil {
		t.Fatalf("obtained cert must be served, got %v", err)
	}
	// It must have been persisted for reuse across restarts.
	if _, err := os.Stat(filepath.Join(dir, "self", host, "cert.pem")); err != nil {
		t.Fatalf("obtained cert must be persisted: %v", err)
	}
}

func TestReservedCerts_DegradedWhenNoCAAndNoCache(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	iss := &countingIssuer{err: context.DeadlineExceeded} // no CA can issue

	rc := newReservedCerts(context.Background(), dir, []string{host}, iss.obtain, neverRenew, 48*time.Hour, testLogger())

	if _, err := rc.getCertificateFor(host)(nil); err == nil {
		t.Fatal("with no CA and no cache the reserved host must be degraded (TLS refused)")
	}
}

func TestReservedCerts_RenewsExpiringCache(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	// Cached pair is still valid but inside the renew margin → must be renewed at startup.
	oldCert, oldKey, oldInfo := mintSelfCert(t, host, time.Now().Add(10*time.Hour))
	seedCache(t, dir, host, oldCert, oldKey, oldInfo)
	newCert, newKey, newInfo := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	iss := &countingIssuer{certPEM: newCert, keyPEM: newKey, info: newInfo}

	_ = newReservedCerts(context.Background(), dir, []string{host}, iss.obtain, neverRenew, 48*time.Hour, testLogger())

	if iss.callCount() != 1 {
		t.Fatalf("an expiring cached pair must be renewed once at startup, got %d", iss.callCount())
	}
	// The persisted meta must reflect the renewed (far-future) NotAfter.
	metaRaw, err := os.ReadFile(filepath.Join(dir, "self", host, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got store.CertInfo
	_ = json.Unmarshal(metaRaw, &got)
	if !got.NotAfter.After(oldInfo.NotAfter) {
		t.Fatalf("renewed cert must be re-persisted with a later NotAfter (old=%v new=%v)", oldInfo.NotAfter, got.NotAfter)
	}
}
