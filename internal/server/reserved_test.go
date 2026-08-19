package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestReservedMaybeRenew_LogsShouldRenewError verifies a shouldRenew error is logged (not silently
// swallowed) so a stalled reserved-host renewal is diagnosable before the cert expires.
func TestReservedMaybeRenew_LogsShouldRenewError(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	iss := &countingIssuer{certPEM: certPEM, keyPEM: keyPEM, info: info}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	failRenew := func(context.Context, store.CertInfo) (bool, time.Time, error) {
		return false, time.Time{}, errors.New("cooldown state unavailable")
	}
	rc := newReservedCerts(context.Background(), dir, []string{host}, iss.obtain, failRenew, 48*time.Hour, logger)
	rc.maybeRenew(context.Background(), rc.hosts[host])
	if !strings.Contains(buf.String(), "renewal check failed") {
		t.Fatalf("a shouldRenew error must be logged at Warn; log = %q", buf.String())
	}
}

// TestReservedEnsure_UsesInjectedClock verifies the renew-margin branch compares against the injected
// clock (rc.now), not the wall clock: a cache valid by the wall clock but inside the margin by the
// injected clock must trigger a renewal.
func TestReservedEnsure_UsesInjectedClock(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	realNow := time.Now()
	cachedCert, cachedKey, cachedInfo := mintSelfCert(t, host, realNow.Add(100*time.Hour))
	seedCache(t, dir, host, cachedCert, cachedKey, cachedInfo)
	newCert, newKey, newInfo := mintSelfCert(t, host, realNow.Add(400*time.Hour))
	iss := &countingIssuer{certPEM: newCert, keyPEM: newKey, info: newInfo}

	fakeNow := realNow.Add(60 * time.Hour) // cache NotAfter=+100h is now inside the 48h margin
	rc := &reservedCerts{
		dir: filepath.Join(dir, "self"), obtain: iss.obtain, shouldRenew: neverRenew,
		renewMargin: 48 * time.Hour, logger: testLogger(),
		now:   func() time.Time { return fakeNow },
		hosts: map[string]*reservedHost{},
	}
	rh := &reservedHost{host: host}
	rc.hosts[host] = rh
	rc.ensure(context.Background(), rh)

	if iss.callCount() != 1 {
		t.Fatalf("the margin branch must use the injected clock (renew → 1 obtain), got %d", iss.callCount())
	}
}

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
	// It must have been persisted for reuse across restarts (atomic single-file bundle).
	if _, err := os.Stat(filepath.Join(dir, "self", host, "bundle.json")); err != nil {
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
	// The persisted bundle must reflect the renewed (far-future) NotAfter.
	raw, err := os.ReadFile(filepath.Join(dir, "self", host, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got certBundle
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Info.NotAfter.After(oldInfo.NotAfter) {
		t.Fatalf("renewed cert must be re-persisted with a later NotAfter (old=%v new=%v)", oldInfo.NotAfter, got.Info.NotAfter)
	}
}

func TestReservedCerts_PersistAtomicBundle(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	rc := &reservedCerts{dir: filepath.Join(dir, "self"), logger: testLogger(), now: time.Now}

	rc.persist(host, certPEM, keyPEM, info)

	hd := filepath.Join(dir, "self", host)
	if _, err := os.Stat(filepath.Join(hd, "bundle.json")); err != nil {
		t.Fatalf("persist must write bundle.json via rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hd, "bundle.json.tmp")); !os.IsNotExist(err) {
		t.Fatalf("the temp file must not survive a successful persist (err=%v)", err)
	}
	cert, gotInfo, ok := rc.loadCached(host)
	if !ok || cert == nil {
		t.Fatal("the persisted bundle must load back")
	}
	if !gotInfo.NotAfter.Equal(info.NotAfter) {
		t.Fatalf("loaded NotAfter mismatch: got %v want %v", gotInfo.NotAfter, info.NotAfter)
	}
}

func TestReservedCerts_LoadLegacyTriple(t *testing.T) {
	dir := t.TempDir()
	host := "connect.example.test"
	certPEM, keyPEM, info := mintSelfCert(t, host, time.Now().Add(400*time.Hour))
	seedCache(t, dir, host, certPEM, keyPEM, info) // pre-bundle cert.pem/key.pem/meta.json triple
	rc := &reservedCerts{dir: filepath.Join(dir, "self"), logger: testLogger(), now: time.Now}

	cert, gotInfo, ok := rc.loadCached(host)
	if !ok || cert == nil {
		t.Fatal("a legacy cert.pem/key.pem/meta.json triple must still load")
	}
	if gotInfo.NotAfter.IsZero() {
		t.Fatal("legacy load must recover NotAfter")
	}
}

func TestReservedCerts_CorruptBundleTreatedAbsent(t *testing.T) {
	dir := t.TempDir()
	host := "enroll.example.test"
	hd := filepath.Join(dir, "self", host)
	if err := os.MkdirAll(hd, 0o700); err != nil {
		t.Fatal(err)
	}
	// A truncated bundle.json with no legacy fallback must report absent, never crash.
	if err := os.WriteFile(filepath.Join(hd, "bundle.json"), []byte(`{"cert_pem":"---BEGIN`), 0o600); err != nil {
		t.Fatal(err)
	}
	rc := &reservedCerts{dir: filepath.Join(dir, "self"), logger: testLogger(), now: time.Now}

	if _, _, ok := rc.loadCached(host); ok {
		t.Fatal("a corrupt bundle.json with no legacy fallback must report absent")
	}
}
