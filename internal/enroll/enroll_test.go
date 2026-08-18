package enroll

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// --- test doubles ---

type fakeVerifier struct {
	key crypto.PublicKey
	err error
}

func (f fakeVerifier) Verify(_ []*x509.Certificate, _ []byte, _ time.Time) (attest.Result, error) {
	if f.err != nil {
		return attest.Result{}, f.err
	}
	return attest.Result{LeafPublicKey: f.key, Package: "dev.example.app"}, nil
}

type fakeIssuer struct {
	obtainErr error
	ca        string
}

func (f fakeIssuer) Obtain(_ context.Context, _ *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	if f.obtainErr != nil {
		return nil, store.CertInfo{}, f.obtainErr
	}
	return []byte("PUBLIC-CERT-PEM"), store.CertInfo{CA: f.ca, Serial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(160 * time.Hour)}, nil
}

func (f fakeIssuer) Renew(_ context.Context, _ *x509.CertificateRequest, name string, _ store.CertInfo) ([]byte, store.CertInfo, error) {
	return f.Obtain(context.Background(), nil, name)
}

type rateLimitedErr struct{}

func (rateLimitedErr) Error() string             { return "rate limited" }
func (rateLimitedErr) IssuerClass() string       { return "rate-limited" }
func (rateLimitedErr) RetryAfter() time.Duration { return time.Hour }

// --- helpers ---

func testCA(t *testing.T) *ca.CA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "Test Internal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(100 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	keyDER, _ := x509.MarshalECPrivateKey(key)
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	c, err := ca.Load(certPath, keyPath, 4380*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newCSR(t *testing.T) (*x509.CertificateRequest, crypto.PublicKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "whatever"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	return csr, &key.PublicKey
}

func newService(t *testing.T, cfg Config) (*Service, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cfg.RDB = rdb
	cfg.Limiter = limit.NewLimiter(rdb, 125000, 1<<40, 1<<40)
	if cfg.NameLength == 0 {
		cfg.NameLength = 10
	}
	if cfg.IssuePerWeek == 0 {
		cfg.IssuePerWeek = 3
	}
	if cfg.EnrollHour == 0 {
		cfg.EnrollHour = 20
	}
	if cfg.EnrollMinute == 0 {
		cfg.EnrollMinute = 2
	}
	if cfg.ClaimTimeout == 0 {
		cfg.ClaimTimeout = 3 * time.Second
	}
	if cfg.ClaimSettle == 0 {
		cfg.ClaimSettle = 5 * time.Second
	}
	svc := NewService(cfg)
	svc.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	return svc, mr
}

// mintNonce inserts a valid nonce and returns it.
func mintNonce(t *testing.T, svc *Service) []byte {
	t.Helper()
	n, err := svc.Nonce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEnrollHappyPath(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	tlsCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: fakeIssuer{ca: "letsencrypt"},
	})
	nonce := mintNonce(t, svc)
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{
		Nonce: nonce, IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	if res.Name == "" || res.CA != "letsencrypt" || len(res.IdentityCert) == 0 || len(res.PublicCert) == 0 {
		t.Errorf("bad result: %+v", res)
	}
	// The claimed name has a durable record carrying the identity fingerprint.
	rec, err := st.GetName(context.Background(), res.Name)
	if err != nil || rec.IdentityKeyFP == "" || rec.CA != "letsencrypt" {
		t.Errorf("record missing/incomplete: %+v %v", rec, err)
	}
}

func TestEnrollAttestationRejectRecordsEvidence(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, _ := newCSR(t)
	tlsCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{err: attest.ErrSignerNotAllowed}, Issuer: fakeIssuer{},
	})
	nonce := mintNonce(t, svc)
	_, ee := svc.Enroll(context.Background(), "9.9.9.9", Request{Nonce: nonce, IdentityCSR: idCSR, TLSCSR: tlsCSR})
	if ee == nil || ee.Reason != "unauthorized" {
		t.Fatalf("expected unauthorized, got %v", ee)
	}
	if len(st.Rejected) != 1 || st.Rejected[0].Reason != "attest-signer" {
		t.Errorf("evidence not captured with the typed reason: %+v", st.Rejected)
	}
}

func TestEnrollKeyBindingMismatch(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, _ := newCSR(t)
	tlsCSR, _ := newCSR(t)
	_, otherPub := newCSR(t) // attested key differs from the identity CSR key
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: otherPub}, Issuer: fakeIssuer{},
	})
	nonce := mintNonce(t, svc)
	_, ee := svc.Enroll(context.Background(), "1.1.1.1", Request{Nonce: nonce, IdentityCSR: idCSR, TLSCSR: tlsCSR})
	if ee == nil || ee.Reason != "unauthorized" {
		t.Fatalf("mismatched identity key should be unauthorized, got %v", ee)
	}
	if len(st.Rejected) != 1 || st.Rejected[0].Reason != "csr-mismatch" {
		t.Errorf("expected csr-mismatch evidence, got %+v", st.Rejected)
	}
}

func TestEnrollAcmeFailureRollsBack(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	tlsCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: fakeIssuer{obtainErr: rateLimitedErr{}},
	})
	nonce := mintNonce(t, svc)
	_, ee := svc.Enroll(context.Background(), "2.2.2.2", Request{Nonce: nonce, IdentityCSR: idCSR, TLSCSR: tlsCSR})
	if ee == nil || ee.Reason != "acme_rate_limited" || !ee.Retryable {
		t.Fatalf("expected retryable acme_rate_limited, got %v", ee)
	}
	// The claimed name was rolled back (no orphaned record) — the fake captured a Put then a Delete.
	if len(st.ConnLogs) != 0 {
		t.Error("no conn logs expected")
	}
}

func TestClaimZombiePutLoserRedraws(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	tlsCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: fakeIssuer{ca: "gts"},
	})
	// A competitor's record + nonce lands between our PUT and our verify GET, so our verify sees a
	// different nonce → we redraw and still succeed with a different name.
	var injected bool
	st.BeforeVerifyGet = func(name string) {
		if injected {
			return
		}
		injected = true
		_ = st.PutName(context.Background(), name, store.NameRecord{Schema: 1, ClaimNonce: "competitor-nonce"})
	}
	nonce := mintNonce(t, svc)
	res, ee := svc.Enroll(context.Background(), "3.3.3.3", Request{Nonce: nonce, IdentityCSR: idCSR, TLSCSR: tlsCSR})
	if ee != nil {
		t.Fatalf("should redraw and succeed: %v", ee)
	}
	if res.Name == "" {
		t.Error("expected a claimed name after redraw")
	}
}

func TestEnrollInvalidNonce(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	tlsCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: fakeIssuer{ca: "letsencrypt"},
	})
	_, ee := svc.Enroll(context.Background(), "4.4.4.4", Request{Nonce: []byte("never-issued"), IdentityCSR: idCSR, TLSCSR: tlsCSR})
	if ee == nil || ee.Reason != "invalid_nonce" {
		t.Fatalf("expected invalid_nonce, got %v", ee)
	}
}

func TestFirstLabel(t *testing.T) {
	for in, want := range map[string]string{
		"enroll.example.test":      "enroll",
		"connect.example.test:443": "connect",
		"HOST":                     "host",
	} {
		if got := firstLabel(in); got != want {
			t.Errorf("firstLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func bigOne() *big.Int { return big.NewInt(1) }
