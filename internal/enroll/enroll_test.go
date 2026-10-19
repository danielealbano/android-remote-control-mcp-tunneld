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
	"errors"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
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
	obtains   int
	renews    int
	lastCur   store.CertInfo // the cur passed to the last Renew
}

func (f *fakeIssuer) Obtain(_ context.Context, _ *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	f.obtains++
	if f.obtainErr != nil {
		return nil, store.CertInfo{}, f.obtainErr
	}
	return []byte("PUBLIC-CERT-PEM"), store.CertInfo{CA: f.ca, Serial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(160 * time.Hour)}, nil
}

func (f *fakeIssuer) Renew(_ context.Context, _ *x509.CertificateRequest, name string, cur store.CertInfo) ([]byte, store.CertInfo, error) {
	f.renews++
	f.lastCur = cur
	if f.obtainErr != nil {
		return nil, store.CertInfo{}, f.obtainErr
	}
	return []byte("PUBLIC-CERT-PEM"), store.CertInfo{CA: f.ca, Serial: "02", NotBefore: time.Now(), NotAfter: time.Now().Add(160 * time.Hour)}, nil
}

type rateLimitedErr struct{}

func (rateLimitedErr) Error() string             { return "rate limited" }
func (rateLimitedErr) IssuerClass() string       { return "rate-limited" }
func (rateLimitedErr) RetryAfter() time.Duration { return time.Hour }

// --- helpers ---

func testCA(t *testing.T) *ca.CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "Test Internal CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(100 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := ca.Load(certPath, keyPath, 4380*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newCSR(t *testing.T) (*x509.CertificateRequest, crypto.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "whatever"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr, &key.PublicKey
}

func newService(t *testing.T, cfg Config) (*Service, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	cfg.RDB = rdb
	cfg.Limiter = limit.NewLimiter(rdb, 125000, 1<<40, 1<<40, time.Hour)
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

// doEnroll runs Phase 1 (identity enrollment) and returns the assigned name.
func doEnroll(t *testing.T, svc *Service, idCSR *x509.CertificateRequest) string {
	t.Helper()
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee != nil {
		t.Fatalf("enroll (phase 1) failed: %v", ee)
	}
	return res.Name
}

// newTLSCSR builds a public-cert CSR requesting exactly fqdn (CN + SAN).
func newTLSCSR(t *testing.T, fqdn string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{fqdn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestEnrollHappyPath covers Phase 1: attestation + name claim + bootstrap identity cert, with NO public
// cert yet (the record carries the identity fingerprint but no cert info).
func TestEnrollHappyPath(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	if res.Name == "" || len(res.IdentityCert) == 0 || len(res.PublicCert) != 0 {
		t.Errorf("phase 1 must return name + identity cert and NO public cert: %+v", res)
	}
	rec, err := st.GetName(context.Background(), res.Name)
	if err != nil || rec.IdentityKeyFP == "" || rec.CA != "" {
		t.Errorf("phase-1 record must carry the identity fingerprint and NO cert: %+v %v", rec, err)
	}
}

// TestIssueHappyPath covers Phase 2: an enrolled tunnel obtains its public cert (regenerating the
// identity cert too) for <name>.<tunnel-domain>; the record then carries the issued cert.
func TestIssueHappyPath(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	name := doEnroll(t, svc, idCSR)
	tlsCSR := newTLSCSR(t, name+".example.test")
	res, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if ee != nil {
		t.Fatalf("issue failed: %v", ee)
	}
	if res.CA != "letsencrypt" || len(res.IdentityCert) == 0 || len(res.PublicCert) == 0 {
		t.Errorf("issue must regenerate identity + public certs: %+v", res)
	}
	rec, err := st.GetName(context.Background(), name)
	if err != nil || rec.CA != "letsencrypt" || rec.Cert.Serial == "" {
		t.Errorf("record must carry the issued cert: %+v %v", rec, err)
	}
}

// TestIssueRejectsWrongDomain covers the server-dictated public identity: a TLS CSR that does not request
// <name>.<tunnel-domain> is refused.
func TestIssueRejectsWrongDomain(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	name := doEnroll(t, svc, idCSR)
	tlsCSR := newTLSCSR(t, "attacker.example.test") // wrong name
	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if ee == nil || ee.Reason != "csr_domain_mismatch" {
		t.Fatalf("expected csr_domain_mismatch, got %v", ee)
	}
}

func TestEnrollAttestationRejectRecordsEvidence(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{err: attest.ErrSignerNotAllowed}, Issuer: &fakeIssuer{},
	})
	nonce := mintNonce(t, svc)
	_, ee := svc.Enroll(context.Background(), "9.9.9.9", Request{Nonce: nonce, IdentityCSR: idCSR})
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
	_, otherPub := newCSR(t) // attested key differs from the identity CSR key
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: otherPub}, Issuer: &fakeIssuer{},
	})
	nonce := mintNonce(t, svc)
	_, ee := svc.Enroll(context.Background(), "1.1.1.1", Request{Nonce: nonce, IdentityCSR: idCSR})
	if ee == nil || ee.Reason != "unauthorized" {
		t.Fatalf("mismatched identity key should be unauthorized, got %v", ee)
	}
	if len(st.Rejected) != 1 || st.Rejected[0].Reason != "csr-mismatch" {
		t.Errorf("expected csr-mismatch evidence, got %+v", st.Rejected)
	}
}

// TestIssueAcmeFailure covers a rate-limited public-cert issuance at Phase 2: it surfaces a retryable
// acme_rate_limited error and the enrolled name record persists (Phase 2 is retryable — never rolled back).
func TestIssueAcmeFailure(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{obtainErr: rateLimitedErr{}},
	})
	name := doEnroll(t, svc, idCSR)
	tlsCSR := newTLSCSR(t, name+".example.test")
	_, ee := svc.Issue(context.Background(), name, "2.2.2.2", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if ee == nil || ee.Reason != "acme_rate_limited" || !ee.Retryable {
		t.Fatalf("expected retryable acme_rate_limited, got %v", ee)
	}
	if _, err := st.GetName(context.Background(), name); err != nil {
		t.Errorf("the enrolled name must persist after a retryable issuance failure: %v", err)
	}
}

func TestEnrollInvalidNonce(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	_, ee := svc.Enroll(context.Background(), "4.4.4.4", Request{Nonce: []byte("never-issued"), IdentityCSR: idCSR})
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

func TestAttestReason_MatchesObservAttestResults(t *testing.T) {
	errs := []error{
		attest.ErrChainUntrusted, attest.ErrChallengeMismatch, attest.ErrSignerNotAllowed, attest.ErrSecurityLevel,
		attest.ErrBootState, attest.ErrDeviceUnlocked, attest.ErrRevoked, attest.ErrStatusStale, errors.New("other"),
	}
	got := map[string]bool{"ok": true}
	for _, err := range errs {
		got[attestReason(err)] = true
	}
	want := map[string]bool{}
	for _, r := range observ.AttestResults {
		want[r] = true
	}
	if !maps.Equal(got, want) {
		t.Fatalf("attest results = %v, observ.AttestResults = %v", got, want)
	}
}

type recordingNames struct {
	*tunneltest.Store
	mu   sync.Mutex
	puts []store.NameRecord
}

func (c *recordingNames) PutName(ctx context.Context, name string, rec store.NameRecord) error {
	c.mu.Lock()
	c.puts = append(c.puts, rec)
	c.mu.Unlock()
	return c.Store.PutName(ctx, name, rec)
}

func TestEnroll_SingleRegistryWriteCarriesTheFullRecord(t *testing.T) {
	t.Parallel()
	names := &recordingNames{Store: tunneltest.NewStore()}
	idCSR, idPub := newCSR(t)
	dev := store.DeviceInfo{OSVersion: 150000, OSPatch: 202609, SecurityLevel: "TrustedEnvironment"}
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: names, Evidence: names.Store, TunnelDomain: "example.test",
		Verifier: devVerifier{fakeVerifier: fakeVerifier{key: idPub}, dev: dev}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	wantFP, err := keyFingerprint(idPub)
	if err != nil {
		t.Fatal(err)
	}
	names.mu.Lock()
	defer names.mu.Unlock()
	if len(names.puts) != 1 {
		t.Fatalf("enrollment must write the registry once (the claim), got %d writes", len(names.puts))
	}
	got := names.puts[0]
	if got.IdentityKeyFP != wantFP || got.Device != dev || got.Schema != 1 || got.EnrolledAt.IsZero() {
		t.Errorf("the claim write must carry the full Phase-1 record: %+v", got)
	}
	rec, err := names.GetName(context.Background(), res.Name)
	if err != nil || rec != got {
		t.Errorf("stored record = %+v (err %v), want the claim write %+v", rec, err, got)
	}
}
