package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// devVerifier is a fakeVerifier that also returns device scalars.
type devVerifier struct {
	fakeVerifier
	dev store.DeviceInfo
}

func (d devVerifier) Verify(chain []*x509.Certificate, nonce []byte, now time.Time) (attest.Result, error) {
	res, err := d.fakeVerifier.Verify(chain, nonce, now)
	if err != nil {
		return res, err
	}
	res.Device = d.dev
	return res, nil
}

// TestEnrollRecordsDeviceScalars: the attested device scalars land in the phase-1 registry record and
// are refreshed by Issue.
func TestEnrollRecordsDeviceScalars(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	dev := store.DeviceInfo{OSVersion: 160000, OSPatch: 202601, SecurityLevel: "tee", AttestationVersion: 300}
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: devVerifier{fakeVerifier: fakeVerifier{key: idPub}, dev: dev}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	name := doEnroll(t, svc, idCSR)
	rec, err := st.GetName(context.Background(), name)
	if err != nil || rec.Device != dev {
		t.Fatalf("phase-1 record must carry the attested device scalars, got %+v (%v)", rec.Device, err)
	}

	tlsCSR := newTLSCSR(t, name+".example.test")
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	}); ee != nil {
		t.Fatalf("issue failed: %v", ee)
	}
	got, err := st.GetName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	rec = got
	if rec.Device != dev {
		t.Fatalf("issue must keep the freshly-attested device scalars, got %+v", rec.Device)
	}
}

// TestEnrollUnsupportedKeyType: a non-P256 identity CSR maps to the documented unsupported_key_type
// reason, and the freshly claimed name is rolled back.
func TestEnrollUnsupportedKeyType(t *testing.T) {
	st := tunneltest.NewStore()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: rsaKey.Public()}, Issuer: &fakeIssuer{},
	})
	_, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: rsaCSR})
	if ee == nil || ee.Reason != "unsupported_key_type" {
		t.Fatalf("expected unsupported_key_type, got %v", ee)
	}
	if n := st.NameCount(); n != 0 {
		t.Fatalf("the claimed name must be rolled back on a sign failure, %d records remain", n)
	}
}

// TestIssueReject_CarriesTunnelName verifies an Issue-path csr-mismatch reject records the mTLS-CN name
// (ARCHITECTURE §8 dedup key), unlike the Phase-1 path which has no name yet.
func TestIssueReject_CarriesTunnelName(t *testing.T) {
	st := tunneltest.NewStore()
	rec := &tunneltest.Recorder{}
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"}, Recorder: rec,
	})
	name := doEnroll(t, svc, idCSR)
	wrong := newTLSCSR(t, "someone-else.example.test") // wrong domain → csr-mismatch
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: wrong}); ee == nil {
		t.Fatal("a wrong-domain TLS CSR must be rejected")
	}
	found := false
	for _, c := range rec.Calls {
		if c.Kind == "reject" && c.Reason == "csr-mismatch" && c.Tunnel == name {
			found = true
		}
	}
	if !found {
		t.Fatalf("the Issue-path csr-mismatch reject must carry the tunnel name %q; calls=%+v", name, rec.Calls)
	}
}

// TestIssue_RejectsNonP256TLSCSR verifies a non-P256 TLS CSR (correct domain, valid signature) is refused
// unsupported_key_type with a csr-mismatch metric; the identity CSR path is unchanged.
func TestIssue_RejectsNonP256TLSCSR(t *testing.T) {
	st := tunneltest.NewStore()
	rec := &tunneltest.Recorder{}
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"}, Recorder: rec,
	})
	name := doEnroll(t, svc, idCSR)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fqdn := name + ".example.test"
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{fqdn}}, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: rsaCSR})
	if ee == nil || ee.Reason != "unsupported_key_type" {
		t.Fatalf("a non-P256 TLS CSR must be refused unsupported_key_type, got %v", ee)
	}
	if rec.Count("reject", "csr-mismatch") == 0 {
		t.Fatal("the non-P256 rejection must record a csr-mismatch metric")
	}
}

// TestIssue_NonceConsumedOnFailure verifies a FAILED Issue still consumes its nonce (a replay is refused
// invalid_nonce) — the documented retry path requires a fresh nonce.
func TestIssue_NonceConsumedOnFailure(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	name := doEnroll(t, svc, idCSR)
	nonce := mintNonce(t, svc)
	wrong := newTLSCSR(t, "elsewhere.example.test") // rejected AFTER the nonce is consumed
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{Nonce: nonce, IdentityCSR: idCSR, TLSCSR: wrong}); ee == nil {
		t.Fatal("the failing Issue must return an error")
	}
	tls2 := newTLSCSR(t, name+".example.test")
	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{Nonce: nonce, IdentityCSR: idCSR, TLSCSR: tls2})
	if ee == nil || ee.Reason != "invalid_nonce" {
		t.Fatalf("replaying a consumed nonce must be invalid_nonce, got %v", ee)
	}
}

// TestConsumeNonce_ValkeyErrorIsInternal verifies a control-plane error during nonce consumption yields
// internal (retryable), NOT invalid_nonce.
func TestConsumeNonce_ValkeyErrorIsInternal(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, mr := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	name := doEnroll(t, svc, idCSR)
	nonce := mintNonce(t, svc)
	mr.Close() // Valkey down → consumeNonce errors
	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{Nonce: nonce, IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, name+".example.test")})
	if ee == nil || ee.Reason != "internal" {
		t.Fatalf("a Valkey error during nonce consume must be internal, got %v", ee)
	}
}

// TestSignFailureRollsBack: any SignIdentity failure after a
// claim deletes the claimed name.
func TestSignFailureRollsBack(t *testing.T) {
	st := tunneltest.NewStore()
	// A CSR whose signature verifies but whose key the CA refuses (RSA) forces the sign failure AFTER
	// the claim; key binding is bypassed via a matching attested key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: rsaKey.Public()}, Issuer: &fakeIssuer{},
	})
	if _, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: rsaCSR}); ee == nil {
		t.Fatal("sign failure must surface an error")
	}
	if st.NameCount() != 0 {
		t.Fatal("DeleteName must roll the claim back")
	}
}

// TestClaimCollisionDrawsNewName: the plan's "claim collision → new name" row — an existing first
// candidate forces a redraw; the second candidate is claimed.
func TestClaimCollisionDrawsNewName(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{},
	})
	names := []string{"taken0name0", "fresh0name0"}
	svc.SetNameGen(func() (string, error) {
		n := names[0]
		if len(names) > 1 {
			names = names[1:]
		}
		return n, nil
	})
	// Pre-claim the first candidate.
	if err := st.PutName(context.Background(), "taken0name0", store.NameRecord{Schema: 1, IdentityKeyFP: "other"}); err != nil {
		t.Fatal(err)
	}
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	if res.Name != "fresh0name0" {
		t.Fatalf("a colliding candidate must be redrawn, got %q", res.Name)
	}
	if rec, err := st.GetName(context.Background(), "taken0name0"); err != nil {
		t.Fatal(err)
	} else if rec.IdentityKeyFP != "other" {
		t.Fatal("the competitor's claim must stand")
	}
}

// TestClaimTimeoutCountsAsLoss: the plan's "claim timeout counts as loss" row — a failed PUT abandons
// that name permanently and the loop draws a new one.
func TestClaimTimeoutCountsAsLoss(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{},
	})
	var drawn []string
	i := 0
	svc.SetNameGen(func() (string, error) {
		i++
		n := "cand0name0" + string(rune('a'+i))
		drawn = append(drawn, n)
		return n, nil
	})
	st.FailNextPut = errors.New("deadline exceeded")
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	if len(drawn) < 2 || res.Name != drawn[len(drawn)-1] {
		t.Fatalf("a timed-out PUT must abandon the name and redraw, drew %v won %q", drawn, res.Name)
	}
	if _, err := st.GetName(context.Background(), drawn[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the abandoned candidate must not exist")
	}
}

// TestFinalRecordWriteNonFatal: the plan's "final record write is non-fatal" row — a failing
// success-path PutName still returns the issued certs.
func TestFinalRecordWriteNonFatal(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "gts"},
	})
	name := doEnroll(t, svc, idCSR)
	tlsCSR := newTLSCSR(t, name+".example.test")
	st.FailNextPut = errors.New("s3 down") // the recordCert LWW write fails
	res, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if ee != nil || len(res.PublicCert) == 0 {
		t.Fatalf("a failing final record write must not fail the issuance: %v", ee)
	}
}

// TestRejectedEvidenceBestEffort: the plan's "rejected-evidence best-effort" row — an evidence-store
// failure never masks the rejection.
func TestRejectedEvidenceBestEffort(t *testing.T) {
	st := tunneltest.NewStore()
	st.RejectedErr = errors.New("s3 down")
	idCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{err: attest.ErrBootState}, Issuer: &fakeIssuer{},
	})
	_, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee == nil || ee.Reason != "unauthorized" {
		t.Fatalf("the rejection must surface unchanged despite the evidence failure, got %v", ee)
	}
}

// TestIssueRecordsIssuanceAndCap: the plan's "success records issuance" + "issuance cap" rows — the 7d
// counter increments on success only, and an at-cap name gets a retryable refusal without an issue call.
func TestIssueRecordsIssuanceAndCap(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	iss := &fakeIssuer{ca: "letsencrypt"}
	svc, mr := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: iss, IssuePerWeek: 1,
	})
	name := doEnroll(t, svc, idCSR)
	tlsCSR := newTLSCSR(t, name+".example.test")
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	}); ee != nil {
		t.Fatalf("first issuance failed: %v", ee)
	}
	callsAfterFirst := iss.obtains + iss.renews
	mr.FastForward(time.Hour)

	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if ee == nil || ee.Reason != "issuance_cap" || !ee.Retryable || ee.RetryAfter != 7*24*time.Hour-time.Hour {
		t.Fatalf("an at-cap name must get a retryable issuance_cap with the time left in its window, got %+v", ee)
	}
	if iss.obtains+iss.renews != callsAfterFirst {
		t.Fatal("the cap must refuse BEFORE any issuer call")
	}
}

type cancellingIssuer struct {
	fakeIssuer
	cancel context.CancelFunc
}

func (c *cancellingIssuer) Obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	defer c.cancel()
	return c.fakeIssuer.Obtain(ctx, csr, name)
}

func TestIssue_CounterSurvivesCancelledRequest(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	iss := &cancellingIssuer{fakeIssuer: fakeIssuer{ca: "letsencrypt"}, cancel: cancel}
	svc, mr := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: iss, IssuePerWeek: 1,
	})
	name := doEnroll(t, svc, idCSR)
	if _, ee := svc.Issue(ctx, name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, name+".example.test"),
	}); ee != nil {
		t.Fatalf("issuance failed: %v", ee)
	}
	if got, err := mr.Get("iss:" + name); err != nil || got != "1" {
		t.Fatalf("a certificate issued as the request is cancelled must still be counted: iss=%q err=%v", got, err)
	}
}

func TestSignError_RetryableAnd503(t *testing.T) {
	if e := signError(errors.New("x")); e.Reason != "identity_sign_failed" || !e.Retryable || statusForError(e) != http.StatusServiceUnavailable {
		t.Fatalf("a signing failure = %+v (status %d), want retryable identity_sign_failed / 503", e, statusForError(e))
	}
	if e := signError(ca.ErrUnsupportedKeyType); e.Reason != "unsupported_key_type" || e.Retryable || statusForError(e) != http.StatusBadRequest {
		t.Fatalf("a non-P-256 key = %+v (status %d), want unsupported_key_type / 400", e, statusForError(e))
	}
}

// TestRenewalCallsRenewWithCur: the plan's "renewal calls Renew with cur" row — a name with an issued
// cert renews via Renew (never Obtain), receiving the current cert info.
func TestRenewalCallsRenewWithCur(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	iss := &fakeIssuer{ca: "gts"}
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: iss, IssuePerWeek: 5,
	})
	name := doEnroll(t, svc, idCSR)
	tlsCSR := newTLSCSR(t, name+".example.test")
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	}); ee != nil {
		t.Fatalf("first issuance failed: %v", ee)
	}
	if iss.obtains != 1 || iss.renews != 0 {
		t.Fatalf("first issuance must Obtain, got obtains=%d renews=%d", iss.obtains, iss.renews)
	}
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	}); ee != nil {
		t.Fatalf("renewal failed: %v", ee)
	}
	if iss.renews != 1 {
		t.Fatalf("a renewal must call Renew, got obtains=%d renews=%d", iss.obtains, iss.renews)
	}
	if iss.lastCur.CA != "gts" {
		t.Fatalf("Renew must receive the CURRENT cert info, got %+v", iss.lastCur)
	}
}

// TestNonceSingleUse: the plan's "nonce single use" row — a consumed nonce cannot be replayed.
func TestNonceSingleUse(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{},
	})
	nonce := mintNonce(t, svc)
	if _, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: nonce, IdentityCSR: idCSR}); ee != nil {
		t.Fatalf("first use failed: %v", ee)
	}
	if _, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: nonce, IdentityCSR: idCSR}); ee == nil || ee.Reason != "invalid_nonce" {
		t.Fatalf("a replayed nonce must be refused, got %v", ee)
	}
}

// TestAttestationOptionalAcceptsWithoutVerify: the plan's "attestation-optional accepts fixture" row —
// with the test-only mode on, enrollment succeeds without a verifier verdict.
func TestAttestationOptionalAcceptsWithoutVerify(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, _ := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, AttestOptional: true,
		Verifier: fakeVerifier{err: attest.ErrChainUntrusted}, // would fail if consulted
		Issuer:   &fakeIssuer{},
	})
	if _, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR}); ee != nil {
		t.Fatalf("attestation-optional enrollment failed: %v", ee)
	}
}

// TestEnrollPerIPLimit: the plan's "enroll per-IP limit" row — over the minute window, enrollment is
// refused before attestation.
func TestEnrollPerIPLimit(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, EnrollMinute: 1, EnrollHour: 100,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{},
	})
	if _, ee := svc.Enroll(context.Background(), "6.6.6.6", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR}); ee != nil {
		t.Fatalf("first enroll failed: %v", ee)
	}
	_, ee := svc.Enroll(context.Background(), "6.6.6.6", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee == nil || ee.Reason != "enroll_rate" || !ee.Retryable {
		t.Fatalf("over-limit enroll must be refused with enroll_rate, got %v", ee)
	}
}

// multiSANCSR builds a TLS CSR with an arbitrary CN + SAN list (the smuggling attack shapes).
func multiSANCSR(t *testing.T, cn string, sans []string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: sans,
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

// TestIssueRejectsExtraIdentifiers covers the exact-identifier invariant: the TLS CSR must request
// EXACTLY <name>.<tunnel-domain> — a CSR that ALSO carries another tenant's name, a wildcard, or a
// reserved host must be refused (lego would otherwise order certs for every SAN in the CSR).
func TestIssueRejectsExtraIdentifiers(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{ca: "letsencrypt"},
	})
	name := doEnroll(t, svc, idCSR)
	want := name + ".example.test"

	tests := []struct {
		tname string
		cn    string
		sans  []string
	}{
		{tname: "extra tenant SAN", cn: want, sans: []string{want, "othertenant.example.test"}},
		{tname: "wildcard SAN", cn: want, sans: []string{want, "*.example.test"}},
		{tname: "reserved enroll host SAN", cn: want, sans: []string{want, "enroll.example.test"}},
		{tname: "reserved control host SAN", cn: want, sans: []string{want, "connect.example.test"}},
		{tname: "foreign CN with own SAN", cn: "othertenant.example.test", sans: []string{want}},
		{tname: "wildcard only", cn: "", sans: []string{"*.example.test"}},
	}
	for _, tc := range tests {
		t.Run(tc.tname, func(t *testing.T) {
			_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
				Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: multiSANCSR(t, tc.cn, tc.sans),
			})
			if ee == nil || ee.Reason != "csr_domain_mismatch" {
				t.Fatalf("a CSR with extra/foreign identifiers must be refused (csr_domain_mismatch), got %v", ee)
			}
		})
	}

	// The exact single-identifier CSR still issues.
	if _, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: multiSANCSR(t, want, []string{want}),
	}); ee != nil {
		t.Fatalf("the exact CSR must still issue: %v", ee)
	}
}

// blockingIssuer blocks in Obtain until proceed is closed, so a test can hold one Issue in-flight (its
// issuance lock held) while a second concurrent Issue runs against the same name.
type blockingIssuer struct {
	entered chan struct{}
	proceed chan struct{}
}

func (b *blockingIssuer) Obtain(_ context.Context, _ *x509.CertificateRequest, _ string) ([]byte, store.CertInfo, error) {
	b.entered <- struct{}{}
	<-b.proceed
	return []byte("PUBLIC-CERT-PEM"), store.CertInfo{CA: "letsencrypt", Serial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(160 * time.Hour)}, nil
}

func (b *blockingIssuer) Renew(_ context.Context, _ *x509.CertificateRequest, _ string, _ store.CertInfo) ([]byte, store.CertInfo, error) {
	return nil, store.CertInfo{}, errors.New("renew not expected")
}

// TestIssue_ConcurrentCallsRespectCap: with cap 1, a first Issue holds its issuance lock while
// a concurrent second Issue for the same name is refused with issuance_cap.
func TestIssue_ConcurrentCallsRespectCap(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	iss := &blockingIssuer{entered: make(chan struct{}, 1), proceed: make(chan struct{})}
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, TunnelDomain: "example.test",
		Verifier: fakeVerifier{key: idPub}, Issuer: iss, IssuePerWeek: 1,
	})
	name := doEnroll(t, svc, idCSR)
	tlsCSR := newTLSCSR(t, name+".example.test")

	type outcome struct {
		res Result
		err *Error
	}
	done := make(chan outcome, 1)
	go func() {
		r, e := svc.Issue(context.Background(), name, "1.2.3.4", Request{
			Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
		})
		done <- outcome{r, e}
	}()
	<-iss.entered // the first Issue holds its issuance lock and is now inside Obtain

	// A concurrent second Issue for the same name must be refused by the in-flight cap.
	_, e2 := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if e2 == nil || e2.Reason != "issuance_cap" || !e2.Retryable || e2.RetryAfter != 300*time.Second {
		t.Fatalf("a concurrent second issue must hit issuance_cap with a 300 s retry_after, got %+v", e2)
	}

	close(iss.proceed) // let the first Issue finish
	if got := <-done; got.err != nil {
		t.Fatalf("the first issue must succeed: %v", got.err)
	}
}

func TestClaimName_LockedCandidateDrawsNewName(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	svc, mr := newService(t, Config{Names: st})
	names := []string{"held0name00", "free0name00"}
	svc.SetNameGen(func() (string, error) {
		n := names[0]
		if len(names) > 1 {
			names = names[1:]
		}
		return n, nil
	})
	if err := mr.Set(claimLockKey("held0name00"), "competitor"); err != nil {
		t.Fatal(err)
	}
	name, err := svc.claimName(context.Background(), store.NameRecord{})
	if err != nil || name != "free0name00" {
		t.Fatalf("claimName = %q, %v; want the unlocked candidate", name, err)
	}
	if _, err := st.GetName(context.Background(), "held0name00"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a candidate locked by another claimer must not be written")
	}
}

func TestClaimName_LockKeptForTheSettleWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		putFail bool
	}{
		{name: "claimed"},
		{name: "write failed (zombie window)", putFail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := tunneltest.NewStore()
			svc, mr := newService(t, Config{Names: st, ClaimTimeout: 2 * time.Second, ClaimSettle: 5 * time.Second})
			var drawn []string
			svc.SetNameGen(func() (string, error) {
				n := "cand0name0" + string(rune('a'+len(drawn)))
				drawn = append(drawn, n)
				return n, nil
			})
			if tc.putFail {
				st.FailNextPut = errors.New("deadline exceeded")
			}
			name, err := svc.claimName(context.Background(), store.NameRecord{})
			if err != nil {
				t.Fatal(err)
			}
			if ttl := mr.TTL(claimLockKey(drawn[0])); ttl != 5*time.Second {
				t.Fatalf("the first candidate's lock must stay for --registry-claim-settle, TTL = %v", ttl)
			}
			if _, err := st.GetName(context.Background(), name); err != nil {
				t.Fatal(err)
			}
			if ttl := mr.TTL(claimLockKey(name)); ttl != 5*time.Second {
				t.Fatalf("the winning candidate's lock must stay for --registry-claim-settle, TTL = %v", ttl)
			}
		})
	}
}

func TestClaimName_ZombieWriteNeverGetsAnOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := tunneltest.NewStore()
	svc, mr := newService(t, Config{Names: st, ClaimTimeout: 3 * time.Second, ClaimSettle: 5 * time.Second})
	draws := []string{"zomb0name00", "zomb0name00", "free0name00", "zomb0name00", "next0name00"}
	svc.SetNameGen(func() (string, error) {
		n := draws[0]
		draws = draws[1:]
		return n, nil
	})
	st.ZombieNextPut = errors.New("timeout but landed")
	name, err := svc.claimName(ctx, store.NameRecord{IdentityKeyFP: "zombie"})
	if err != nil || name != "free0name00" {
		t.Fatalf("claimName = %q, %v; the zombie's name must be abandoned and its redraw refused by the lock", name, err)
	}
	if ttl := mr.TTL(claimLockKey("zomb0name00")); ttl != 5*time.Second {
		t.Fatalf("the abandoned name's lock must stay for --registry-claim-settle, TTL = %v", ttl)
	}
	mr.FastForward(6 * time.Second)
	name, err = svc.claimName(ctx, store.NameRecord{IdentityKeyFP: "second"})
	if err != nil || name != "next0name00" {
		t.Fatalf("claimName = %q, %v; after the lock expired the landed zombie record must still refuse its name", name, err)
	}
	if rec, err := st.GetName(ctx, "zomb0name00"); err != nil || rec.IdentityKeyFP != "zombie" {
		t.Fatalf("the zombie record must stay unowned and untouched: %+v %v", rec, err)
	}
}
