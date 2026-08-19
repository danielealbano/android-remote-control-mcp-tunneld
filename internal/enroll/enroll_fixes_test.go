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
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
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
	rec, _ = st.GetName(context.Background(), name)
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
	rsaCSR, _ := x509.ParseCertificateRequest(der)
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

// TestSignFailureRollsBack: the plan's "sign failure rolls back" row — any SignIdentity failure after a
// verified claim deletes the claimed name.
func TestSignFailureRollsBack(t *testing.T) {
	st := tunneltest.NewStore()
	// A CSR whose signature verifies but whose key the CA refuses (RSA) forces the sign failure AFTER
	// the claim; key binding is bypassed via a matching attested key.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, rsaKey)
	rsaCSR, _ := x509.ParseCertificateRequest(der)
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
	if err := st.PutName(context.Background(), "taken0name0", store.NameRecord{Schema: 1, ClaimNonce: "other"}); err != nil {
		t.Fatal(err)
	}
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	if res.Name != "fresh0name0" {
		t.Fatalf("a colliding candidate must be redrawn, got %q", res.Name)
	}
	if rec, _ := st.GetName(context.Background(), "taken0name0"); rec.ClaimNonce != "other" {
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
	svc, _ := newService(t, Config{
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

	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if ee == nil || ee.Reason != "issuance_cap" || !ee.Retryable {
		t.Fatalf("an at-cap name must get a retryable issuance_cap, got %v", ee)
	}
	if iss.obtains+iss.renews != callsAfterFirst {
		t.Fatal("the cap must refuse BEFORE any issuer call")
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

// TestClaimSettleWaitBeforeVerify: the plan's "claim settle wait > timeout" row — the verify GET runs
// only AFTER the full --registry-claim-settle wait has been taken.
func TestClaimSettleWaitBeforeVerify(t *testing.T) {
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, ClaimTimeout: 2 * time.Second, ClaimSettle: 5 * time.Second,
		Verifier: fakeVerifier{key: idPub}, Issuer: &fakeIssuer{},
	})
	var slept []time.Duration
	settled := false
	verifySawSettle := false
	gets := 0
	svc.sleep = func(d time.Duration) { slept = append(slept, d); settled = true }
	st.BeforeVerifyGet = func(string) {
		gets++
		if gets == 2 { // 1st GET = existence check (pre-sleep); 2nd GET = the claim verify
			verifySawSettle = settled
		}
	}
	if _, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{Nonce: mintNonce(t, svc), IdentityCSR: idCSR}); ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	if len(slept) == 0 || slept[0] != 5*time.Second {
		t.Fatalf("the claim must settle-wait exactly --registry-claim-settle before verifying, got %v", slept)
	}
	if !verifySawSettle {
		t.Fatal("the verify GET must run only AFTER the settle wait")
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
	csr, _ := x509.ParseCertificateRequest(der)
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
// issuance slot reserved) while a second concurrent Issue runs against the same name.
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

// TestIssue_ConcurrentCallsRespectCap: with cap 1, a first Issue holds its in-flight issuance slot while
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
	<-iss.entered // the first Issue holds its in-flight slot and is now inside Obtain

	// A concurrent second Issue for the same name must be refused by the in-flight cap.
	_, e2 := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: tlsCSR,
	})
	if e2 == nil || e2.Reason != "issuance_cap" {
		t.Fatalf("a concurrent second issue must hit issuance_cap, got %v", e2)
	}

	close(iss.proceed) // let the first Issue finish
	if got := <-done; got.err != nil {
		t.Fatalf("the first issue must succeed: %v", got.err)
	}
}

// countingNames is a NameStore that counts GETs/PUTs and scripts the claim-verify GET: the initial GET
// on an unclaimed candidate is a definitive miss (so the claim PUT proceeds); once a record exists, a
// verify GET returns verifyErr (persistent failure) or, one time, ErrNotFound (PUT definitively lost).
type countingNames struct {
	recs           map[string]store.NameRecord
	gets           int
	puts           int
	verifyErr      error
	verifyGoneOnce bool
}

func (c *countingNames) GetName(_ context.Context, name string) (store.NameRecord, error) {
	c.gets++
	rec, ok := c.recs[name]
	if !ok {
		return store.NameRecord{}, store.ErrNotFound
	}
	if c.verifyErr != nil {
		return store.NameRecord{}, c.verifyErr
	}
	if c.verifyGoneOnce {
		c.verifyGoneOnce = false
		return store.NameRecord{}, store.ErrNotFound
	}
	return rec, nil
}

func (c *countingNames) PutName(_ context.Context, name string, rec store.NameRecord) error {
	c.puts++
	c.recs[name] = rec
	return nil
}

func (c *countingNames) DeleteName(_ context.Context, name string) error {
	delete(c.recs, name)
	return nil
}

// TestClaimName_VerifyErrorFailsWithoutNewName: a persistent claim-verify GET error fails the claim
// (retryable) and consumes EXACTLY one candidate — moving on could orphan a claim whose PUT landed.
func TestClaimName_VerifyErrorFailsWithoutNewName(t *testing.T) {
	names := &countingNames{recs: map[string]store.NameRecord{}, verifyErr: errors.New("s3 read timeout")}
	svc, _ := newService(t, Config{Names: names})
	var drawn []string
	svc.SetNameGen(func() (string, error) {
		n := "cand" + string(rune('a'+len(drawn)))
		drawn = append(drawn, n)
		return n, nil
	})

	name, _, err := svc.claimName(context.Background())
	if err == nil {
		t.Fatalf("a persistent verify error must fail the claim, got name %q", name)
	}
	if len(drawn) != 1 {
		t.Fatalf("a persistent verify error must consume exactly one candidate, drew %v", drawn)
	}
}

// TestClaimName_VerifyNotFoundDrawsNewName: a definitive NotFound at verify means the PUT did not land,
// so the candidate is abandoned and the next one is drawn (regression for the pre-fix behavior).
func TestClaimName_VerifyNotFoundDrawsNewName(t *testing.T) {
	names := &countingNames{recs: map[string]store.NameRecord{}, verifyGoneOnce: true}
	svc, _ := newService(t, Config{Names: names})
	var drawn []string
	svc.SetNameGen(func() (string, error) {
		n := "cand" + string(rune('a'+len(drawn)))
		drawn = append(drawn, n)
		return n, nil
	})

	name, _, err := svc.claimName(context.Background())
	if err != nil {
		t.Fatalf("a NotFound at verify must redraw and then succeed, got %v", err)
	}
	if len(drawn) != 2 || name != drawn[1] {
		t.Fatalf("a NotFound at verify must draw a new candidate, drew %v won %q", drawn, name)
	}
}
