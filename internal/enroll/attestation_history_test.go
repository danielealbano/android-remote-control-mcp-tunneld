package enroll

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const testChainPEM = "-----BEGIN CERTIFICATE-----\nATTESTATION\n-----END CERTIFICATE-----\n"

func newHistoryService(t *testing.T, st *tunneltest.Store, v Verifier, optional bool) (*Service, *syncBuffer) {
	t.Helper()
	logger, buf := captureLogger()
	svc, _ := newService(t, Config{
		CA: testCA(t), Names: st, Evidence: st, Attestations: st, TunnelDomain: "example.test", Logger: logger,
		Verifier: v, Issuer: &fakeIssuer{ca: "letsencrypt"}, AttestOptional: optional,
	})
	return svc, buf
}

func enrollWithChain(t *testing.T, svc *Service, idCSR *x509.CertificateRequest) string {
	t.Helper()
	res, ee := svc.Enroll(context.Background(), "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, AttestChainPEM: []byte(testChainPEM),
	})
	if ee != nil {
		t.Fatalf("enroll failed: %v", ee)
	}
	return res.Name
}

func issueWithChain(t *testing.T, svc *Service, name string, idCSR *x509.CertificateRequest) *Error {
	t.Helper()
	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, name+".example.test"),
		AttestChainPEM: []byte(testChainPEM),
	})
	return ee
}

func TestEnroll_RecordsTheAcceptedAttestation(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newHistoryService(t, st, fakeVerifier{key: idPub}, false)
	name := enrollWithChain(t, svc, idCSR)
	got := st.Attestations(name)
	want := store.Attestation{TS: time.Unix(1_700_000_000, 0).UTC(), Kind: store.AttestationKindEnroll, AttestChainPEM: testChainPEM}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("attestation history = %+v, want exactly %+v", got, want)
	}
}

func TestIssue_RecordsTheAttestationAndKeepsTheLastTen(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newHistoryService(t, st, fakeVerifier{key: idPub}, false)
	name := enrollWithChain(t, svc, idCSR)
	base := time.Unix(1_600_000_000, 0).UTC()
	for i := range 10 {
		if err := st.PutAttestation(context.Background(), name, store.Attestation{TS: base.Add(time.Duration(i) * time.Hour), Kind: store.AttestationKindIssue, AttestChainPEM: "older"}); err != nil {
			t.Fatal(err)
		}
	}
	svc.SetClock(func() time.Time { return time.Unix(1_700_000_100, 0) })
	if ee := issueWithChain(t, svc, name, idCSR); ee != nil {
		t.Fatalf("issue failed: %v", ee)
	}
	got := st.Attestations(name)
	if len(got) != attestationHistory {
		t.Fatalf("history holds %d attestations, want %d", len(got), attestationHistory)
	}
	if !got[0].TS.Equal(base.Add(2 * time.Hour)) {
		t.Errorf("oldest kept attestation is from %s, want the two oldest dropped (%s)", got[0].TS, base.Add(2*time.Hour))
	}
	enrolled, issued := got[len(got)-2], got[len(got)-1]
	if enrolled.Kind != store.AttestationKindEnroll || issued.Kind != store.AttestationKindIssue || issued.AttestChainPEM != testChainPEM ||
		!issued.TS.Equal(time.Unix(1_700_000_100, 0)) {
		t.Errorf("the newest attestations must be the enrollment then this issuance, got %+v then %+v", enrolled, issued)
	}
}

func TestAttestationHistory_NothingRecordedWhenAttestationIsOptional(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, _ := newCSR(t)
	svc, _ := newHistoryService(t, st, fakeVerifier{err: attest.ErrChainUntrusted}, true)
	name := enrollWithChain(t, svc, idCSR)
	if ee := issueWithChain(t, svc, name, idCSR); ee != nil {
		t.Fatalf("issue failed: %v", ee)
	}
	if got := st.Attestations(name); len(got) != 0 {
		t.Fatalf("an unverified attestation must never enter the history, got %+v", got)
	}
}

func TestIssue_RefusedAttestationIsNotRecorded(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	svc, _ := newHistoryService(t, st, fakeVerifier{key: idPub}, false)
	name := enrollWithChain(t, svc, idCSR)
	_, ee := svc.Issue(context.Background(), name, "1.2.3.4", Request{
		Nonce: mintNonce(t, svc), IdentityCSR: idCSR, TLSCSR: newTLSCSR(t, "attacker.example.test"),
		AttestChainPEM: []byte(testChainPEM),
	})
	if ee == nil || ee.Reason != "csr_domain_mismatch" {
		t.Fatalf("expected csr_domain_mismatch, got %v", ee)
	}
	if got := st.Attestations(name); len(got) != 1 || got[0].Kind != store.AttestationKindEnroll {
		t.Fatalf("a refused certificate request must not enter the history, got %+v", got)
	}
}

func TestAttestationHistory_StoreFailuresAreLoggedAndNeverRefuse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		putErr   error
		pruneErr error
		want     string
	}{
		{name: "put fails", putErr: errInjected, want: "could not save the phone's attestation in the tunnel's history"},
		{name: "prune fails", pruneErr: errInjected, want: "could not remove the oldest attestations from the tunnel's history"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := tunneltest.NewStore()
			idCSR, idPub := newCSR(t)
			svc, buf := newHistoryService(t, st, fakeVerifier{key: idPub}, false)
			name := enrollWithChain(t, svc, idCSR)
			st.AttestationPutErr, st.AttestationPruneErr = tc.putErr, tc.pruneErr
			if ee := issueWithChain(t, svc, name, idCSR); ee != nil {
				t.Fatalf("a history failure must never refuse the phone, got %v", ee)
			}
			if out := buf.String(); !strings.Contains(out, tc.want) || !strings.Contains(out, "level=WARN") || !strings.Contains(out, "tunnel="+name) {
				t.Fatalf("log must carry the failure, got:\n%s", out)
			}
		})
	}
}

func TestEnroll_HistoryFailureIsLoggedAndNeverRefuses(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	st.AttestationPutErr = errInjected
	idCSR, idPub := newCSR(t)
	svc, buf := newHistoryService(t, st, fakeVerifier{key: idPub}, false)
	name := enrollWithChain(t, svc, idCSR)
	if _, err := st.GetName(context.Background(), name); err != nil {
		t.Fatalf("the enrollment must stand: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "could not save the phone's attestation in the tunnel's history") || !strings.Contains(out, "kind=enroll") {
		t.Fatalf("log must carry the failure, got:\n%s", out)
	}
}

func TestIssue_DevicePropertiesFollowTheLatestAttestation(t *testing.T) {
	t.Parallel()
	st := tunneltest.NewStore()
	idCSR, idPub := newCSR(t)
	withModel := store.DeviceInfo{OSVersion: 150000, SecurityLevel: "tee", Brand: "brand-x", Device: "device-x", Product: "product-x", Manufacturer: "maker-x", Model: "model-x"}
	svc, _ := newHistoryService(t, st, devVerifier{fakeVerifier: fakeVerifier{key: idPub}, dev: withModel}, false)
	name := enrollWithChain(t, svc, idCSR)
	if rec, err := st.GetName(context.Background(), name); err != nil || rec.Device != withModel {
		t.Fatalf("enrollment must record the attested device properties, got %+v (%v)", rec.Device, err)
	}
	withoutModel := store.DeviceInfo{OSVersion: 150000, SecurityLevel: "tee"}
	svc.cfg.Verifier = devVerifier{fakeVerifier: fakeVerifier{key: idPub}, dev: withoutModel}
	if ee := issueWithChain(t, svc, name, idCSR); ee != nil {
		t.Fatalf("an attestation without device properties must still be accepted, got %v", ee)
	}
	if rec, err := st.GetName(context.Background(), name); err != nil || rec.Device != withoutModel {
		t.Fatalf("the record must follow the latest attestation, got %+v (%v)", rec.Device, err)
	}
}
