package attest

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// testVerifier wires a Verifier from in-memory snapshots (white-box; no HTTP).
func testVerifier(t *testing.T, ca *fakeCA, signerDigest []byte, statusEntries map[string]string, fetchedAt time.Time) *Verifier {
	t.Helper()
	roots := &RootSet{}
	roots.pool.Store(ca.rootPool())

	status := &StatusList{now: time.Now}
	if statusEntries == nil {
		statusEntries = map[string]string{}
	}
	norm := map[string]string{}
	for k, v := range statusEntries {
		norm[normalizeSerial(k)] = v
	}
	status.snap.Store(&statusSnapshot{entries: norm, fetchedAt: fetchedAt})

	set, err := parseDigests([]byte(hexOf(signerDigest)))
	if err != nil {
		t.Fatal(err)
	}
	signers := &SignerAllowlist{}
	signers.set.Store(&set)

	return NewVerifier(roots, status, signers, 24*time.Hour)
}

func hexOf(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdig[c>>4], hexdig[c&0xf])
	}
	return string(out)
}

func frozenNow() time.Time { return time.Unix(1_700_000_000, 0).Add(24 * time.Hour) }

func TestVerifyRealisticChainPasses(t *testing.T) {
	ca := newFakeCA(t)
	p := defaultParams()
	chain, key := ca.buildChain(t, p)
	v := testVerifier(t, ca, p.signerDigest, nil, frozenNow())

	res, err := v.Verify(chain, p.challenge, frozenNow())
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if res.Package != p.packageName {
		t.Errorf("package = %q", res.Package)
	}
	if res.Device.SecurityLevel != "tee" || res.Device.OSVersion != 160000 {
		t.Errorf("device scalars = %+v", res.Device)
	}
	if res.LeafPublicKey == nil {
		t.Error("LeafPublicKey must be surfaced for key binding")
	}
	// The surfaced key IS the attested leaf key.
	if !key.PublicKey.Equal(res.LeafPublicKey) {
		t.Error("LeafPublicKey must equal the attested leaf key")
	}
}

func TestVerifyNegativeMatrix(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(p *chainParams)
		wrongCA bool
		wantErr error
	}{
		{"wrong root", nil, true, ErrChainUntrusted},
		{"software level", func(p *chainParams) { p.securityLevel = SecuritySoftware }, false, ErrSecurityLevel},
		{"unverified boot", func(p *chainParams) { p.bootState = BootUnverified }, false, ErrBootState},
		{"device unlocked", func(p *chainParams) { p.deviceLocked = false }, false, ErrDeviceUnlocked},
		{"broken signature", func(p *chainParams) { p.breakSignature = true }, false, ErrChainUntrusted},
		{"tampered extension", func(p *chainParams) { p.tamperExtension = true }, false, ErrChainUntrusted},
		{"leaf-only chain", func(p *chainParams) { p.leafOnly = true }, false, ErrChainUntrusted},
		{"dropped intermediate", func(p *chainParams) { p.dropIntermediate = true }, false, ErrChainUntrusted},
		{"duplicated chain", func(p *chainParams) { p.duplicateLeaf = true }, false, ErrChainUntrusted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newFakeCA(t)
			p := defaultParams()
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			chain, _ := ca.buildChain(t, p)
			verifierCA := ca
			if tc.wrongCA {
				verifierCA = newFakeCA(t) // verify against a DIFFERENT root than the one that signed
			}
			v := testVerifier(t, verifierCA, defaultParams().signerDigest, nil, frozenNow())
			_, err := v.Verify(chain, p.challenge, frozenNow())
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyRejectsChallengeMismatch(t *testing.T) {
	ca := newFakeCA(t)
	p := defaultParams()
	chain, _ := ca.buildChain(t, p) // chain carries p.challenge
	v := testVerifier(t, ca, p.signerDigest, nil, frozenNow())
	// Verify with a DIFFERENT server nonce than the one embedded in the chain.
	if _, err := v.Verify(chain, []byte("a-different-server-nonce"), frozenNow()); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("got %v, want ErrChallengeMismatch", err)
	}
}

func TestVerifyRejectsDigestNotAllowed(t *testing.T) {
	ca := newFakeCA(t)
	p := defaultParams()
	chain, _ := ca.buildChain(t, p)
	// Allowlist holds a DIFFERENT digest.
	v := testVerifier(t, ca, sha256sum([]byte("some-other-signer")), nil, frozenNow())
	if _, err := v.Verify(chain, p.challenge, frozenNow()); !errors.Is(err, ErrSignerNotAllowed) {
		t.Errorf("got %v, want ErrSignerNotAllowed", err)
	}
}

func TestVerifyRejectsRevokedSerial(t *testing.T) {
	ca := newFakeCA(t)
	p := defaultParams()
	chain, _ := ca.buildChain(t, p)
	revoked := map[string]string{chain[0].SerialNumber.Text(16): "REVOKED"}
	v := testVerifier(t, ca, p.signerDigest, revoked, frozenNow())
	if _, err := v.Verify(chain, p.challenge, frozenNow()); !errors.Is(err, ErrRevoked) {
		t.Errorf("got %v, want ErrRevoked", err)
	}
}

func TestVerifyRejectsStaleStatus(t *testing.T) {
	ca := newFakeCA(t)
	p := defaultParams()
	chain, _ := ca.buildChain(t, p)
	// Status fetched 48h before now, maxStale 24h → stale.
	v := testVerifier(t, ca, p.signerDigest, nil, frozenNow().Add(-48*time.Hour))
	if _, err := v.Verify(chain, p.challenge, frozenNow()); !errors.Is(err, ErrStatusStale) {
		t.Errorf("got %v, want ErrStatusStale", err)
	}
}

func TestVerifyRejectsExpiredChainAtSimulatedDate(t *testing.T) {
	// Agreed deterministic substitute for "verify at current time": verify a valid chain at
	// notAfter + 30 days — always past validity, green on any calendar day.
	ca := newFakeCA(t)
	p := defaultParams()
	chain, _ := ca.buildChain(t, p)
	simulated := p.notAfter.Add(30 * 24 * time.Hour)
	v := testVerifier(t, ca, p.signerDigest, nil, simulated)
	if _, err := v.Verify(chain, p.challenge, simulated); !errors.Is(err, ErrChainUntrusted) {
		t.Errorf("expired chain: got %v, want ErrChainUntrusted", err)
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	ca := newFakeCA(t)
	v := testVerifier(t, ca, defaultParams().signerDigest, nil, frozenNow())
	if _, err := v.Verify(nil, []byte("x"), frozenNow()); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("got %v, want ErrEmptyChain", err)
	}
}

var _ = x509.Certificate{}
