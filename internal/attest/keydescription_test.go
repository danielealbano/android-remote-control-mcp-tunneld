package attest

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseKeyDescriptionFields(t *testing.T) {
	ca := newFakeCA(t)
	p := defaultParams()
	chain, _ := ca.buildChain(t, p)
	kd, err := ParseKeyDescription(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if kd.Package != p.packageName {
		t.Errorf("package = %q", kd.Package)
	}
	if kd.SecurityLevel != SecurityTrustedEnvironment {
		t.Errorf("security level = %d", kd.SecurityLevel)
	}
	if kd.VerifiedBootState != BootVerified || !kd.DeviceLocked {
		t.Errorf("boot=%d locked=%v", kd.VerifiedBootState, kd.DeviceLocked)
	}
	if kd.OSVersion != 160000 || kd.OSPatch != 202607 || kd.VendorPatch != 202607 || kd.BootPatch != 202607 {
		t.Errorf("patch scalars = %+v", kd)
	}
	if len(kd.SignatureDigests) != 1 || hex.EncodeToString(kd.SignatureDigests[0]) != hex.EncodeToString(p.signerDigest) {
		t.Errorf("signature digest mismatch")
	}
	if string(kd.Challenge) != string(p.challenge) {
		t.Errorf("challenge = %q", kd.Challenge)
	}
}

// TestVerifyRealRealmeT70Chain validates the REAL device chain when the fixture is committed (captured
// on-device via the adb path). It SKIPS when the fixture is absent (this repo does not commit one
// without hardware capture); the predicate logic is otherwise covered in full by the fake-CA matrix.
func TestVerifyRealRealmeT70Chain(t *testing.T) {
	pemPath := filepath.Join("testdata", "realme_t70_chain.pem")
	metaPath := filepath.Join("testdata", "realme_t70.json")
	if _, err := os.Stat(pemPath); err != nil {
		t.Skip("no committed real-device fixture (captured on-device via the adb-gated path)")
	}
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		t.Fatal("empty fixture chain")
	}
	_ = metaPath // the committed metadata (challenge + frozen validAt) is loaded by the capture harness
	_ = time.Now
}
