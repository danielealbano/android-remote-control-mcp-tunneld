//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
)

// Google's live attestation endpoints (the config defaults). The adb-gated real-attestation test hits
// these directly — it is a LOCAL developer gate, NEVER wired to CI-with-device.
const (
	googleAttestRootURL   = "https://android.googleapis.com/attestation/root"
	googleAttestStatusURL = "https://android.googleapis.com/attestation/status"
)

// TestE2E_DeviceAttestation runs the REAL attestation capture+verify against a locally-connected Android
// device: it asks an operator-supplied on-device probe to generate a hardware-attested key bound to a
// fresh server nonce, pulls the attestation chain, and verifies it with the production attest.Verifier
// against the live Google root + revocation-status sets. It SKIPS (never fails) when the prerequisites
// are absent, and is NEVER run in CI with a device.
//
// Prerequisites (all required, else the test skips):
//   - `adb` on PATH with exactly one device that reports "device" state.
//   - TUNNELD_ATTEST_PROBE: path to an executable invoked as `<probe> <nonceHex>` that prints the
//     device's attestation chain as PEM (leaf certificate first) to stdout. The probe embodies the
//     on-device keystore-attestation step; the Android client is out of THIS repo's scope
//     (see docs/PROJECT.md Non-goals), so the probe is provided by the operator.
//   - TUNNELD_ATTEST_SIGNER_FILE: the signer-digest allowlist file matching the probe app's signing cert.
func TestE2E_DeviceAttestation(t *testing.T) {
	if !adbHasDevice(t) {
		t.Skip("no adb device connected")
	}
	probe := os.Getenv("TUNNELD_ATTEST_PROBE")
	if probe == "" {
		t.Skip("set TUNNELD_ATTEST_PROBE to the on-device attestation probe executable")
	}
	signerFile := os.Getenv("TUNNELD_ATTEST_SIGNER_FILE")
	if signerFile == "" {
		t.Skip("set TUNNELD_ATTEST_SIGNER_FILE to the probe app's signer-digest allowlist")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Fresh server nonce → the probe binds it into the attestation challenge (freshness).
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	nonceHex := hex.EncodeToString(nonce[:])

	out, err := exec.CommandContext(ctx, probe, nonceHex).Output()
	if err != nil {
		t.Fatalf("attestation probe failed: %v", err)
	}
	chain, err := parsePEMChain(out)
	if err != nil || len(chain) == 0 {
		t.Fatalf("probe did not return a PEM attestation chain: %v", err)
	}

	// Build the PRODUCTION verifier against the LIVE Google root + status sets and the probe's allowlist.
	signers, err := attest.LoadSignerAllowlist(signerFile, nil)
	if err != nil {
		t.Fatalf("load signer allowlist: %v", err)
	}
	roots, err := attest.NewRootSet(ctx, googleAttestRootURL, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("fetch Google attestation roots: %v", err)
	}
	status, err := attest.NewStatusList(ctx, googleAttestStatusURL, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("fetch Google attestation status: %v", err)
	}
	verifier := attest.NewVerifier(roots, status, signers, 24*time.Hour)

	res, verr := verifier.Verify(chain, nonce[:], time.Now())
	if verr != nil {
		t.Fatalf("real device attestation must verify (freshness): %v", verr)
	}
	if res.LeafPublicKey == nil {
		t.Fatal("verified attestation must expose the attested leaf public key")
	}
}

// adbHasDevice reports whether exactly one connected device is in the "device" state.
func adbHasDevice(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("adb"); err != nil {
		return false
	}
	out, err := exec.Command("adb", "devices").Output()
	if err != nil {
		return false
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n")[1:] {
		if strings.HasSuffix(strings.TrimSpace(line), "\tdevice") {
			count++
		}
	}
	return count == 1
}

func parsePEMChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	return chain, nil
}
