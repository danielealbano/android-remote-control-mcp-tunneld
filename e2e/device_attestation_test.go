//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

// attestProbePkg is the committed probe app (support/attest-probe/, built via `make attest-probe`).
const attestProbePkg = "com.example.attestprobe"

// TestE2E_DeviceAttestation runs the REAL attestation capture+verify against a locally-connected Android
// device using the committed probe APK: it integrity-checks the committed APK against its committed
// SHA-256, installs it, launches its Activity with a fresh server nonce, lets the app generate a
// hardware-attested key bound to that nonce and write the chain, pulls the chain via run-as, and
// verifies it with the production attest.Verifier against the live Google root + revocation-status sets.
// It SKIPS (never fails) when no single adb device is present, and is NEVER run in CI with a device.
func TestE2E_DeviceAttestation(t *testing.T) {
	serial, ok := attestDeviceSerial(t)
	if !ok {
		t.Skip("no single adb device connected")
	}

	apkPath := filepath.Join("..", "fixtures", "attest-probe", "attest-probe.apk")
	shaPath := filepath.Join("..", "fixtures", "attest-probe", "attest-probe.apk.sha256")
	signersPath := filepath.Join("..", "fixtures", "attest-probe", "signers.allow")

	// Integrity-gate the committed APK against its committed digest before installing anything.
	wantSum, err := os.ReadFile(shaPath)
	if err != nil {
		t.Fatalf("read committed APK sha256: %v", err)
	}
	if got := apkSHA256(t, apkPath); got != strings.TrimSpace(string(wantSum)) {
		t.Fatalf("committed probe APK sha256 mismatch: got %s want %s (run 'make attest-probe')",
			got, strings.TrimSpace(string(wantSum)))
	}

	adb(t, serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	adb(t, serial, "install", "-r", apkPath)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = exec.CommandContext(ctx, "adb", "-s", serial, "uninstall", attestProbePkg).Run()
	})
	// install -r keeps app data, so clear any stale result files from a prior interrupted run.
	adb(t, serial, "shell", "run-as", attestProbePkg, "sh", "-c",
		"rm -f files/done files/error files/chain.pem")

	// Fresh server nonce → the app binds it into the attestation challenge (freshness).
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	adb(t, serial, "shell", "am", "start", "-n", attestProbePkg+"/.MainActivity",
		"-e", "nonce", hex.EncodeToString(nonce[:]))

	chainPEM := pollProbeResult(t, serial, attestProbePkg, 60*time.Second)
	chain, err := parsePEMChain(chainPEM)
	if err != nil || len(chain) == 0 {
		t.Fatalf("probe did not return a PEM attestation chain: %v", err)
	}

	// Build the PRODUCTION verifier against the LIVE Google root + status sets and the committed allowlist.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	signers, err := attest.LoadSignerAllowlist(signersPath, nil)
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
	pub, ok := res.LeafPublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("attested leaf key must be ECDSA P-256, got %T", res.LeafPublicKey)
	}
}

// attestDeviceSerial returns the serial of the single connected device in the "device" state, or
// ok=false when adb is absent or there is not exactly one such device.
func attestDeviceSerial(t *testing.T) (string, bool) {
	t.Helper()
	if _, err := exec.LookPath("adb"); err != nil {
		return "", false
	}
	out, err := exec.Command("adb", "devices").Output()
	if err != nil {
		return "", false
	}
	var serials []string
	for _, line := range strings.Split(string(out), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "device" {
			serials = append(serials, fields[0])
		}
	}
	if len(serials) != 1 {
		return "", false
	}
	return serials[0], true
}

// adb runs `adb -s <serial> <args…>` under a bounded timeout, returning stdout; it fails the test on any
// non-zero exit or timeout (so a hung command can never block the suite forever).
func adb(t *testing.T, serial string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	full := append([]string{"-s", serial}, args...)
	cmd := exec.CommandContext(ctx, "adb", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("adb %s failed: %v\n%s", strings.Join(full, " "), err, stderr.String())
	}
	return stdout.Bytes()
}

// pollProbeResult polls the app's result files (via run-as, so app-internal storage is readable because
// the debug APK is debuggable) until a `done` marker (→ returns chain.pem) or an `error` file (→ fails)
// appears, or the timeout elapses (→ fails). The [ -f ] guards make it robust to adb exit-code quirks.
func pollProbeResult(t *testing.T, serial, pkg string, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status := string(adb(t, serial, "exec-out", "run-as", pkg, "sh", "-c",
			"if [ -f files/error ]; then echo ERR; cat files/error; "+
				"elif [ -f files/done ]; then echo DONE; fi"))
		switch {
		case strings.HasPrefix(status, "ERR"):
			t.Fatalf("attestation probe reported an error: %s",
				strings.TrimSpace(strings.TrimPrefix(status, "ERR")))
		case strings.HasPrefix(status, "DONE"):
			return adb(t, serial, "exec-out", "run-as", pkg, "sh", "-c", "cat files/chain.pem")
		}
		if time.Now().After(deadline) {
			t.Fatalf("attestation probe produced no result within %s", timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// apkSHA256 returns the lowercase-hex SHA-256 of the file at path.
func apkSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read probe APK %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
