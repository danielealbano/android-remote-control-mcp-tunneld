// The unit lifecycle test; the real-server coverage lives in the integration tier
// (internal/server/integration_test.go, //go:build integration).
package server

import (
	"context"
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

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
)

// writeCA generates a self-signed internal CA (cert + key) to temp files and returns their paths.
func writeCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tunneld-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "ca-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// lifecycleConfig builds a ServeCmd wired for a local, network-free lifecycle test: loopback listeners,
// miniredis, unreachable ACME/attestation/S3 endpoints (so those paths fail fast and DEGRADE rather than
// dialing the internet).
func lifecycleConfig(t *testing.T, redisAddr string) config.ServeCmd {
	t.Helper()
	caCert, caKey := writeCA(t)
	acmeDir := t.TempDir()
	signer := filepath.Join(t.TempDir(), "signers.txt")
	if err := os.WriteFile(signer, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	const unreachable = "http://127.0.0.1:1"
	return config.ServeCmd{
		RedisURL:       "redis://" + redisAddr,
		Listen:         "127.0.0.1:0",
		MeshListen:     "127.0.0.1:0",
		InternalListen: "127.0.0.1:0",
		MeshAdvertise:  "127.0.0.1:19443",
		MeshPoolSize:   4,
		MeshCertTTL:    24 * time.Hour,

		EnrollHost:   "enroll.example.test",
		ControlHost:  "connect.example.test",
		NameLength:   10,
		CACert:       caCert,
		CAKey:        caKey,
		CertValidity: 4380 * time.Hour,

		AttestSignerDigestFile: signer,
		AttestRootURL:          unreachable + "/root",
		AttestStatusURL:        unreachable + "/status",
		AttestStatusMaxStale:   24 * time.Hour,
		AttestationOptional:    true,

		ACMEDirLE:           unreachable + "/dir",
		ACMEDirGTS:          unreachable + "/dir",
		ACMEDirZeroSSL:      unreachable + "/dir",
		ACMEEmail:           "ops@example.test",
		ACMELEProfile:       "shortlived",
		ACMEGTSValidity:     168 * time.Hour,
		ACMEAccountDir:      acmeDir,
		ACMEDNSProvider:     "",
		ACMECooldownDefault: time.Hour,
		ACMEBackoffInitial:  time.Minute,
		ACMEBackoffMax:      6 * time.Hour,
		ACMERenewMargin:     48 * time.Hour,
		IssuePerWeek:        3,

		RouteTTL:            30 * time.Second,
		ControlPingInterval: 30 * time.Second,
		LimitStreamPending:  64,
		LimitEnrollHour:     20,
		LimitEnrollMinute:   2,
		LimitEnrollBody:     "1mb",

		MaxClients:       100,
		LimitConnRate:    100,
		LimitConcurrent:  8,
		HandshakeTimeout: 5 * time.Second, LimitDialBackTimeout: 10 * time.Second,
		LimitConnIdle:        120 * time.Second,
		LimitConnMinGrace:    10 * time.Second,
		LimitConnEvictIdle:   30 * time.Second,
		LimitConnMinRate:     "1kb",
		LimitConnProtectRate: "10kb",
		LimitBandwidth:       "1mbit",
		LimitTrafficDay:      "1gb",
		LimitTrafficWeek:     "4gb",

		RegistryClaimTimeout: 3 * time.Second,
		RegistryClaimSettle:  5 * time.Second,

		BanPoll:       time.Second,
		ShutdownGrace: 2 * time.Second,

		S3Endpoint:       unreachable,
		S3Region:         "us-east-1",
		S3Bucket:         "tunneld-test",
		S3AccessKey:      "test",
		S3SecretKey:      "test-changeme",
		S3ForcePathStyle: true,
	}
}

// TestRun_Lifecycle boots the full E2E assembly on loopback (degraded ACME/attestation/S3), lets the
// listeners + schedulers start, then cancels and asserts a clean drain. It exercises the wiring, not the
// data plane (that is the integration tier).
func TestRun_Lifecycle(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := lifecycleConfig(t, mr.Addr())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, testLogger(), "test") }()

	// Wait until the node heartbeat has registered this node (proves construction finished and the
	// schedulers are running) before cancelling.
	waitUntil(t, 5*time.Second, func() bool { return len(mr.DB(0).Keys()) > 0 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned an error on clean shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not drain within 15s of context cancellation")
	}
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
