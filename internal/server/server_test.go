// The unit lifecycle test; the real-server coverage lives in the integration tier
// (internal/server/integration_test.go, //go:build integration).
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
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
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
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
		ConnLogDir:     t.TempDir(),
		Listen:         "127.0.0.1:0",
		MeshListen:     "127.0.0.1:0",
		InternalListen: "127.0.0.1:0",
		MeshAdvertise:  "127.0.0.1:19443",
		MeshPoolSize:   4,
		MeshCertTTL:    24 * time.Hour,

		EnrollHost:   "enroll.example.test",
		ControlHost:  "connect.example.test",
		NameLength:   10,
		DialBackAdvertise: "127.0.0.1:0", DialBackHTTPS: true, DialBackMTLS: true,
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
		LimitPackets:     100000,
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

	baseline := asyncLogGoroutines()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, testLogger(), "test") }()

	// Wait until the node heartbeat has registered this node (proves construction finished and the
	// schedulers are running) before cancelling.
	waitUntil(t, 5*time.Second, func() bool {
		for _, k := range mr.DB(0).Keys() {
			if strings.HasPrefix(k, "node:") {
				return true
			}
		}
		return false
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned an error on clean shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not drain within 15s of context cancellation")
	}
	waitAsyncLogGoroutines(t, baseline)
	spool, err := store.NewConnLogSpool(cfg.ConnLogDir, "00000000000000aa", tunneltest.NewStore(), func(int) {}, testLogger())
	if err != nil {
		t.Fatalf("a cleanly returned Run must release the --conn-log-dir lock: %v", err)
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	spool.Drain(drainCtx)
}

// TestRun_InternalBindFailureIsFatal verifies an unusable --internal-listen makes Run return an error
// (not a silent Warn that leaves metrics/healthz dead forever).
func TestRun_InternalBindFailureIsFatal(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := lifecycleConfig(t, mr.Addr())
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, occupied)
	cfg.InternalListen = occupied.Addr().String() // already in use → bind must fail

	baseline := asyncLogGoroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg, testLogger(), "bindfatal") }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run must return an error when the internal listener cannot bind")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not fail on the internal bind")
	}
	waitAsyncLogGoroutines(t, baseline)

	go func() { errCh <- Run(ctx, cfg, testLogger(), "bindfatal-again") }()
	select {
	case err := <-errCh:
		if err == nil || strings.Contains(err.Error(), "in use by another process") {
			t.Fatalf("a returned Run must release the --conn-log-dir lock, second Run got %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the second Run did not fail on the internal bind")
	}
	waitAsyncLogGoroutines(t, baseline)
}

// freeAddr binds an ephemeral loopback port, closes it, and returns the address for reuse (small race
// window; acceptable for tests — server.Run rebinds it immediately).
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	tunneltest.CloseOrLog(t, ln)
	return addr
}

func TestRun_HTTPServerErrorsGoThroughSlog(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := lifecycleConfig(t, mr.Addr())
	cfg.Listen = freeAddr(t)
	cfg.MeshListen = freeAddr(t)

	var std syncBuffer
	prev := log.Writer()
	log.SetOutput(&std)
	t.Cleanup(func() { log.SetOutput(prev) })
	var out syncBuffer
	logger := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, logger, "test") }()
	waitUntil(t, 5*time.Second, func() bool {
		for _, k := range mr.DB(0).Keys() {
			if strings.HasPrefix(k, "node:") {
				return true
			}
		}
		return false
	})

	failHandshake(t, cfg.Listen, cfg.EnrollHost)
	failHandshake(t, cfg.MeshListen, "mesh")
	waitUntil(t, 5*time.Second, func() bool {
		return logLineHas(out.String(), "level=DEBUG", "TLS handshake error", "no reserved-host certificate yet") &&
			logLineHas(out.String(), "level=WARN", "TLS handshake error", "client didn't provide a certificate")
	})
	if strings.Contains(std.String(), "TLS handshake error") {
		t.Fatalf("an http.Server error reached the stdlib logger instead of slog: %q", std.String())
	}

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

func failHandshake(t *testing.T, addr, serverName string) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Logf("handshake to %s (%s) failed as intended: %v", addr, serverName, err)
		return
	}
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Logf("read from %s (%s) failed as intended: %v", addr, serverName, err)
	}
	tunneltest.CloseOrLog(t, conn)
}

func logLineHas(logs string, parts ...string) bool {
	for _, line := range strings.Split(logs, "\n") {
		all := true
		for _, p := range parts {
			if !strings.Contains(line, p) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func TestConnLogDropped_AddsEventCount(t *testing.T) {
	t.Parallel()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_connlog_dropped_total", Help: "test"})
	drop := connLogDropped(c)
	drop(3)
	drop(1)
	if got := testutil.ToFloat64(c); got != 4 {
		t.Fatalf("the dropped counter must grow by each call's event count, got %v", got)
	}
}

func asyncLogGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			count := 0
			for _, g := range strings.Split(string(buf[:n]), "\n\n") {
				if strings.Contains(g, "store.(*ConnLogSpool)") {
					count++
				}
			}
			return count
		}
		buf = make([]byte, 2*len(buf))
	}
}

func waitAsyncLogGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline, bounded := t.Deadline()
	for got := asyncLogGoroutines(); got > baseline; got = asyncLogGoroutines() {
		if bounded && time.Until(deadline) < time.Second {
			t.Fatalf("Run returned with %d connection-log goroutines still running (baseline %d)", got, baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRun_ACMEHTTPBindFailureIsFatal(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := lifecycleConfig(t, mr.Addr())
	cfg.ACMEChallengeZeroSSL = config.ChallengeHTTP01
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.InternalListen = probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, occupied)
	cfg.ACMEHTTPListen = occupied.Addr().String()

	baseline := asyncLogGoroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg, testLogger(), "acmehttpbind") }()
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "acme http listen") {
			t.Fatalf("Run must fail on the ACME HTTP-01 bind, got %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not fail on the ACME HTTP-01 bind")
	}
	waitAsyncLogGoroutines(t, baseline)
	rebound, err := net.Listen("tcp", cfg.InternalListen)
	if err != nil {
		t.Fatalf("the internal listener leaked after the ACME HTTP-01 bind failure: %v", err)
	}
	tunneltest.CloseOrLog(t, rebound)
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
	t.Fatal("waitUntil: condition not met within timeout")
}
