//go:build integration

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
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/enroll"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const (
	itTunnelDomain = "example.test"
	itEnrollHost   = "enroll.example.test"
	itControlHost  = "connect.example.test"
	itBucket       = "tunneld-it"
)

// freeAddr binds an ephemeral loopback port, closes it, and returns the address for reuse (small race
// window; acceptable for tests — server.Run rebinds it immediately).
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func emptyFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "signers.txt")
	if err := os.WriteFile(p, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// itEnv is a running integration server plus its infra handles.
type itEnv struct {
	edgeAddr string
	pebble   *tunneltest.PebbleEnv
	s3URL    string
	s3Access string
	s3Secret string
	rdb      *redis.Client
	st       *store.S3Store
}

// startIntegrationServer stands up Valkey + MinIO + Pebble/challtestsrv + the DNS shim, runs the real
// server.Run on loopback in attestation-optional mode against Pebble, and waits until it is ready
// (construction, incl. the reserved-host cert obtain, has finished and the node heartbeat has landed).
func startIntegrationServer(t *testing.T) *itEnv {
	t.Helper()
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, itBucket)
	pebble := tunneltest.StartPebble(t)
	shim := tunneltest.StartACMEDNSShim(t, pebble)

	// lego reads these at startup: the httpreq DNS provider endpoint + the Pebble ACME trust anchor.
	t.Setenv("HTTPREQ_ENDPOINT", shim)
	t.Setenv("LEGO_CA_CERTIFICATES", pebble.MinicaFile)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")

	caCert, caKey := writeCA(t)
	edgeAddr := freeAddr(t)

	cfg := config.ServeCmd{
		RedisURL:       redisURL,
		Listen:         edgeAddr,
		MeshListen:     freeAddr(t),
		InternalListen: freeAddr(t),
		MeshAdvertise:  "127.0.0.1:19443",
		MeshPoolSize:   4, MeshCertTTL: 24 * time.Hour,

		TunnelDomain: itTunnelDomain, EnrollHost: itEnrollHost, ControlHost: itControlHost, NameLength: 10,
		CACert: caCert, CAKey: caKey, CertValidity: 4380 * time.Hour,

		S3Endpoint: s3URL, S3Region: "us-east-1", S3Bucket: itBucket,
		S3AccessKey: access, S3SecretKey: secret, S3ForcePathStyle: true,
		RegistryClaimTimeout: 3 * time.Second, RegistryClaimSettle: 5 * time.Second,

		AttestSignerDigestFile: emptyFile(t),
		AttestRootURL:          "http://127.0.0.1:1/root", AttestStatusURL: "http://127.0.0.1:1/status",
		AttestRefresh: time.Hour, AttestStatusMaxStale: 24 * time.Hour, AttestationOptional: true,

		ACMEDirLE: pebble.DirectoryURL, ACMEDirGTS: pebble.DirectoryURL, ACMEDirZeroSSL: pebble.DirectoryURL,
		ACMEEmail: "ops@example.test", ACMELEProfile: "shortlived", ACMEGTSValidity: 168 * time.Hour,
		ACMEAccountDir: t.TempDir(), ACMEDNSProvider: "httpreq",
		ACMEDNSResolvers: []string{pebble.DNSResolver}, ACMEDNSSkipPropagationCheck: true,
		ACMECooldownDefault: time.Hour, ACMEBackoffInitial: time.Minute, ACMEBackoffMax: 6 * time.Hour,
		ACMERenewMargin: 48 * time.Hour, IssuePerWeek: 3,

		RouteTTL: 30 * time.Second, ControlPingInterval: 30 * time.Second,
		LimitStreamPending: 64, LimitEnrollHour: 1000, LimitEnrollMinute: 1000, LimitEnrollBody: "64kb",
		MaxClients: 100, LimitConnRate: 1000, LimitConcurrent: 8, HandshakeTimeout: 5 * time.Second, LimitDialBackTimeout: 10 * time.Second,
		LimitConnIdle: 120 * time.Second, LimitConnMinGrace: 60 * time.Second, LimitConnEvictIdle: 10 * time.Second,
		LimitConnMinRate: "1kb", LimitConnProtectRate: "10kb", LimitBandwidth: "1mbit",
		LimitTrafficDay: "1gb", LimitTrafficWeek: "4gb",
		BanPoll: time.Second, ShutdownGrace: 3 * time.Second,
		Log: []string{"output=std;level=error"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, testLogger(), "it") }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("server did not drain within 20s of cancellation")
		}
	})

	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })

	// Readiness: the node heartbeat writes a key only AFTER construction (which includes the synchronous
	// reserved-host cert obtain against Pebble) completes. Generous timeout for container warm-up + the
	// two reserved-cert ACME orders.
	if !waitBool(120*time.Second, func() bool {
		keys, _ := rdb.Keys(context.Background(), "*").Result()
		return len(keys) > 0
	}) {
		t.Fatal("server never became ready (reserved-host cert obtain may have failed)")
	}

	st, err := store.NewS3Store(context.Background(), store.S3Config{
		Endpoint: s3URL, Region: "us-east-1", Bucket: itBucket,
		AccessKey: access, SecretKey: secret, ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &itEnv{edgeAddr: edgeAddr, pebble: pebble, s3URL: s3URL, s3Access: access, s3Secret: secret, rdb: rdb, st: st}
}

// TestIntegration_EnrollConnectRoundtrip exercises the full E2E path against the real assembled server +
// Valkey + MinIO + Pebble: two-phase enrollment (Pebble issues the public cert), the phone binds, and a
// frontend TLS session round-trips through the tunnel to the phone (which TLS-terminates with its
// Pebble-issued cert). It then asserts the MinIO registry + connection-log objects and the two lifecycle
// rules provisioned at startup.
func TestIntegration_EnrollConnectRoundtrip(t *testing.T) {
	env := startIntegrationServer(t)
	ctx := context.Background()

	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if ident.Name == "" || len(ident.PublicCertPEM) == 0 {
		t.Fatalf("enrollment must yield a name + public cert: name=%q pubcert=%d", ident.Name, len(ident.PublicCertPEM))
	}
	fqdn := ident.Name + "." + itTunnelDomain

	// The phone TLS-terminates each dial-back data stream with its Pebble-issued public cert and echoes.
	phoneTLS := phoneServerTLS(t, ident)
	backend := func(s io.ReadWriteCloser) {
		conn := tls.Server(&rwcConn{rwc: s}, phoneTLS)
		defer func() { _ = conn.Close() }()
		if err := conn.Handshake(); err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	}
	c, err := client.New(env.edgeAddr, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident, backend)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() { _ = c.Run(runCtx) }()

	// Once the phone binds, a frontend TLS roundtrip through the edge must succeed.
	var lastErr error
	if !waitBool(30*time.Second, func() bool {
		lastErr = frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots)
		return lastErr == nil
	}) {
		t.Fatalf("frontend TLS roundtrip never succeeded: %v", lastErr)
	}

	// MinIO: the name registry object carries the issued cert, and a connection-log object landed.
	rec, err := env.st.GetName(ctx, ident.Name)
	if err != nil || rec.CA == "" {
		t.Errorf("name record missing/incomplete in MinIO: %+v %v", rec, err)
	}
	if !waitBool(15*time.Second, func() bool {
		return len(tunneltest.S3ListKeys(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, "tunnel-logs/")) > 0
	}) {
		t.Error("no connection-log object written to MinIO")
	}

	// Both object-lifecycle rules were provisioned at startup.
	lc := tunneltest.S3LifecyclePrefixes(t, env.s3URL, env.s3Access, env.s3Secret, itBucket)
	if lc["tunnel-logs/"] != 90 || lc["rejected-enroll/"] != 30 {
		t.Errorf("lifecycle rules not applied (want tunnel-logs/=90, rejected-enroll/=30): %+v", lc)
	}

	// Renewal rotates the certs: inject a server-minted challenge nonce, trigger a renewal via the real
	// mTLS POST /issue (the Renew path, since a cert already exists), and assert the identity cert changes.
	oldIDCert := string(c.Identity().IdentityCertPEM)
	nonceHex := randomHex(t)
	if err := env.rdb.Set(ctx, "enroll-nonce:"+nonceHex, "1", 5*time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if err := c.Renew(ctx, nonceHex); err != nil {
		t.Fatalf("renewal via /issue failed: %v", err)
	}
	if string(c.Identity().IdentityCertPEM) == oldIDCert || len(c.Identity().PublicCertPEM) == 0 {
		t.Error("renewal must rotate the identity + public certs")
	}
}

func randomHex(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b[:])
}

// phoneServerTLS builds the phone's server-side TLS config from its Pebble-issued public cert + key.
func phoneServerTLS(t *testing.T, id *client.Identity) *tls.Config {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(id.PublicCertPEM, keyPEM)
	if err != nil {
		t.Fatalf("phone public keypair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// frontendRoundtrip dials the edge, does a full TLS handshake for fqdn (verifying against the Pebble
// issuing roots), and asserts an echo.
func frontendRoundtrip(edgeAddr, fqdn string, roots *x509.CertPool) error {
	raw, err := net.DialTimeout("tcp", edgeAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, &tls.Config{ServerName: fqdn, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	defer func() { _ = conn.Close() }()
	msg := []byte("e2e-roundtrip-hello")
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if string(buf) != string(msg) {
		return fmt.Errorf("echo mismatch: got %q", buf)
	}
	return nil
}

func waitBool(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// rwcConn adapts an io.ReadWriteCloser (a dial-back data stream) to net.Conn so the phone can wrap it in
// tls.Server. Addresses + deadlines are inert (the underlying HTTP/2 stream governs lifecycle).
type rwcConn struct{ rwc io.ReadWriteCloser }

func (c *rwcConn) Read(b []byte) (int, error)       { return c.rwc.Read(b) }
func (c *rwcConn) Write(b []byte) (int, error)      { return c.rwc.Write(b) }
func (c *rwcConn) Close() error                     { return c.rwc.Close() }
func (c *rwcConn) LocalAddr() net.Addr              { return tunnelAddr{} }
func (c *rwcConn) RemoteAddr() net.Addr             { return tunnelAddr{} }
func (c *rwcConn) SetDeadline(time.Time) error      { return nil }
func (c *rwcConn) SetReadDeadline(time.Time) error  { return nil }
func (c *rwcConn) SetWriteDeadline(time.Time) error { return nil }

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "tunnel" }
func (tunnelAddr) String() string  { return "tunnel" }

// TestIntegration_Registry exercises the durable name registry against REAL MinIO with the real enroll
// service (no full server / ACME needed): rejected-enrollment evidence, and the concurrent write-verify
// name-claim race (exactly one claimant wins a forced collision; the loser redraws to a distinct name).
func TestIntegration_Registry(t *testing.T) {
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	const bucket = "tunneld-registry"
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, bucket)
	st := newS3Store(t, s3URL, access, secret, bucket)

	t.Run("rejected-enrollment-evidence", func(t *testing.T) {
		svc := enroll.NewService(enroll.Config{
			RDB: newRedis(t, redisURL), CA: loadCA(t), Names: st, Evidence: st,
			Verifier: rejectVerifier{}, Issuer: stubIssuer{},
			TunnelDomain: itTunnelDomain, NameLength: 10, IssuePerWeek: 3,
			EnrollHour: 1000, EnrollMinute: 1000, ClaimTimeout: time.Second, ClaimSettle: 2 * time.Second,
		})
		nonce, err := svc.Nonce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		chain, chainPEM := dummyAttChain(t)
		_, ee := svc.Enroll(context.Background(), "9.9.9.9", enroll.Request{
			Nonce: nonce, AttestChainPEM: chainPEM, AttestChain: chain, IdentityCSR: identityCSR(t),
		})
		if ee == nil || ee.Reason != "unauthorized" {
			t.Fatalf("attestation-required enrollment must be rejected: %v", ee)
		}
		if !waitBool(10*time.Second, func() bool {
			return len(tunneltest.S3ListKeys(t, s3URL, access, secret, bucket, "rejected-enroll/")) > 0
		}) {
			t.Error("rejected-enrollment evidence object not written to MinIO")
		}
	})

	t.Run("concurrent-claim-one-winner", func(t *testing.T) {
		const fixed = "collide23456"
		svc := enroll.NewService(enroll.Config{
			RDB: newRedis(t, redisURL), CA: loadCA(t), Names: st, Evidence: st,
			Verifier: stubVerifier{}, Issuer: stubIssuer{}, AttestOptional: true,
			TunnelDomain: itTunnelDomain, NameLength: 12, IssuePerWeek: 3,
			EnrollHour: 1000, EnrollMinute: 1000,
			ClaimTimeout: 200 * time.Millisecond, ClaimSettle: 600 * time.Millisecond,
		})
		var mu sync.Mutex
		calls := 0
		// The first candidate of each racer is the SAME name (forced collision); a loser redraws random.
		svc.SetNameGen(func() (string, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if calls <= 2 {
				return fixed, nil
			}
			return ca.GenerateName("", 12)
		})

		type result struct {
			name string
			err  *enroll.Error
		}
		csrs := []*x509.CertificateRequest{identityCSR(t), identityCSR(t)}
		out := make(chan result, 2)
		for i := 0; i < 2; i++ {
			csr := csrs[i]
			go func() {
				nonce, nerr := svc.Nonce(context.Background())
				if nerr != nil {
					out <- result{err: &enroll.Error{Reason: "nonce"}}
					return
				}
				r, ee := svc.Enroll(context.Background(), "3.3.3.3", enroll.Request{Nonce: nonce, IdentityCSR: csr})
				out <- result{name: r.Name, err: ee}
			}()
		}
		a, b := <-out, <-out
		if a.err != nil || b.err != nil {
			t.Fatalf("both enrollments should succeed: %v / %v", a.err, b.err)
		}
		if a.name == b.name {
			t.Fatalf("racers must end with distinct names, both got %q", a.name)
		}
		fixedWinners := 0
		for _, n := range []string{a.name, b.name} {
			if n == fixed {
				fixedWinners++
			}
			if _, err := st.GetName(context.Background(), n); err != nil {
				t.Errorf("claimed name %q missing its registry object: %v", n, err)
			}
		}
		if fixedWinners != 1 {
			t.Errorf("exactly one racer must win the collided name %q, got %d", fixed, fixedWinners)
		}
	})
}

func newRedis(t *testing.T, url string) *redis.Client {
	t.Helper()
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	c := redis.NewClient(opts)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newS3Store(t *testing.T, url, access, secret, bucket string) *store.S3Store {
	t.Helper()
	st, err := store.NewS3Store(context.Background(), store.S3Config{
		Endpoint: url, Region: "us-east-1", Bucket: bucket, AccessKey: access, SecretKey: secret, ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func loadCA(t *testing.T) *ca.CA {
	t.Helper()
	certPath, keyPath := writeCA(t)
	c, err := ca.Load(certPath, keyPath, 4380*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func identityCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "phone"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	return csr
}

func dummyAttChain(t *testing.T) ([]*x509.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "att"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return []*x509.Certificate{c}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type rejectVerifier struct{}

func (rejectVerifier) Verify(_ []*x509.Certificate, _ []byte, _ time.Time) (attest.Result, error) {
	return attest.Result{}, attest.ErrChainUntrusted
}

type stubVerifier struct{}

func (stubVerifier) Verify(_ []*x509.Certificate, _ []byte, _ time.Time) (attest.Result, error) {
	return attest.Result{}, nil
}

type stubIssuer struct{}

func (stubIssuer) Obtain(context.Context, *x509.CertificateRequest, string) ([]byte, store.CertInfo, error) {
	return []byte("cert"), store.CertInfo{CA: "letsencrypt"}, nil
}

func (stubIssuer) Renew(context.Context, *x509.CertificateRequest, string, store.CertInfo) ([]byte, store.CertInfo, error) {
	return []byte("cert"), store.CertInfo{CA: "letsencrypt"}, nil
}
