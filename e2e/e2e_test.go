//go:build e2e

// Package e2e is the end-to-end tier: it runs TWO real tunneld replicas (in-process server.Run instances
// sharing one testcontainers Valkey + MinIO + Pebble/challtestsrv), a raw-TLS frontend connecting
// directly to a replica's :443, and the reference phone client. It exercises the cross-node mesh path,
// the same-node fast path, per-tunnel quota exhaustion, and ACME CA spillover. No proxy anywhere.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/server"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const (
	e2eTunnelDomain = "example.test"
	e2eEnrollHost   = "enroll.example.test"
	e2eControlHost  = "connect.example.test"
	e2eBucket       = "tunneld-e2e"
)

// e2eInfra is the shared testcontainers infrastructure for a set of replicas.
type e2eInfra struct {
	redisURL string
	s3URL    string
	access   string
	secret   string
	pebble   *tunneltest.PebbleEnv
	caCert   string
	caKey    string
	internal map[string]string // edge address → that replica's internal (metrics/healthz) address
}

func startE2EInfra(t *testing.T) *e2eInfra {
	t.Helper()
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, e2eBucket)
	pebble := tunneltest.StartPebble(t)
	shim := tunneltest.StartACMEDNSShim(t, pebble)
	t.Setenv("HTTPREQ_ENDPOINT", shim)
	t.Setenv("LEGO_CA_CERTIFICATES", pebble.MinicaFile)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")
	caCert, caKey := writeCA(t)
	return &e2eInfra{redisURL: redisURL, s3URL: s3URL, access: access, secret: secret, pebble: pebble, caCert: caCert, caKey: caKey, internal: map[string]string{}}
}

// replicaOpts tweaks a replica's config for a specific scenario.
type replicaOpts struct {
	acmeDirLE  string // override the LE directory (for spillover); empty = Pebble
	trafficDay string // override --limit-traffic-day; empty = 1gb
	concurrent int    // override --limit-concurrent; 0 = 8
}

// startReplica runs a real server.Run on loopback against the shared infra and returns its public edge
// address. It waits until the replica is serving (internal /healthz is 200). freeAddr probes-and-closes
// ports, so server.Run's bind can lose a race to another process — and the internal-listener bind is now
// fatal — so a boot that exits before serving is retried with fresh ports (bounded).
func (inf *e2eInfra) startReplica(t *testing.T, opts replicaOpts) string {
	t.Helper()
	for range 5 {
		if addr, ok := inf.runReplicaOnce(t, opts); ok {
			return addr
		}
	}
	t.Fatal("startReplica: replica never bound its listeners after 5 attempts (port races)")
	return ""
}

// runReplicaOnce attempts one replica boot on fresh freeAddr ports. It returns (edgeAddr, true) once the
// replica is serving, or ("", false) when server.Run exits before becoming ready (a freeAddr port race —
// the caller retries with fresh ports).
func (inf *e2eInfra) runReplicaOnce(t *testing.T, opts replicaOpts) (string, bool) {
	t.Helper()
	edgeAddr := freeAddr(t)
	meshAddr := freeAddr(t)
	internalAddr := freeAddr(t)

	leDir := inf.pebble.DirectoryURL
	if opts.acmeDirLE != "" {
		leDir = opts.acmeDirLE
	}
	trafficDay := "1gb"
	if opts.trafficDay != "" {
		trafficDay = opts.trafficDay
	}
	concurrent := 8
	if opts.concurrent != 0 {
		concurrent = opts.concurrent
	}

	cfg := config.ServeCmd{
		RedisURL: inf.redisURL, Listen: edgeAddr, MeshListen: meshAddr, InternalListen: internalAddr,
		MeshAdvertise: meshAddr, MeshPoolSize: 4, MeshCertTTL: 24 * time.Hour,
		TunnelDomain: e2eTunnelDomain, EnrollHost: e2eEnrollHost, ControlHost: e2eControlHost, NameLength: 10,
		CACert: inf.caCert, CAKey: inf.caKey, CertValidity: 4380 * time.Hour,
		S3Endpoint: inf.s3URL, S3Region: "us-east-1", S3Bucket: e2eBucket,
		S3AccessKey: inf.access, S3SecretKey: inf.secret, S3ForcePathStyle: true,
		RegistryClaimTimeout: 3 * time.Second, RegistryClaimSettle: 5 * time.Second,
		AttestSignerDigestFile: emptyFile(t),
		AttestRootURL:          "http://127.0.0.1:1/root", AttestStatusURL: "http://127.0.0.1:1/status",
		AttestRefresh: time.Hour, AttestStatusMaxStale: 24 * time.Hour, AttestationOptional: true,
		ACMEDirLE: leDir, ACMEDirGTS: inf.pebble.DirectoryURL, ACMEDirZeroSSL: inf.pebble.DirectoryURL,
		ACMEEmail: "ops@example.test", ACMELEProfile: "shortlived", ACMEGTSValidity: 168 * time.Hour,
		ACMEAccountDir: t.TempDir(), ACMEDNSProvider: "httpreq",
		ACMEDNSResolvers: []string{inf.pebble.DNSResolver}, ACMEDNSSkipPropagationCheck: true,
		ACMECooldownDefault: time.Second, ACMEBackoffInitial: time.Second, ACMEBackoffMax: 5 * time.Second,
		ACMERenewMargin: 48 * time.Hour, IssuePerWeek: 10,
		RouteTTL: 30 * time.Second, ControlPingInterval: 30 * time.Second,
		LimitStreamPending: 64, LimitEnrollHour: 1000, LimitEnrollMinute: 1000, LimitEnrollBody: "64kb",
		MaxClients: 100, LimitConnRate: 1000, LimitConcurrent: concurrent, HandshakeTimeout: 5 * time.Second, LimitDialBackTimeout: 10 * time.Second,
		LimitConnIdle: 120 * time.Second, LimitConnMinGrace: 60 * time.Second, LimitConnEvictIdle: 1 * time.Second,
		LimitConnMinRate: "1kb", LimitConnProtectRate: "1mb", LimitBandwidth: "10mbit",
		LimitTrafficDay: trafficDay, LimitTrafficWeek: "4gb",
		BanPoll: time.Second, ShutdownGrace: 3 * time.Second, Log: []string{"output=std;level=error"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, cfg, discardLogger(), "e2e") }()

	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			cancel() // Run exited before serving (freeAddr port race) — retry with fresh ports
			return "", false
		default:
		}
		if healthOK(internalAddr) {
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
					t.Error("replica did not drain within 20s")
				}
			})
			inf.internal[edgeAddr] = internalAddr
			return edgeAddr, true
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("replica never became ready (reserved-host cert obtain may have failed)")
	return "", false
}

// echoPhone enrolls a tunnel via enrollAddr, connects the phone control to controlAddr, and serves an
// echoing TLS-terminating backend. It returns the identity (for the frontend to derive the SNI + trust).
func echoPhone(t *testing.T, inf *e2eInfra, enrollAddr, controlAddr string) *client.Identity {
	t.Helper()
	ctx := context.Background()
	ident, err := client.Enroll(ctx, enrollAddr, e2eEnrollHost, e2eControlHost, e2eTunnelDomain, inf.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	phoneTLS := phoneServerTLS(t, ident)
	backend := func(s io.ReadWriteCloser) {
		conn := tls.Server(&rwcConn{rwc: s}, phoneTLS)
		defer func() { _ = conn.Close() }()
		if err := conn.Handshake(); err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	}
	c, err := client.New(controlAddr, e2eControlHost, e2eTunnelDomain, inf.pebble.IssuingRoots, ident, backend)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() { _ = c.Run(runCtx); close(runDone) }()
	// Close honors its "call once Run has returned" contract: cancel, JOIN Run, then Close (no leaked
	// control transport, no Close-before-Run-return).
	t.Cleanup(func() {
		cancel()
		<-runDone
		c.Close()
	})
	return ident
}

// TestE2E_CrossNodeAndFastPath enrolls one tunnel, binds it on replica B, and proves both the cross-node
// mesh path (frontend on A → owner B) and the same-node fast path (entering at the owner replica B) work.
// The phone stays bound to B throughout; no route rebinding occurs.
func TestE2E_CrossNodeAndFastPath(t *testing.T) {
	inf := startE2EInfra(t)
	edgeA := inf.startReplica(t, replicaOpts{})
	edgeB := inf.startReplica(t, replicaOpts{})

	// Enroll via A, but run the phone's control connection on B → B owns the route.
	ident := echoPhone(t, inf, edgeA, edgeB)
	fqdn := ident.Name + "." + e2eTunnelDomain

	// Cross-node: the frontend hits A; A meshes to the owner B.
	var lastErr error
	if !waitBool(30*time.Second, func() bool {
		lastErr = frontendRoundtrip(edgeA, fqdn, inf.pebble.IssuingRoots)
		return lastErr == nil
	}) {
		t.Fatalf("cross-node mesh roundtrip never succeeded: %v", lastErr)
	}

	// Fast path: the frontend hits B directly (owner == entry).
	if !waitBool(15*time.Second, func() bool {
		lastErr = frontendRoundtrip(edgeB, fqdn, inf.pebble.IssuingRoots)
		return lastErr == nil
	}) {
		t.Fatalf("same-node fast-path roundtrip never succeeded: %v", lastErr)
	}
}

// TestE2E_Spillover forces the LE directory unreachable so the ACME chain spills to GTS (the Pebble test
// CA): the issued public cert must come from the fallback CA.
func TestE2E_Spillover(t *testing.T) {
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, replicaOpts{acmeDirLE: "https://127.0.0.1:1/dir"})

	ident, err := client.Enroll(context.Background(), edge, e2eEnrollHost, e2eControlHost, e2eTunnelDomain, inf.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll (spillover): %v", err)
	}
	if ident.CA != "gts" {
		t.Fatalf("primary LE unreachable must spill to GTS, got CA=%q", ident.CA)
	}
}

// TestE2E_Quota drives more traffic than the per-tunnel day cap allows; the edge must cut the stream
// (the full echo cannot complete).
func TestE2E_Quota(t *testing.T) {
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, replicaOpts{trafficDay: "48kb"})
	ident := echoPhone(t, inf, edge, edge)
	fqdn := ident.Name + "." + e2eTunnelDomain

	// Wait for bind (a small roundtrip succeeds), then exceed the cap.
	if !waitBool(30*time.Second, func() bool { return frontendRoundtrip(edge, fqdn, inf.pebble.IssuingRoots) == nil }) {
		t.Fatal("initial roundtrip never succeeded")
	}
	if err := frontendTransfer(edge, fqdn, inf.pebble.IssuingRoots, 256*1024); err == nil {
		t.Fatal("a transfer well past --limit-traffic-day must be cut by the quota, but it completed")
	}
	if !waitBool(10*time.Second, func() bool {
		return metricCounterPositive(inf.internal[edge], "tunneld_quota_exhausted_total")
	}) {
		t.Fatal("the cut must be attributed to the quota (tunneld_quota_exhausted_total)")
	}
}

// TestE2E_Eviction fills a tunnel's concurrent-stream cap with idle connections, then opens one more:
// the edge must evict a least-active (idle) stream so the new connection succeeds.
func TestE2E_Eviction(t *testing.T) {
	inf := startE2EInfra(t)
	edge := inf.startReplica(t, replicaOpts{concurrent: 2})
	ident := echoPhone(t, inf, edge, edge)
	fqdn := ident.Name + "." + e2eTunnelDomain

	if !waitBool(30*time.Second, func() bool { return frontendRoundtrip(edge, fqdn, inf.pebble.IssuingRoots) == nil }) {
		t.Fatal("initial roundtrip never succeeded")
	}

	// Fill the concurrency cap (2) with idle, handshaked connections.
	c1, err := dialTunnelTLS(edge, fqdn, inf.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("c1: %v", err)
	}
	defer func() { _ = c1.Close() }()
	c2, err := dialTunnelTLS(edge, fqdn, inf.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("c2: %v", err)
	}
	defer func() { _ = c2.Close() }()

	// A third connection must succeed by evicting a least-active idle stream (rolling rate 0 < protect).
	var c3 *tls.Conn
	if !waitBool(15*time.Second, func() bool {
		c3, err = dialTunnelTLS(edge, fqdn, inf.pebble.IssuingRoots)
		if err != nil {
			return false
		}
		if eerr := echoOn(c3); eerr != nil {
			_ = c3.Close() // a leaked conn would join the eviction population under test
			err = eerr
			return false
		}
		return true
	}) {
		t.Fatalf("the over-cap connection must evict an idle stream and round-trip: %v", err)
	}
	_ = c3.Close()

	// The over-cap admission must have EVICTED one of the two idle victims (not silently admitted a
	// third): exactly one of c1/c2 must observe its socket closed by the edge. If the concurrency cap
	// were unenforced, both would stay open and this assertion would fail.
	isEvicted := func(c *tls.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, rerr := c.Read(make([]byte, 1))
		if rerr == nil {
			return false // read data on an idle conn → not the evicted victim
		}
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			return false // read deadline hit on a still-open idle conn → not evicted
		}
		return true // EOF / reset → the edge closed this (evicted) victim
	}
	evicted := 0
	if isEvicted(c1) {
		evicted++
	}
	if isEvicted(c2) {
		evicted++
	}
	if evicted != 1 {
		t.Fatalf("exactly one of c1/c2 must be evicted by the over-cap admission, got %d", evicted)
	}
}

// --- helpers ---

func echoOn(conn *tls.Conn) error {
	msg := []byte("evict-check")
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != string(msg) {
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
}

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

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func writeCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tunneld-e2e-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "ca-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func phoneServerTLS(t *testing.T, id *client.Identity) *tls.Config {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(id.PublicCertKey)
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

// metricCounterPositive GETs the replica's internal /metrics and reports whether any exposition line for
// the given counter family carries a value > 0 (i.e. the counter fired at least once).
func metricCounterPositive(internalAddr, family string) bool {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + internalAddr + "/metrics")
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, family) {
			continue
		}
		// The family name must be followed by a label set or a space — not by more name characters
		// (skip prefix-sharing families such as <family>_created).
		rest := line[len(family):]
		if rest != "" && rest[0] != ' ' && rest[0] != '{' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil && v > 0 {
			return true
		}
	}
	return false
}

func healthOK(internalAddr string) bool {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + internalAddr + "/healthz")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func frontendRoundtrip(edgeAddr, fqdn string, roots *x509.CertPool) error {
	conn, err := dialTunnelTLS(edgeAddr, fqdn, roots)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	msg := []byte("e2e-hello")
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	if string(buf) != string(msg) {
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
}

// frontendTransfer writes n bytes and tries to read them all back; it returns an error if the full echo
// does not complete (e.g. the quota cut the stream).
func frontendTransfer(edgeAddr, fqdn string, roots *x509.CertPool, n int) error {
	conn, err := dialTunnelTLS(edgeAddr, fqdn, roots)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	payload := make([]byte, n)
	done := make(chan error, 1)
	go func() {
		_, werr := conn.Write(payload)
		done <- werr
	}()
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read %d bytes: %w", n, err)
	}
	return <-done
}

func dialTunnelTLS(edgeAddr, fqdn string, roots *x509.CertPool) (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", edgeAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn := tls.Client(raw, &tls.Config{ServerName: fqdn, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return conn, nil
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
