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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// TestIntegration_DrainWritesShutdownEndEvents holds a LIVE public splice open across a server drain and
// asserts its close_reason=server-shutdown end event lands in MinIO — the ordered drain (join public
// handlers → flush the async conn-log queue) must not lose it.
func TestIntegration_DrainWritesShutdownEndEvents(t *testing.T) {
	env := startIntegrationServer(t)
	ctx := context.Background()

	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	fqdn := ident.Name + "." + itTunnelDomain

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

	// Wait for the phone to bind, then open a LIVE public splice and keep it open across the drain.
	if !waitBool(30*time.Second, func() bool {
		return frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots) == nil
	}) {
		t.Fatal("frontend roundtrip never succeeded (phone never bound)")
	}
	live := dialFrontend(t, env.edgeAddr, fqdn, env.pebble.IssuingRoots)
	defer func() { _ = live.Close() }()
	// One echo confirms a real public splice exists at drain time.
	if _, err := live.Write([]byte("live")); err != nil {
		t.Fatalf("live write: %v", err)
	}
	if _, err := io.ReadFull(live, make([]byte, 4)); err != nil {
		t.Fatalf("live echo: %v", err)
	}

	// Drain: cancel Run and wait for it to return. The ordered drain must enqueue the public splice's
	// server-shutdown end event AND flush the async conn-log queue before Run returns.
	if err := env.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}

	found := waitBool(15*time.Second, func() bool {
		for _, k := range tunneltest.S3ListKeys(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, "tunnel-logs/"+ident.Name+"/") {
			if !strings.HasSuffix(k, "-end.json") {
				continue
			}
			var ev store.Event
			if err := json.Unmarshal(s3GetObject(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, k), &ev); err != nil {
				continue
			}
			if ev.Type == "public" && ev.CloseReason == store.CloseServerShutdown {
				return true
			}
		}
		return false
	})
	if !found {
		t.Fatal("drain did not write a public close_reason=server-shutdown end event to MinIO")
	}
}

// TestIntegration_MeshListenFailureClosesRawListener pre-occupies the mesh port so the mesh bind (the last
// construction step) fails, and asserts Run errors AND the raw :443 listener was closed on that error, so
// cfg.Listen is immediately rebindable (no leaked bound-but-unserved socket).
func TestIntegration_MeshListenFailureClosesRawListener(t *testing.T) {
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, itBucket)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	meshAddr := occupied.Addr().String()
	edgeAddr := freeAddr(t)

	// Unreachable ACME (port 1).
	cfg := itServeConfig(t, redisURL, s3URL, access, secret, edgeAddr, meshAddr,
		"https://127.0.0.1:1/dir", "https://127.0.0.1:1/dir", "https://127.0.0.1:1/dir", nil)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, cfg, testLogger(), "it-mesh") }()

	select {
	case runErr := <-errCh:
		if runErr == nil {
			t.Fatal("Run must fail when the mesh port is already bound")
		}
		if !strings.Contains(runErr.Error(), "mesh listen") {
			t.Fatalf("expected a mesh-listen failure, got %v", runErr)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("Run did not return after the mesh-bind failure")
	}

	// The raw listener must have been closed on the construction error — cfg.Listen is rebindable now.
	reln, err := net.Listen("tcp", edgeAddr)
	if err != nil {
		t.Fatalf("cfg.Listen must be rebindable after a failed startup (raw listener leaked): %v", err)
	}
	_ = reln.Close()
}

func startPendingIssuanceServer(t *testing.T, mutate ...func(*config.ServeCmd)) (config.ServeCmd, *hangACMEListener, func()) {
	t.Helper()
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, itBucket)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")

	hang := newHangACMEListener(t)
	cfg := itServeConfig(t, redisURL, s3URL, access, secret, freeAddr(t), freeAddr(t),
		hang.url(), hang.url(), hang.url(), nil)
	for _, m := range mutate {
		m(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, testLogger(), "it-pending") }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			hang.release()
			select {
			case <-done:
			case <-time.After(90 * time.Second):
				t.Error("Run did not return after cancellation")
			}
		})
	}
	t.Cleanup(stop)

	if !waitBool(5*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", cfg.Listen, 500*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}) {
		t.Fatal(":443 must accept TCP while reserved-host issuance is still pending")
	}
	return cfg, hang, stop
}

func TestIntegration_ListenersServeWhileReservedIssuancePending(t *testing.T) {
	cfg, _, stop := startPendingIssuanceServer(t)

	raw, err := net.DialTimeout("tcp", cfg.Listen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: "unrouted.other.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err == nil {
		t.Fatal("an unrouted SNI must be closed, not served")
	}
	_ = raw.Close()
	if v, met, err := waitMetric(10*time.Second, cfg.InternalListen, `tunneld_rejections_total{reason="no-route"}`,
		func(v float64) bool { return v >= 1 }); !met {
		t.Fatalf("an unrouted SNI must be recorded as no-route (no-route = %v, last scrape error: %v)", v, err)
	}

	if tunneltest.ServesCertificate(cfg.Listen, itEnrollHost) || tunneltest.ServesCertificate(cfg.Listen, itControlHost) {
		t.Fatal("reserved hosts must present no certificate while their issuance is pending")
	}
	stop()
}

func TestIntegration_ReservedCacheServedWhileIssuancePending(t *testing.T) {
	now := time.Now()
	leaves := map[string][]byte{}
	cfg, hang, stop := startPendingIssuanceServer(t, func(c *config.ServeCmd) {
		for _, host := range []string{itEnrollHost, itControlHost} {
			leaves[host] = writeReservedBundle(t, c.ACMEAccountDir, host, now.Add(-150*time.Hour), now.Add(10*time.Hour))
		}
	})
	if !waitBool(30*time.Second, func() bool { return hang.held() > 0 }) {
		t.Fatal("the renewal of the due cache never reached the (hanging) ACME directory")
	}
	for _, host := range []string{itEnrollHost, itControlHost} {
		leaf := presentedLeaf(t, cfg.Listen, host)
		if string(leaf) != string(leaves[host]) {
			t.Fatalf("%s: the cached certificate must be served while its renewal is pending", host)
		}
	}
	stop()
}

func TestIntegration_ACMEHTTPListenerOnlyWhenUsed(t *testing.T) {
	cfg, _, stop := startPendingIssuanceServer(t, func(c *config.ServeCmd) { c.ACMEHTTPListen = freeAddr(t) })
	if c, err := net.DialTimeout("tcp", cfg.ACMEHTTPListen, 2*time.Second); err == nil {
		_ = c.Close()
		t.Fatal("the HTTP-01 listener must not be bound when no CA uses http-01")
	}
	stop()
}

func writeReservedBundle(t *testing.T, accountDir, host string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rc := &reservedCerts{dir: filepath.Join(accountDir, "self"), logger: testLogger(), now: time.Now}
	rc.persist(host,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		store.CertInfo{NotBefore: notBefore, NotAfter: notAfter})
	return der
}

func presentedLeaf(t *testing.T, edgeAddr, host string) []byte {
	t.Helper()
	var leaf []byte
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", edgeAddr, &tls.Config{
		ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				leaf = cs.PeerCertificates[0].Raw
			}
			return nil
		},
	})
	if err == nil {
		if cerr := conn.Close(); cerr != nil {
			t.Logf("%s: close the probe connection: %v", host, cerr)
		}
	}
	if leaf == nil {
		t.Fatalf("%s presented no certificate (dial: %v)", host, err)
	}
	return leaf
}

func metricLineValue(internalAddr, series string) (float64, error) {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + internalAddr + "/metrics")
	if err != nil {
		return 0, err
	}
	body, err := io.ReadAll(resp.Body)
	if err := errors.Join(err, resp.Body.Close()); err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("metrics status %d", resp.StatusCode)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, series+" ") {
			return strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, series)), 64)
		}
	}
	return 0, nil
}

func waitMetric(d time.Duration, internalAddr, series string, cond func(float64) bool) (float64, bool, error) {
	var v float64
	var err error
	met := waitBool(d, func() bool {
		v, err = metricLineValue(internalAddr, series)
		return err == nil && cond(v)
	})
	return v, met, err
}

// dialFrontend opens a frontend TLS connection to the edge for fqdn (verified against roots) and returns
// it OPEN (the caller keeps the public splice live).
func dialFrontend(t *testing.T, edgeAddr, fqdn string, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", edgeAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: fqdn, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		t.Fatalf("frontend handshake: %v", err)
	}
	return conn
}

// s3GetObject fetches one object's bytes from MinIO (test assertions on connection-log content).
func s3GetObject(t *testing.T, endpoint, access, secret, bucket, key string) []byte {
	t.Helper()
	cli := s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(access, secret, ""),
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
	})
	out, err := cli.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("get object %q: %v", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	b, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("read object %q: %v", key, err)
	}
	return b
}

// hangACMEListener accepts TCP connections and holds them without responding, so an ACME directory fetch
// pointed at it blocks in its TLS handshake.
// release() closes the listener and every held connection, letting the fetch fail fast.
type hangACMEListener struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	done  bool
}

func newHangACMEListener(t *testing.T) *hangACMEListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &hangACMEListener{ln: ln}
	go h.accept()
	return h
}

func (h *hangACMEListener) accept() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		if h.done {
			h.mu.Unlock()
			_ = c.Close()
			continue
		}
		h.conns = append(h.conns, c) // hold open, never respond → the dialer's TLS handshake blocks
		h.mu.Unlock()
	}
}

func (h *hangACMEListener) url() string { return "https://" + h.ln.Addr().String() + "/dir" }

func (h *hangACMEListener) held() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

func (h *hangACMEListener) release() {
	h.mu.Lock()
	if h.done {
		h.mu.Unlock()
		return
	}
	h.done = true
	conns := h.conns
	h.conns = nil
	h.mu.Unlock()
	_ = h.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}
