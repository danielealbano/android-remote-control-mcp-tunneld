//go:build integration

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
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

	// Unreachable ACME (port 1) → the reserved-cert obtain fails fast and starts degraded, so construction
	// still reaches the listener binds.
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

// TestIntegration_StartupBindsAfterConstruction points all three ACME directory URLs at an in-process
// accept-and-hang listener, so the reserved-cert obtain (a construction step) blocks. A dial to :443 at
// +500 ms MUST be connection-refused (nothing bound while construction is in flight); cancelling +
// releasing the hang then lets construction finish and Run return.
func TestIntegration_StartupBindsAfterConstruction(t *testing.T) {
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, itBucket)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")

	hang := newHangACMEListener(t)
	defer hang.release()
	edgeAddr := freeAddr(t)

	cfg := itServeConfig(t, redisURL, s3URL, access, secret, edgeAddr, freeAddr(t),
		hang.url(), hang.url(), hang.url(), nil)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, testLogger(), "it-bind") }()

	// +500 ms: construction is still blocked on the reserved-cert ACME obtain (the directory fetch is held
	// by the hang listener), so NOTHING is bound — a dial to :443 MUST be connection-refused.
	time.Sleep(500 * time.Millisecond)
	probe, derr := net.DialTimeout("tcp", edgeAddr, 500*time.Millisecond)
	if derr == nil {
		_ = probe.Close()
		cancel()
		hang.release()
		<-done
		t.Fatal(":443 was bound while reserved-cert construction was still in flight")
	}
	if !errors.Is(derr, syscall.ECONNREFUSED) {
		cancel()
		hang.release()
		<-done
		t.Fatalf("pre-construction dial to :443 must be connection-refused, got %v", derr)
	}

	// Cancel + release the hang: the ACME obtain fails fast, construction finishes, and because ctx is
	// already cancelled Run drains and returns.
	cancel()
	hang.release()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
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
// pointed at it blocks in its TLS handshake — keeping server construction deliberately in flight.
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
