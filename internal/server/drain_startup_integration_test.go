//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// TestIntegration_DrainWritesShutdownEndEvents holds a LIVE public splice open across a server drain and
// asserts its close_reason=server-shutdown end event lands in MinIO — joining the public handlers
// and flushing the async conn-log queue must not lose it.
func TestIntegration_DrainWritesShutdownEndEvents(t *testing.T) {
	env := startIntegrationServer(t, func(c *config.ServeCmd) { c.LimitConnIdle = 3 * time.Second })
	ctx := context.Background()

	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	fqdn := ident.Name + "." + itTunnelDomain

	phoneTLS := phoneServerTLS(t, ident)
	backend := func(_ string, s io.ReadWriteCloser) {
		conn := tls.Server(&rwcConn{rwc: s}, phoneTLS)
		defer tunneltest.CloseLogged(conn)
		if err := conn.Handshake(); err != nil {
			testLogger().Warn("echo phone handshake failed", "err", err)
			return
		}
		if _, err := io.Copy(conn, conn); err != nil {
			testLogger().Debug("echo phone stream ended with an error", "err", err)
		}
	}
	c, err := client.New(env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident, backend)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() {
		if err := c.Run(runCtx); err != nil && runCtx.Err() == nil {
			testLogger().Warn("tunnel client run failed", "err", err)
		}
	}()

	// Wait for the phone to bind, then open a LIVE public splice and keep it open across the drain.
	var rtErr error
	if !waitBool(30*time.Second, func() bool {
		rtErr = frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots)
		return rtErr == nil
	}) {
		t.Fatalf("frontend roundtrip never succeeded (phone never bound): %v", rtErr)
	}
	live := dialFrontend(t, env.edgeAddr, fqdn, env.pebble.IssuingRoots)
	defer tunneltest.CloseOrLog(t, live)
	// One echo confirms a real public splice exists at drain time.
	if _, err := live.Write([]byte("live")); err != nil {
		t.Fatalf("live write: %v", err)
	}
	if _, err := io.ReadFull(live, make([]byte, 4)); err != nil {
		t.Fatalf("live echo: %v", err)
	}
	defer keepSpliceBusy(live).close()

	// Drain: cancel Run and wait for it to return. It must enqueue the public splice's
	// server-shutdown end event AND flush the async conn-log queue before Run returns.
	if err := env.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}

	found := waitBool(15*time.Second, func() bool {
		for _, k := range tunneltest.S3ListKeys(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, "tunnel-logs/") {
			if !strings.HasSuffix(k, ".jsonl") {
				continue
			}
			for _, line := range bytes.Split(bytes.TrimSpace(s3GetObject(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, k)), []byte("\n")) {
				var ev store.Event
				if err := json.Unmarshal(line, &ev); err != nil {
					t.Fatalf("connection log %s has an invalid JSON line: %v", k, err)
				}
				if ev.Tunnel == ident.Name && ev.Event == "end" && ev.Type == "public" && ev.CloseReason == store.CloseServerShutdown {
					return true
				}
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
	defer tunneltest.CloseOrLog(t, occupied)
	meshAddr := occupied.Addr().String()
	edgeAddr := tunneltest.FreeAddr(t)

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
	tunneltest.CloseOrLog(t, reln)
}

func startPendingIssuanceServer(t *testing.T, mutate ...func(*config.ServeCmd)) (config.ServeCmd, *hangACMEListener, func()) {
	t.Helper()
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, itBucket)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")

	hang := newHangACMEListener(t)
	cfg := itServeConfig(t, redisURL, s3URL, access, secret, tunneltest.FreeAddr(t), tunneltest.FreeAddr(t),
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
			case err := <-done:
				if err != nil {
					t.Errorf("Run: %v", err)
				}
			case <-time.After(90 * time.Second):
				t.Error("Run did not return after cancellation")
			}
		})
	}
	t.Cleanup(stop)

	var dialErr error
	if !waitBool(5*time.Second, func() bool {
		var c net.Conn
		c, dialErr = net.DialTimeout("tcp", cfg.Listen, 500*time.Millisecond)
		if dialErr != nil {
			return false
		}
		tunneltest.CloseOrLog(t, c)
		return true
	}) {
		t.Fatalf(":443 must accept TCP while reserved-host issuance is still pending (last dial error: %v)", dialErr)
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
	tunneltest.CloseOrLog(t, raw)
	if v, met, err := waitMetric(10*time.Second, cfg.InternalListen, `tunneld_rejections_total{reason="no-route"}`,
		func(v float64) bool { return v >= 1 }); !met {
		t.Fatalf("an unrouted SNI must be recorded as no-route (no-route = %v, last scrape error: %v)", v, err)
	}

	for _, host := range []string{itEnrollHost, itControlHost} {
		if ok, err := tunneltest.ServesCertificate(t, cfg.Listen, host); ok || err == nil {
			t.Fatalf("%s must present no certificate while its issuance is pending (presented=%v, probe error=%v)", host, ok, err)
		}
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
	t.Run("not bound without http-01 or plain dial-backs", func(t *testing.T) {
		cfg, _, stop := startPendingIssuanceServer(t, func(c *config.ServeCmd) { c.ACMEHTTPListen = tunneltest.FreeAddr(t) })
		if c, err := net.DialTimeout("tcp", cfg.ACMEHTTPListen, 2*time.Second); err == nil {
			tunneltest.CloseOrLog(t, c)
			t.Fatal("the HTTP-01 listener must not be bound when no CA uses http-01")
		}
		stop()
	})
	t.Run("bound for plain dial-backs", func(t *testing.T) {
		cfg, _, stop := startPendingIssuanceServer(t, func(c *config.ServeCmd) {
			c.ACMEHTTPListen = tunneltest.FreeAddr(t)
			c.DialBackHTTPS, c.DialBackMTLS = false, false
		})
		hc := &http.Client{Timeout: 5 * time.Second}
		get := func(path string) int {
			t.Helper()
			resp, err := hc.Get("http://" + cfg.ACMEHTTPListen + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			tunneltest.CloseOrLog(t, resp.Body)
			return resp.StatusCode
		}
		if code := get("/api/v1/data"); code != http.StatusBadRequest {
			t.Fatalf("GET /api/v1/data without an upgrade = %d, want 400 from the phone handler", code)
		}
		if v, err := metricLineValue(cfg.InternalListen, `tunneld_rejections_total{reason="acme-http-miss"}`); err != nil || v != 0 {
			t.Fatalf("a dial-back request must not count as acme-http-miss (value %v, scrape error %v)", v, err)
		}
		if code := get("/.well-known/acme-challenge/unknown-token-0123456789"); code != http.StatusNotFound {
			t.Fatalf("an unknown ACME challenge = %d, want 404", code)
		}
		if v, met, err := waitMetric(10*time.Second, cfg.InternalListen, `tunneld_rejections_total{reason="acme-http-miss"}`,
			func(v float64) bool { return v == 1 }); !met {
			t.Fatalf("the ACME path must keep recording acme-http-miss (value %v, scrape error %v)", v, err)
		}
		stop()
	})
}

func TestIntegration_DrainBoundedWithUnreachablePeer(t *testing.T) {
	var grace, drainGrace time.Duration
	env := startIntegrationServer(t, func(c *config.ServeCmd) {
		c.LimitConnIdle = 3 * time.Second
		grace, drainGrace = c.ShutdownGrace, c.DrainGrace()
	})
	ctx := context.Background()

	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	fqdn := ident.Name + "." + itTunnelDomain
	phoneTLS := phoneServerTLS(t, ident)
	c, err := client.New(env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident, func(_ string, s io.ReadWriteCloser) {
		conn := tls.Server(&rwcConn{rwc: s}, phoneTLS)
		defer tunneltest.CloseLogged(conn)
		if err := conn.Handshake(); err != nil {
			testLogger().Warn("echo phone handshake failed", "err", err)
			return
		}
		if _, err := io.Copy(conn, conn); err != nil {
			testLogger().Debug("echo phone stream ended with an error", "err", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() {
		if err := c.Run(runCtx); err != nil && runCtx.Err() == nil {
			testLogger().Warn("tunnel client run failed", "err", err)
		}
	}()
	var rtErr error
	if !waitBool(30*time.Second, func() bool {
		rtErr = frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots)
		return rtErr == nil
	}) {
		t.Fatalf("frontend roundtrip never succeeded (phone never bound): %v", rtErr)
	}
	live := dialFrontend(t, env.edgeAddr, fqdn, env.pebble.IssuingRoots)
	defer tunneltest.CloseOrLog(t, live)
	if _, err := live.Write([]byte("live")); err != nil {
		t.Fatalf("live write: %v", err)
	}
	if _, err := io.ReadFull(live, make([]byte, 4)); err != nil {
		t.Fatalf("live echo: %v", err)
	}
	defer keepSpliceBusy(live).close()

	blackHole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, blackHole)
	var heldMu sync.Mutex
	var held []net.Conn
	defer func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		for _, hc := range held {
			tunneltest.CloseOrLog(t, hc)
		}
	}()
	go func() {
		for {
			hc, aerr := blackHole.Accept()
			if aerr != nil {
				if !errors.Is(aerr, net.ErrClosed) {
					testLogger().Warn("black-hole accept failed", "err", aerr)
				}
				return
			}
			heldMu.Lock()
			held = append(held, hc)
			heldMu.Unlock()
		}
	}()
	reg, err := router.NewRegistry(env.rdb, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterNode(ctx, "unreachable-peer", router.NodeInfo{Advertise: blackHole.Addr().String(), Public: blackHole.Addr().String()}, time.Minute); err != nil {
		t.Fatal(err)
	}
	nodes, err := reg.LiveNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var self string
	for id := range nodes {
		if id != "unreachable-peer" {
			self = id
		}
	}
	if self == "" || len(nodes) != 2 {
		t.Fatalf("live nodes = %v, want the server and the unreachable peer", nodes)
	}

	start := time.Now()
	if err := env.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if elapsed := time.Since(start); elapsed > drainGrace+grace+2*time.Second {
		t.Fatalf("Run returned %s after cancel, want within the drain grace (%s) + ShutdownGrace (%s) + 2s", elapsed, drainGrace, grace)
	}
	if _, ok, err := reg.LookupNode(ctx, self); err != nil || ok {
		t.Fatalf("the drained node must be deregistered (ok=%v err=%v)", ok, err)
	}

	var publicEnd, phoneEnd bool
	if !waitBool(15*time.Second, func() bool {
		publicEnd, phoneEnd = false, false
		for _, k := range tunneltest.S3ListKeys(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, "tunnel-logs/") {
			if !strings.HasSuffix(k, ".jsonl") {
				continue
			}
			for _, line := range bytes.Split(bytes.TrimSpace(s3GetObject(t, env.s3URL, env.s3Access, env.s3Secret, itBucket, k)), []byte("\n")) {
				var ev store.Event
				if err := json.Unmarshal(line, &ev); err != nil {
					t.Fatalf("connection log %s has an invalid JSON line: %v", k, err)
				}
				if ev.Tunnel != ident.Name || ev.Event != "end" {
					continue
				}
				switch ev.Type {
				case "public":
					publicEnd = publicEnd || ev.CloseReason == store.CloseServerShutdown
				case "phone":
					phoneEnd = true
				}
			}
		}
		return publicEnd && phoneEnd
	}) {
		t.Fatalf("drain events in MinIO: public server-shutdown end=%v, phone end=%v; want both", publicEnd, phoneEnd)
	}
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

type busySplice struct {
	failed atomic.Pointer[error]
	stop   chan struct{}
	done   chan struct{}
	conn   *tls.Conn
}

func keepSpliceBusy(conn *tls.Conn) *busySplice {
	b := &busySplice{stop: make(chan struct{}), done: make(chan struct{}), conn: conn}
	go func() {
		defer close(b.done)
		buf := make([]byte, 1)
		for {
			select {
			case <-b.stop:
				return
			case <-time.After(300 * time.Millisecond):
			}
			_, err := conn.Write([]byte("k"))
			if err == nil {
				_, err = io.ReadFull(conn, buf)
			}
			if err != nil {
				b.failed.Store(&err)
				testLogger().Info("busy splice ended", "err", err)
				return
			}
		}
	}()
	return b
}

func (b *busySplice) failure() error {
	if p := b.failed.Load(); p != nil {
		return *p
	}
	return nil
}

func (b *busySplice) close() {
	close(b.stop)
	tunneltest.CloseLogged(b.conn)
	<-b.done
}

func enrollHostGet(t *testing.T, edgeAddr, path string, roots *x509.CertPool) (int, []byte, bool) {
	t.Helper()
	tr := &http.Transport{DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{ServerName: itEnrollHost, RootCAs: roots, MinVersion: tls.VersionTLS12}}
		return d.DialContext(ctx, network, edgeAddr)
	}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + itEnrollHost + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer tunneltest.CloseOrLog(t, resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, body, resp.Close
}

func TestIntegration_StopRunsThePredrainAndTheDrain(t *testing.T) {
	const predrain = 6 * time.Second
	var grace, drainGrace time.Duration
	env := startIntegrationServer(t, func(c *config.ServeCmd) {
		c.PredrainWait = predrain
		c.LimitConnIdle = 3 * time.Second
		grace, drainGrace = c.ShutdownGrace, c.DrainGrace()
	})
	ctx := context.Background()
	if code, body, _ := enrollHostGet(t, env.edgeAddr, "/api/v1/health", env.pebble.IssuingRoots); code != http.StatusOK || string(body) != "ok\n" {
		t.Fatalf("health while serving = %d %q, want 200 ok", code, body)
	}

	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	fqdn := ident.Name + "." + itTunnelDomain
	phoneTLS := phoneServerTLS(t, ident)
	echo := func(_ string, s io.ReadWriteCloser) {
		conn := tls.Server(&rwcConn{rwc: s}, phoneTLS)
		defer tunneltest.CloseLogged(conn)
		if err := conn.Handshake(); err != nil {
			testLogger().Warn("echo phone handshake failed", "err", err)
			return
		}
		if _, err := io.Copy(conn, conn); err != nil {
			testLogger().Debug("echo phone stream ended with an error", "err", err)
		}
	}
	c, err := client.New(env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident, echo)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() {
		if err := c.Run(runCtx); err != nil && runCtx.Err() == nil {
			testLogger().Warn("tunnel client run failed", "err", err)
		}
	}()
	var rtErr error
	if !waitBool(30*time.Second, func() bool {
		rtErr = frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots)
		return rtErr == nil
	}) {
		t.Fatalf("frontend roundtrip never succeeded (phone never bound): %v", rtErr)
	}
	live := dialFrontend(t, env.edgeAddr, fqdn, env.pebble.IssuingRoots)
	if _, err := live.Write([]byte("live")); err != nil {
		t.Fatalf("live write: %v", err)
	}
	if _, err := io.ReadFull(live, make([]byte, 4)); err != nil {
		t.Fatalf("live echo: %v", err)
	}
	busy := keepSpliceBusy(live)
	defer busy.close()

	start := time.Now()
	drained := make(chan error, 1)
	go func() { drained <- env.drain() }()

	if !waitBool(2*time.Second, func() bool {
		code, _, _ := enrollHostGet(t, env.edgeAddr, "/api/v1/health", env.pebble.IssuingRoots)
		return code == http.StatusServiceUnavailable
	}) {
		t.Fatal("the health check must answer 503 as soon as the node is told to stop")
	}
	if code, _, _ := enrollHostGet(t, env.edgeAddr, "/api/v1/enroll/nonce", env.pebble.IssuingRoots); code != http.StatusOK {
		t.Fatalf("the nonce route during the pre-drain = %d, want 200 (everything else is still served)", code)
	}
	if err := frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots); err != nil {
		t.Fatalf("a new public connection during the pre-drain must still work: %v", err)
	}

	if !waitBool(predrain+2*time.Second, func() bool {
		code, _, _ := enrollHostGet(t, env.edgeAddr, "/api/v1/enroll/nonce", env.pebble.IssuingRoots)
		return code == http.StatusServiceUnavailable
	}) {
		t.Fatal("the nonce route must be refused once the drain starts")
	}
	if elapsed := time.Since(start); elapsed < predrain-500*time.Millisecond {
		t.Fatalf("the drain started %s after the stop, before the %s pre-drain wait", elapsed, predrain)
	}
	code, body, closed := enrollHostGet(t, env.edgeAddr, "/api/v1/enroll/nonce", env.pebble.IssuingRoots)
	var refusal map[string]any
	if err := json.Unmarshal(body, &refusal); err != nil {
		t.Fatalf("draining refusal body %q: %v", body, err)
	}
	if code != http.StatusServiceUnavailable || refusal["reason"] != "draining" || refusal["retryable"] != true ||
		refusal["retry_after_seconds"] != float64(1) || !closed {
		t.Fatalf("draining refusal = %d %v close=%v, want 503 draining, retryable, retry_after_seconds 1, Connection: close", code, refusal, closed)
	}
	second, err := client.New(env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident, echo)
	if err != nil {
		t.Fatal(err)
	}
	sctx, scancel := context.WithTimeout(ctx, 10*time.Second)
	defer scancel()
	if err := second.Run(sctx); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("a new control connection while draining with no other node = %v, want a 503 refusal", err)
	}
	second.Close()
	if err := frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots); err != nil {
		t.Fatalf("a new public connection during the drain must still reach the bound phone: %v", err)
	}
	if err := busy.failure(); err != nil {
		t.Fatalf("the public connection in flight since before the stop must survive the pre-drain and the drain: %v", err)
	}

	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
	case <-time.After(predrain + drainGrace + grace + 5*time.Second):
		t.Fatal("Run did not return after the pre-drain, the drain grace and the shutdown grace")
	}
	if elapsed := time.Since(start); elapsed < predrain+drainGrace-time.Second {
		t.Fatalf("Run returned %s after the stop; a bound phone must hold the drain for its grace (%s + %s)", elapsed, predrain, drainGrace)
	}
}

func TestIntegration_IssueRefusalKeepsTheOpenControlStream(t *testing.T) {
	env := startIntegrationServer(t, func(c *config.ServeCmd) {
		c.LimitConnIdle = 5 * time.Second
		c.ControlPingInterval = time.Second
	})
	ctx := context.Background()
	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(ident.IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(ident.IdentityCertPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	tr := &http.Transport{Protocols: &protocols, MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dials.Add(1)
			d := &tls.Dialer{Config: &tls.Config{ServerName: itControlHost, RootCAs: env.pebble.IssuingRoots,
				MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{cert}}}
			return d.DialContext(ctx, network, env.edgeAddr)
		}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr}

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	pr, pw := io.Pipe()
	defer tunneltest.CloseOrLog(t, pw)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, "https://"+itControlHost+"/api/v1/control", pr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("open the control stream: %v", err)
	}
	defer tunneltest.CloseOrLog(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control stream = %d, want 200", resp.StatusCode)
	}
	pong, err := wire.EncodeControl(wire.CtrlPong, nil)
	if err != nil {
		t.Fatal(err)
	}
	var pings atomic.Int64
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		var hdr [5]byte
		for {
			if _, err := io.ReadFull(resp.Body, hdr[:]); err != nil {
				testLogger().Info("control stream ended", "err", err)
				return
			}
			if _, err := io.CopyN(io.Discard, resp.Body, int64(binary.BigEndian.Uint32(hdr[1:]))); err != nil {
				testLogger().Info("control stream ended", "err", err)
				return
			}
			if wire.ControlType(hdr[0]) == wire.CtrlPing {
				pings.Add(1)
				if _, err := pw.Write(pong); err != nil {
					testLogger().Info("control stream write ended", "err", err)
					return
				}
			}
		}
	}()
	if !waitBool(10*time.Second, func() bool { return pings.Load() > 0 }) {
		t.Fatal("no PING on the control stream")
	}

	drained := make(chan error, 1)
	go func() { drained <- env.drain() }()
	if !waitBool(5*time.Second, func() bool {
		code, _, _ := enrollHostGet(t, env.edgeAddr, "/api/v1/enroll/nonce", env.pebble.IssuingRoots)
		return code == http.StatusServiceUnavailable
	}) {
		t.Fatal("the drain never started")
	}
	issue := func() (int, map[string]any) {
		t.Helper()
		resp, err := hc.Post("https://"+itControlHost+"/api/v1/issue", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("POST /api/v1/issue: %v", err)
		}
		defer tunneltest.CloseOrLog(t, resp.Body)
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode the issue answer: %v", err)
		}
		return resp.StatusCode, body
	}
	code, body := issue()
	if code != http.StatusServiceUnavailable || body["reason"] != "draining" || body["retryable"] != true {
		t.Fatalf("issue while draining = %d %v, want a retryable 503 draining", code, body)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("the issue request must share the control stream's connection, dials = %d", n)
	}
	before := pings.Load()
	if !waitBool(5*time.Second, func() bool { return pings.Load() >= before+2 }) {
		t.Fatal("the open control stream must keep running after the issue refusal's GOAWAY")
	}
	if code, _ := issue(); code != http.StatusServiceUnavailable {
		t.Fatalf("second issue while draining = %d, want 503", code)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("after the GOAWAY the next request must open a new connection, dials = %d", n)
	}
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after the drain")
	}
	select {
	case <-streamDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the control stream must end at the shutdown")
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
		tunneltest.CloseOrLog(t, raw)
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
	defer tunneltest.CloseOrLog(t, out.Body)
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
			if !errors.Is(err, net.ErrClosed) {
				testLogger().Warn("hanging ACME listener accept failed", "err", err)
			}
			return
		}
		h.mu.Lock()
		if h.done {
			h.mu.Unlock()
			tunneltest.CloseLogged(c)
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
	tunneltest.CloseLogged(h.ln)
	for _, c := range conns {
		tunneltest.CloseLogged(c)
	}
}
