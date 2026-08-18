package edge

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestEdge_HandleTunnel_QuotaAdmissionRefusal covers the admission-time quota gate: an exhausted
// traffic window refuses each NEW stream with the matching quota reject, before any dial-back.
func TestEdge_HandleTunnel_QuotaAdmissionRefusal(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	te.e.lim = limit.NewLimiter(rdb, 1<<30, 4, 1<<40) // 4-byte day cap
	// Exhaust the day window before the new stream arrives.
	_, _, err := te.e.lim.ClaimTraffic(context.Background(), "abcdef012345", 10)
	if err != nil {
		t.Fatal(err)
	}

	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.connID = "conn-1"
	conn := newScriptConn("198.51.100.20", nil)
	te.e.handleTunnel(context.Background(), conn, ClientHelloInfo{SNI: "abcdef012345.example.test"})

	if !conn.isClosed() {
		t.Fatal("a quota-refused connection must be closed")
	}
	if !containsStr(te.rec.rejectReasons(), "quota-day") {
		t.Fatalf("want quota-day reject, got %v", te.rec.rejectReasons())
	}
	if te.local.opened != 0 || te.mesh.opened != 0 {
		t.Fatal("a quota-refused stream must never open a dial-back")
	}
}

// TestEdge_HandleTunnel_FreshRouteRetryOnMeshFailure covers PROTOCOL §5's one-fresh-lookup retry: a
// stale route whose mesh dial fails is retried ONCE against a re-looked-up (different) route.
func TestEdge_HandleTunnel_FreshRouteRetryOnMeshFailure(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	te.rtr.queue = []fakeRoute{
		{nodeID: "node-old", fp: "fp", connID: "conn-old", ok: true}, // routing lookup (stale)
		{nodeID: "node-new", fp: "fp", connID: "conn-new", ok: true}, // fresh lookup after the failure
	}
	te.rtr.nodeAdv = "10.0.0.9:9443"
	te.rtr.nodeOK = true
	te.local.has = false // not local — mesh path
	te.mesh.rwc = &pipeStream{r: bytes.NewReader(nil), w: io.Discard, closed: make(chan struct{})}
	te.mesh.errQueue = []error{errNoOwner, nil} // stale dial rejected, fresh dial succeeds

	conn := newScriptConn("198.51.100.21", nil)
	done := make(chan struct{})
	go func() {
		te.e.handleTunnel(context.Background(), conn, ClientHelloInfo{SNI: "abcdef012345.example.test"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleTunnel did not finish")
	}

	if te.rtr.lookups != 2 {
		t.Fatalf("want exactly one fresh route re-lookup (2 total), got %d", te.rtr.lookups)
	}
	if te.mesh.opened != 2 {
		t.Fatalf("want exactly one mesh retry (2 dials), got %d", te.mesh.opened)
	}
	if containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("the retried stream must not be rejected, got %v", te.rec.rejectReasons())
	}
}

// TestEdge_HandleTunnel_NoRetryOnIdenticalRoute: when the fresh lookup returns the SAME route, there
// is nothing new to try — the stream fails with no second dial.
func TestEdge_HandleTunnel_NoRetryOnIdenticalRoute(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.connID = "conn-1"
	te.rtr.nodeAdv = "10.0.0.9:9443"
	te.rtr.nodeOK = true
	te.local.has = false
	te.mesh.err = errNoOwner

	conn := newScriptConn("198.51.100.22", nil)
	te.e.handleTunnel(context.Background(), conn, ClientHelloInfo{SNI: "abcdef012345.example.test"})

	if te.mesh.opened != 1 {
		t.Fatalf("an identical fresh route must not be re-dialed, got %d dials", te.mesh.opened)
	}
	if !containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("want no-route reject, got %v", te.rec.rejectReasons())
	}
}

// TestEdge_PacedCopy_TrafficErrorFailsOpen covers the control-plane-blip behavior: a Valkey error on
// ClaimTraffic must NOT kill the live stream as quota-exhausted.
func TestEdge_PacedCopy_TrafficErrorFailsOpen(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	te.e.lim = limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40)
	mr.Close() // every Valkey call now errors

	src := &pipeStream{r: bytes.NewReader(make([]byte, 1024)), w: io.Discard, closed: make(chan struct{})}
	as := &activeStream{tunnel: "t1"}
	var counter int64
	var sink bytes.Buffer
	got := te.e.pacedCopy(context.Background(), "t1", "in", &sink, src, as, &counter)
	if got == quotaHit {
		t.Fatal("a Valkey error must fail open, not kill the stream as quota-exhausted")
	}
	if counter != 1024 || sink.Len() != 1024 {
		t.Fatalf("bytes must still flow on a control-plane error, copied=%d", counter)
	}
	if len(te.rec.quota) != 0 {
		t.Fatalf("no QuotaExhausted must fire on a control-plane error, got %v", te.rec.quota)
	}
}

// TestEdge_Pace_BatchCredit covers the batch-credit draw: one chunk draws a full bwBatch of credit, so
// subsequent chunks consume locally (the data plane hits Valkey ~once per MB).
func TestEdge_Pace_BatchCredit(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil) // harness limiter: bwRate 1<<30 (≥ bwBatch burst)

	remaining := te.e.pace(context.Background(), "t1", "in", 0, 1000)
	if remaining != bwBatch-1000 {
		t.Fatalf("one draw must batch bwBatch credit (remaining %d, want %d)", remaining, bwBatch-1000)
	}
	// The next chunk consumes the LOCAL credit (no draw needed to satisfy it).
	remaining2 := te.e.pace(context.Background(), "t1", "in", remaining, 1000)
	if remaining2 != remaining-1000 {
		t.Fatalf("local credit must be consumed without a fresh batch, got %d", remaining2)
	}
}

// TestEdge_Pace_EmptyBucketBlocks covers the pacing wait: an exhausted bucket blocks the copy in
// refill waits (the wait IS the pacing) until the ctx ends.
func TestEdge_Pace_EmptyBucketBlocks(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	te.e.lim = limit.NewLimiter(rdb, 1, 1<<40, 1<<40) // 1 B/s: the bucket is empty immediately

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	te.e.pace(ctx, "t1", "in", 0, 32*1024)
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Fatalf("an empty bucket must block in refill waits, returned after %s", elapsed)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("ctx cancel must unblock the pacer, took %s", elapsed)
	}
}

// TestEdge_HandleConn_BanBeforeMaxClients covers the accept-check order: a banned IP is recorded as
// banned even when the node is saturated.
func TestEdge_HandleConn_BanBeforeMaxClients(t *testing.T) {
	cfg := baseConfig()
	cfg.MaxClients = 0 // saturated: admit always refuses
	banned := netip.MustParseAddr("198.51.100.66")
	te := newTestEdge(t, cfg, func(a netip.Addr) bool { return a == banned }, nil)

	conn := newScriptConn("198.51.100.66", nil)
	te.e.handleConn(context.Background(), conn)
	if !conn.isClosed() {
		t.Fatal("banned conn must be closed")
	}
	reasons := te.rec.rejectReasons()
	if !containsStr(reasons, "ban") || containsStr(reasons, "max-clients") {
		t.Fatalf("ban must be checked BEFORE max-clients, got %v", reasons)
	}
}

// TestComputeJA4ALPNComponent verifies the JA4 spec's ALPN component: FIRST and LAST alphanumeric
// characters of the first ALPN value; hex-edge fallback; "00" when absent.
func TestComputeJA4ALPNComponent(t *testing.T) {
	tests := []struct {
		name string
		alpn string
		want string // last two characters of the JA4_a part
	}{
		{name: "h2", alpn: "h2", want: "h2"},
		{name: "http/1.1 uses first+last", alpn: "http/1.1", want: "h1"},
		{name: "single char doubles", alpn: "h", want: "hh"},
		{name: "absent is 00", alpn: "", want: "00"},
		{name: "non-alnum edges use hex", alpn: "\x01\x02", want: "02"}, // hex "0102" → first '0', last '2'
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ja4 := computeJA4(ClientHelloInfo{TLSVersion: "1.3", SNI: "x.example.test", ALPN: tc.alpn},
				[]uint16{0x1301}, []uint16{0x0000, 0x0010}, nil)
			aPart := ja4[:len("t13d0102")+2][len("t13d0102"):]
			if aPart != tc.want {
				t.Fatalf("JA4 ALPN component = %q, want %q (ja4=%s)", aPart, tc.want, ja4)
			}
		})
	}
}

// TestEdge_Splice_IdleTimeout covers the idle half of the connection policy: a connection with no
// bytes in either direction past --limit-conn-idle is closed with the idle-timeout reason.
func TestEdge_Splice_IdleTimeout(t *testing.T) {
	cfg := baseConfig()
	cfg.IdleTimeout = 50 * time.Millisecond
	cfg.MinRate = 0 // disable min-rate so idle is unambiguously what fires
	te := newTestEdge(t, cfg, nil, nil)

	client := newScriptConn("203.0.113.10", nil) // blocks on Read until closed → zero traffic
	far := newScriptConn("203.0.113.10", nil)
	as := &activeStream{tunnel: "t", started: time.Now(), cancel: func() {}}
	as.lastAct.Store(time.Now().Add(-time.Second).UnixNano())

	reason := te.e.splice(context.Background(), "t", client, far, as)
	if reason != store.CloseIdleTimeout {
		t.Fatalf("an idle connection must close with %q, got %q", store.CloseIdleTimeout, reason)
	}
}

// TestPeekClientHelloTimesOutOnTrickle covers the pre-TLS slowloris guard: a peer trickling a partial
// ClientHello is cut off at --handshake-timeout.
func TestPeekClientHelloTimesOutOnTrickle(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	go func() {
		_, _ = client.Write([]byte{0x16, 0x03, 0x01}) // partial record header, then silence
	}()

	start := time.Now()
	_, _, err := peekClientHello(server, 50*time.Millisecond)
	if err == nil {
		t.Fatal("a trickled ClientHello must fail at the handshake timeout")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout not honored, took %s", time.Since(start))
	}
}
