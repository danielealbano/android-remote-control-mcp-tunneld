package edge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
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
	te.e.lim = limit.NewLimiter(rdb, 1<<30, 4, 1<<40, time.Hour) // 4-byte day cap
	// Exhaust the day window (in direction) before the new stream arrives.
	if _, _, _, err := te.e.lim.Charge(context.Background(), "abcdef012345", "in", 10); err != nil {
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
// Charge must NOT kill the live stream as quota-exhausted.
func TestEdge_PacedCopy_TrafficErrorFailsOpen(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	te.e.lim = limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour)
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

// chargeStubEdge builds a test edge whose limiter is a countingLimiter with a controllable Charge
// (action/wait/window/err) and a real embedded limiter (generous caps) for the other methods.
func chargeStubEdge(t *testing.T, action limit.ChargeAction, wait time.Duration, window string, chargeErr error) *testEdge {
	t.Helper()
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	te.e.lim = &countingLimiter{
		Limiter:      limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour),
		chargeAction: action, chargeWait: wait, chargeWindow: window, chargeErr: chargeErr,
	}
	return te
}

// TestEdge_PacedCopy_WaitsWhenOverCap: a ChargeWait read waits ~wait before forwarding, then still
// delivers all bytes (the wait IS the pacing).
func TestEdge_PacedCopy_WaitsWhenOverCap(t *testing.T) {
	te := chargeStubEdge(t, limit.ChargeWait, 40*time.Millisecond, "", nil)
	src := &pipeStream{r: bytes.NewReader(make([]byte, 1024)), w: io.Discard, closed: make(chan struct{})}
	as := &activeStream{tunnel: "t1"}
	var counter int64
	var sink bytes.Buffer
	start := time.Now()
	te.e.pacedCopy(context.Background(), "t1", "in", &sink, src, as, &counter)
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("a ChargeWait read must wait ~wait, returned after %s", elapsed)
	}
	if counter != 1024 || sink.Len() != 1024 {
		t.Fatalf("all bytes must still be delivered after the wait, copied=%d", counter)
	}
}

// TestEdge_PacedCopy_CtxCancelAbandonsWait: ctx cancellation during a pacing wait unblocks pacedCopy
// promptly (teardown/eviction must not wait out the full second).
func TestEdge_PacedCopy_CtxCancelAbandonsWait(t *testing.T) {
	te := chargeStubEdge(t, limit.ChargeWait, 5*time.Second, "", nil)
	src := &pipeStream{r: bytes.NewReader(make([]byte, 1024)), w: io.Discard, closed: make(chan struct{})}
	as := &activeStream{tunnel: "t1"}
	var counter int64
	var sink bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	te.e.pacedCopy(ctx, "t1", "in", &sink, src, as, &counter)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("ctx cancel must abandon the 5s wait promptly, took %s", elapsed)
	}
}

// TestEdge_PacedCopy_ChargeErrorFailsOpen: a Charge error forwards the chunk unpaced (no wait, bytes
// flow), never killing the stream.
func TestEdge_PacedCopy_ChargeErrorFailsOpen(t *testing.T) {
	te := chargeStubEdge(t, limit.ChargeKill, 5*time.Second, "day", errors.New("charge boom")) // kill+wait, but err → ignored
	src := &pipeStream{r: bytes.NewReader(make([]byte, 1024)), w: io.Discard, closed: make(chan struct{})}
	as := &activeStream{tunnel: "t1"}
	var counter int64
	var sink bytes.Buffer
	start := time.Now()
	got := te.e.pacedCopy(context.Background(), "t1", "in", &sink, src, as, &counter)
	if got == quotaHit {
		t.Fatal("a Charge error must fail open, not kill the stream")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("a charge error must NOT wait, took %s", elapsed)
	}
	if counter != 1024 || sink.Len() != 1024 {
		t.Fatalf("bytes must flow unpaced on a charge error, copied=%d", counter)
	}
}

// TestEdge_PacedCopy_KillsOnQuota: a ChargeKill stops the copy with quotaHit and records the window.
func TestEdge_PacedCopy_KillsOnQuota(t *testing.T) {
	te := chargeStubEdge(t, limit.ChargeKill, 0, "day", nil)
	src := &pipeStream{r: bytes.NewReader(make([]byte, 1024)), w: io.Discard, closed: make(chan struct{})}
	as := &activeStream{tunnel: "t1"}
	var counter int64
	var sink bytes.Buffer
	got := te.e.pacedCopy(context.Background(), "t1", "in", &sink, src, as, &counter)
	if got != quotaHit {
		t.Fatalf("a ChargeKill must stop with quotaHit, got %d", got)
	}
	if len(te.rec.quota) == 0 || te.rec.quota[0] != "day" {
		t.Fatalf("want a day QuotaExhausted record, got %v", te.rec.quota)
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

// TestParseRealCurlClientHello parses a REAL captured curl (OpenSSL) ClientHello committed as a
// fixture: field extraction against known ground truth, plus the full JA4 as a regression pin (its
// per-component correctness is anchored by TestJA4SpecVector's external vector).
func TestParseRealCurlClientHello(t *testing.T) {
	data, err := os.ReadFile("testdata/curl_clienthello.bin")
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseClientHello(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.SNI != "curl-fixture.example.test" {
		t.Errorf("SNI = %q", info.SNI)
	}
	if info.TLSVersion != "1.3" {
		t.Errorf("TLSVersion = %q", info.TLSVersion)
	}
	if info.ALPN != "h2" {
		t.Errorf("ALPN = %q", info.ALPN)
	}
	if info.JA4 != "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6" {
		t.Errorf("JA4 drifted for the committed capture: %q", info.JA4)
	}
}

// TestJA4SpecVector validates computeJA4 byte-for-byte against the FoxIO JA4 specification's worked
// example (an EXTERNAL known-good vector): 15 ciphers, 16 extensions (SNI+ALPN counted, excluded from
// the hash), the spec's signature-algorithm order, ALPN h2 → t13d1516h2_8daaf6152771_e5627efa2ab1.
func TestJA4SpecVector(t *testing.T) {
	hexes := func(s string) []uint16 {
		var out []uint16
		for _, h := range strings.Split(s, ",") {
			v, err := strconv.ParseUint(h, 16, 16)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, uint16(v))
		}
		return out
	}
	ciphers := hexes("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9")
	// The 14 hashed extensions from the spec example + SNI(0000) + ALPN(0010) = the 16 counted ones.
	exts := hexes("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01,0000,0010")
	sigAlgs := hexes("0403,0804,0401,0503,0805,0501,0806,0601")

	got := computeJA4(ClientHelloInfo{TLSVersion: "1.3", SNI: "x.example.test", ALPN: "h2"},
		ciphers, exts, sigAlgs)
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if got != want {
		t.Fatalf("JA4 spec vector mismatch:\n got %s\nwant %s", got, want)
	}
}

// eventKinds returns the recorded PublicEvent Event fields (start/end) safely.
func (s *fakeSink) kinds() []PublicEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PublicEvent(nil), s.events...)
}

// TestEdge_HandleTunnel_ConnLogStartEnd covers the bridge's connection-log accounting: a full public
// connection produces a start event and an end event carrying the byte counts + close_reason.
func TestEdge_HandleTunnel_ConnLogStartEnd(t *testing.T) {
	name := "abcdef012345"
	sni := name + ".example.test"
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.fp = "fp"
	te.rtr.connID = "conn"

	// A local phone that echoes: the client sends some bytes, the phone splices them back, then EOF.
	te.local.has = true
	te.local.owns = true
	phoneSide := &pipeStream{r: bytes.NewReader([]byte("PONG-BYTES")), w: io.Discard, closed: make(chan struct{})}
	te.local.ds = phoneSide

	client := newScriptConn("198.51.100.40", []byte("CLIENT-BYTES"))
	done := make(chan struct{})
	go func() {
		te.e.handleTunnel(context.Background(), client, ClientHelloInfo{SNI: sni, ALPN: "h2", TLSVersion: "1.3"})
		close(done)
	}()
	// The phone→client copy hits EOF (bytes.Reader drained) → the splice tears down.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleTunnel did not finish")
	}

	evs := te.sink.kinds()
	var start, end *PublicEvent
	for i := range evs {
		switch evs[i].Event {
		case "start":
			start = &evs[i]
		case "end":
			end = &evs[i]
		}
	}
	if start == nil || end == nil {
		t.Fatalf("a public connection must log a start AND an end event, got %d events: %+v", len(evs), evs)
	}
	if start.Tunnel != name || start.SNI != sni || start.SrcIP != "198.51.100.40" {
		t.Errorf("start event fields wrong: %+v", start)
	}
	if end.CloseReason == "" {
		t.Error("the end event must carry a close_reason")
	}
	// The phone→client direction moved "PONG-BYTES" (10 bytes) out to the client.
	if end.BytesOut != int64(len("PONG-BYTES")) {
		t.Errorf("end event BytesOut = %d, want %d", end.BytesOut, len("PONG-BYTES"))
	}
}

// TestEdge_Splice_CloseReasonAttribution covers the durable close_reason: a phone-side EOF records
// phone-close (not the client-close default), and a client-side EOF records client-close.
func TestEdge_Splice_CloseReasonAttribution(t *testing.T) {
	cfg := baseConfig()
	cfg.IdleTimeout = 0
	cfg.MinRate = 0
	te := newTestEdge(t, cfg, nil, nil)

	t.Run("phone closes first", func(t *testing.T) {
		client := newScriptConn("203.0.113.20", nil)                                            // blocks until closed
		far := &pipeStream{r: bytes.NewReader(nil), w: io.Discard, closed: make(chan struct{})} // EOF immediately
		as := &activeStream{tunnel: "t", started: time.Now(), cancel: func() {}}
		as.lastAct.Store(time.Now().UnixNano())
		if got := te.e.splice(context.Background(), "t", client, far, as); got != store.ClosePhoneClose {
			t.Fatalf("phone EOF must record %q, got %q", store.ClosePhoneClose, got)
		}
	})

	t.Run("client closes first", func(t *testing.T) {
		client := &closingConn{scriptConn: newScriptConn("203.0.113.21", nil), eof: true} // client read EOFs
		far := newScriptConn("203.0.113.21", nil)                                         // phone blocks
		as := &activeStream{tunnel: "t", started: time.Now(), cancel: func() {}}
		as.lastAct.Store(time.Now().UnixNano())
		if got := te.e.splice(context.Background(), "t", client, far, as); got != store.CloseClientClose {
			t.Fatalf("client EOF must record %q, got %q", store.CloseClientClose, got)
		}
	})

	// A ctx cancel with the eviction marker set (evictLeastActive's order) records evicted.
	t.Run("saturation eviction", func(t *testing.T) {
		client := newScriptConn("203.0.113.22", nil) // blocks until closed
		far := newScriptConn("203.0.113.22", nil)    // blocks until closed
		ctx, cancel := context.WithCancel(context.Background())
		as := &activeStream{tunnel: "t", started: time.Now(), cancel: cancel}
		as.lastAct.Store(time.Now().UnixNano())
		go func() {
			time.Sleep(20 * time.Millisecond)
			as.evicted.Store(true)
			cancel()
		}()
		if got := te.e.splice(ctx, "t", client, far, as); got != store.CloseEvicted {
			t.Fatalf("a marked eviction cancel must record %q, got %q", store.CloseEvicted, got)
		}
	})

	// A ctx cancel WITHOUT the eviction marker is the server draining (parent ctx) — never "evicted".
	t.Run("server drain", func(t *testing.T) {
		client := newScriptConn("203.0.113.23", nil) // blocks until closed
		far := newScriptConn("203.0.113.23", nil)    // blocks until closed
		ctx, cancel := context.WithCancel(context.Background())
		as := &activeStream{tunnel: "t", started: time.Now(), cancel: func() {}}
		as.lastAct.Store(time.Now().UnixNano())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		if got := te.e.splice(ctx, "t", client, far, as); got != store.CloseServerShutdown {
			t.Fatalf("a drain cancel must record %q, got %q", store.CloseServerShutdown, got)
		}
	})
}

// closingConn is a scriptConn whose Read returns EOF immediately (the public client closing its side).
type closingConn struct {
	*scriptConn
	eof bool
}

func (c *closingConn) Read(p []byte) (int, error) {
	if c.eof {
		return 0, io.EOF
	}
	return c.scriptConn.Read(p)
}

// TestEdge_HandleTunnel_DuplicateStreamRetries covers the local-path duplicate-stream retry: a
// dial-back that reports a duplicate pending stream id makes the edge re-mint the streamID once and
// re-open against the SAME route.
func TestEdge_HandleTunnel_DuplicateStreamRetries(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.fp = "fp"
	te.rtr.connID = "conn"
	te.local.has = true
	te.local.owns = true
	te.local.ds = &pipeStream{r: bytes.NewReader(nil), w: io.Discard, closed: make(chan struct{})}
	te.local.errQueue = []error{phoneconn.ErrDuplicateStreamID, nil} // first mint duplicates, re-mint succeeds

	conn := newScriptConn("198.51.100.30", nil)
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
	if te.local.opened != 2 {
		t.Fatalf("want one duplicate-stream re-mint (2 local opens), got %d", te.local.opened)
	}
	if te.rtr.lookups != 1 {
		t.Fatalf("a duplicate-stream retry must reuse the same route (1 lookup), got %d", te.rtr.lookups)
	}
	if containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("the re-minted stream must not be rejected, got %v", te.rec.rejectReasons())
	}
}

// TestEdge_HandleTunnel_MeshDuplicateRetries covers the mesh-path duplicate-stream retry: a mesh dial
// answering mesh.ErrDuplicateStream makes the edge re-mint the streamID once and re-dial the SAME owner.
func TestEdge_HandleTunnel_MeshDuplicateRetries(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.fp = "fp"
	te.rtr.connID = "conn"
	te.rtr.nodeAdv = "10.0.0.9:9443"
	te.rtr.nodeOK = true
	te.local.has = false // mesh path
	te.mesh.rwc = &pipeStream{r: bytes.NewReader(nil), w: io.Discard, closed: make(chan struct{})}
	te.mesh.errQueue = []error{mesh.ErrDuplicateStream, nil}

	conn := newScriptConn("198.51.100.31", nil)
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
	if te.mesh.opened != 2 {
		t.Fatalf("want one duplicate-stream re-mint (2 mesh dials), got %d", te.mesh.opened)
	}
	if te.rtr.lookups != 1 {
		t.Fatalf("a duplicate-stream retry must reuse the same route (1 lookup), got %d", te.rtr.lookups)
	}
	if containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("the re-minted stream must not be rejected, got %v", te.rec.rejectReasons())
	}
}

// --- edge accept-loop, SNI case-insensitivity, slot accounting, ban eviction ---

// countingLimiter wraps a real limiter to (a) force AcquireStream to fail-open and (b) count
// ReleaseStream calls, so a fail-open admission's release-once behaviour is observable, and (c) return a
// CONTROLLABLE Charge (chargeAction/chargeWait/chargeWindow/chargeErr; default zero → (Proceed,0,"",nil),
// i.e. never paces) so the pacedCopy wait / ctx-cancel / kill / fail-open paths are testable.
// TrafficExhausted and the other methods fall through to the embedded real limiter.
type countingLimiter struct {
	*limit.Limiter
	acquireErr error
	releases   atomic.Int64

	chargeAction limit.ChargeAction
	chargeWait   time.Duration
	chargeWindow string
	chargeErr    error
}

func (c *countingLimiter) AcquireStream(ctx context.Context, name string, maxN int) (bool, error) {
	if c.acquireErr != nil {
		return false, c.acquireErr
	}
	return c.Limiter.AcquireStream(ctx, name, maxN)
}

func (c *countingLimiter) Charge(_ context.Context, _, _ string, _ int64) (limit.ChargeAction, time.Duration, string, error) {
	return c.chargeAction, c.chargeWait, c.chargeWindow, c.chargeErr
}

func (c *countingLimiter) ReleaseStream(ctx context.Context, name string) error {
	c.releases.Add(1)
	return c.Limiter.ReleaseStream(ctx, name)
}

// scriptedListener returns a scripted sequence of Accept results, recording each call's timestamp so a
// test can observe the accept-loop backoff spacing.
type scriptedListener struct {
	mu    sync.Mutex
	times []time.Time
	steps []func() (net.Conn, error)
	i     int
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.times = append(l.times, time.Now())
	step := func() (net.Conn, error) { return nil, net.ErrClosed }
	if l.i < len(l.steps) {
		step = l.steps[l.i]
		l.i++
	}
	l.mu.Unlock()
	return step()
}

func (l *scriptedListener) Close() error { return nil }
func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

// TestAcceptLoop_BackoffOnPersistentError: persistent accept errors must back off (no hot-spin) and a
// successful accept must reset the backoff.
func TestAcceptLoop_BackoffOnPersistentError(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	tmp := errors.New("temporary accept error")
	ln := &scriptedListener{steps: []func() (net.Conn, error){
		func() (net.Conn, error) { return nil, tmp }, // 1: backoff 5ms
		func() (net.Conn, error) { return nil, tmp }, // 2: backoff 10ms
		func() (net.Conn, error) { return nil, tmp }, // 3: backoff 20ms
		func() (net.Conn, error) {
			return &closingConn{scriptConn: newScriptConn("203.0.113.7", nil), eof: true}, nil
		}, // 4: success → reset
		func() (net.Conn, error) { return nil, tmp },           // 5: backoff 5ms again
		func() (net.Conn, error) { return nil, net.ErrClosed }, // 6: stop the loop
	}}

	te.e.acceptLoop(context.Background(), ln) // returns when the listener reports ErrClosed
	wctx, wcancel := context.WithTimeout(context.Background(), 2*time.Second)
	te.e.Wait(wctx) // the success handler goroutine must finish
	wcancel()

	ln.mu.Lock()
	defer ln.mu.Unlock()
	if len(ln.times) != 6 {
		t.Fatalf("expected 6 Accept calls, got %d", len(ln.times))
	}
	firstBackoff := ln.times[1].Sub(ln.times[0])    // ~5ms
	gapAfterErrors := ln.times[2].Sub(ln.times[1])  // ~10ms
	gapAfterSuccess := ln.times[4].Sub(ln.times[3]) // ~0: the success reset the backoff
	if firstBackoff < 4*time.Millisecond {
		t.Fatalf("a persistent accept error must back off (no hot-spin), first gap = %s", firstBackoff)
	}
	if gapAfterSuccess >= gapAfterErrors {
		t.Fatalf("a successful accept must RESET the backoff: after-success %s should be < after-errors %s",
			gapAfterSuccess, gapAfterErrors)
	}
}

// TestHandleConn_SNICaseInsensitive: an uppercased reserved-host SNI still reaches its local terminator.
func TestHandleConn_SNICaseInsensitive(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	hello := buildClientHello("", []uint16{0x1301}, []extension{sniExt("ENROLL.EXAMPLE.TEST")})
	te.e.handleConn(context.Background(), newScriptConn("203.0.113.40", hello))

	accepted := make(chan net.Conn, 1)
	go func() { c, _ := te.e.EnrollListener().Accept(); accepted <- c }()
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("uppercased enroll SNI must be pushed to the enroll listener")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the enroll listener received no connection for an uppercased SNI")
	}
}

// TestTunnelName_CaseInsensitive: a mixed-case public SNI resolves to the lowercase tunnel name.
func TestTunnelName_CaseInsensitive(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	name, ok := te.e.tunnelName("NAME.Example.TEST")
	if !ok || name != "name" {
		t.Fatalf("mixed-case SNI must resolve to %q, got %q ok=%v", "name", name, ok)
	}
}

// TestHandleTunnel_FailOpenNeverReleases: an AcquireStream error fails open (admits) but must NEVER
// release a slot it never took.
func TestHandleTunnel_FailOpenNeverReleases(t *testing.T) {
	sni := "abcdef01.example.test"
	cfg := baseConfig()
	cfg.Concurrent = 4
	te := newTestEdge(t, cfg, nil, nil)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cl := &countingLimiter{
		Limiter:    limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour),
		acquireErr: errors.New("valkey down"),
	}
	te.e.lim = cl
	te.e.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.fp = "fp"
	te.rtr.connID = "conn"
	te.local.has = false // openFar fails → the reject path runs the deferred release-once
	te.rtr.nodeOK = false

	te.e.handleTunnel(context.Background(), newScriptConn("198.51.100.50", nil), ClientHelloInfo{SNI: sni})

	if cl.releases.Load() != 0 {
		t.Fatalf("a fail-open admission must never DECR a slot it did not take, releases=%d", cl.releases.Load())
	}
}

// TestEvictLeastActive_ReleasesVictimSlotOnce: eviction frees the victim's slot immediately, and the
// victim's own deferred release then no-ops.
func TestEvictLeastActive_ReleasesVictimSlotOnce(t *testing.T) {
	cfg := baseConfig()
	cfg.ProtectRate = 1 << 20
	te := newTestEdge(t, cfg, nil, nil)

	var releases atomic.Int64
	var once sync.Once
	rel := func() { once.Do(func() { releases.Add(1) }) }
	victim := &activeStream{tunnel: "t1", cancel: func() {}, release: rel}
	victim.lastAct.Store(0) // maximally idle → evictable
	te.e.trackStream(victim)

	if !te.e.evictLeastActive("t1") {
		t.Fatal("an idle stream must be evictable")
	}
	if releases.Load() != 1 {
		t.Fatalf("eviction must release the victim slot once, got %d", releases.Load())
	}
	rel() // the victim's OWN deferred release now runs
	if releases.Load() != 1 {
		t.Fatalf("the victim's deferred release must no-op after eviction, got %d", releases.Load())
	}
}

// TestEvictBannedStreams_KillsMatching: a ban reload cancels the matching active splice (close_reason
// ban-evict) and leaves a non-matching stream untouched.
func TestEvictBannedStreams_KillsMatching(t *testing.T) {
	cfg := baseConfig()
	cfg.IdleTimeout = 0
	cfg.MinRate = 0
	te := newTestEdge(t, cfg, nil, nil)

	client := newScriptConn("203.0.113.30", nil) // blocks until closed
	far := newScriptConn("203.0.113.30", nil)    // blocks until closed
	ctx, cancel := context.WithCancel(context.Background())
	victim := &activeStream{tunnel: "t1", fp: "fp-ban", started: time.Now(), cancel: cancel}
	victim.lastAct.Store(time.Now().UnixNano())
	te.e.trackStream(victim)
	defer te.e.untrackStream(victim)

	other := &activeStream{tunnel: "t1", fp: "fp-clean", started: time.Now(), cancel: func() {}}
	te.e.trackStream(other)
	defer te.e.untrackStream(other)

	reasonCh := make(chan string, 1)
	go func() { reasonCh <- te.e.splice(ctx, "t1", client, far, victim) }()
	time.Sleep(20 * time.Millisecond) // let the splice watcher start

	te.e.EvictBannedStreams(func(name, fp string) bool { return name == "t1" && fp == "fp-ban" })

	select {
	case reason := <-reasonCh:
		if reason != store.CloseBanEvict {
			t.Fatalf("a ban-evicted splice must record %q, got %q", store.CloseBanEvict, reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the banned splice was not torn down")
	}
	if !victim.banned.Load() {
		t.Fatal("the matching stream must be marked banned")
	}
	if other.banned.Load() {
		t.Fatal("a non-matching stream must be left untouched")
	}
}

// TestHandleTunnel_RetryPathBanRecordsBan: a fresh route that is banned on the retry path is recorded
// as reason "ban", never "no-route".
func TestHandleTunnel_RetryPathBanRecordsBan(t *testing.T) {
	sni := "abcdef01.example.test"
	te := newTestEdge(t, baseConfig(), nil, func(_, fp string) bool { return fp == "fp-ban" })
	te.rtr.queue = []fakeRoute{
		{nodeID: "node-a", fp: "fp-clean", connID: "conn1", ok: true}, // initial: passes the ban check
		{nodeID: "node-b", fp: "fp-ban", connID: "conn2", ok: true},   // retry: a DIFFERENT, banned route
	}
	te.local.has = false
	te.rtr.nodeOK = false // openFar (mesh) fails → triggers the fresh-route retry

	te.e.handleTunnel(context.Background(), newScriptConn("198.51.100.60", nil), ClientHelloInfo{SNI: sni})

	reasons := te.rec.rejectReasons()
	if !containsStr(reasons, "ban") {
		t.Fatalf("a banned fresh route must reject with reason ban, got %v", reasons)
	}
	if containsStr(reasons, "no-route") {
		t.Fatalf("a banned fresh route must NOT be recorded as no-route, got %v", reasons)
	}
}
