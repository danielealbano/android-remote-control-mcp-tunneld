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
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// TestEdge_HandleTunnel_QuotaAdmissionRefusal covers the admission-time quota gate: an exhausted
// traffic window refuses each NEW stream with the matching quota reject, before any dial-back.
func TestEdge_HandleTunnel_QuotaAdmissionRefusal(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	te.e.lim = limit.NewLimiter(rdb, 1<<30, 4, 1<<40, time.Hour) // 4-byte day cap
	// Exhaust the day window (in direction) before the new stream arrives.
	if _, _, _, err := te.e.lim.Charge(context.Background(), "abcdef012345", "m", "in", 10); err != nil {
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
	if len(te.opener.calls) != 0 || len(te.dial.tokens) != 0 {
		t.Fatal("a quota-refused stream must never open a dial-back")
	}
}

// TestEdge_HandleTunnel_FreshRouteRetryOnOpenFailure covers the one-fresh-lookup retry: a stale route
// that fails is retried ONCE against a re-looked-up (different) route.
func TestEdge_HandleTunnel_FreshRouteRetryOnOpenFailure(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	te.rtr.queue = []fakeRoute{
		{nodeID: "node-old", fp: "fp", connID: "conn-old", ok: true}, // routing lookup (stale)
		{nodeID: "node-new", fp: "fp", connID: "conn-new", ok: true}, // fresh lookup after the failure
	}
	te.rtr.set("node-new", "fp", "conn-new", true, nil)
	te.opener.errByNode["node-old"] = errors.New("owner no longer holds the phone")

	conn := newScriptConn("198.51.100.21", nil)
	done := runTunnel(te, conn, "abcdef012345.example.test")
	phone := waitPhone(t, te, 0)
	var connIDs []string
	deadline := time.Now().Add(5 * time.Second)
	for len(connIDs) == 0 && time.Now().Before(deadline) {
		te.e.smu.Lock()
		for s := range te.e.streams {
			connIDs = append(connIDs, s.connID)
		}
		te.e.smu.Unlock()
		if len(connIDs) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	tunneltest.CloseOrLog(t, phone)
	waitDone(t, done, 5*time.Second)

	te.rtr.mu.Lock()
	lookups := te.rtr.lookups
	te.rtr.mu.Unlock()
	if lookups != 2 {
		t.Fatalf("want exactly one fresh route re-lookup (2 total), got %d", lookups)
	}
	if len(te.opener.calls) != 2 || te.opener.calls[0].token != te.opener.calls[1].token ||
		te.opener.calls[1].nodeID != "node-new" || te.opener.calls[1].connID != "conn-new" {
		t.Fatalf("want one retry with the same token against the fresh route, got %+v", te.opener.calls)
	}
	if len(connIDs) != 1 || connIDs[0] != "conn-new" {
		t.Fatalf("the splice must record the fresh route's connID, got %v", connIDs)
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
	te.opener.errByNode["node-a"] = errors.New("owner unreachable")

	conn := newScriptConn("198.51.100.22", nil)
	te.e.handleTunnel(context.Background(), conn, ClientHelloInfo{SNI: "abcdef012345.example.test"})

	if len(te.opener.calls) != 1 {
		t.Fatalf("an identical fresh route must not be re-opened, got %d opens", len(te.opener.calls))
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
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
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
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
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
	defer tunneltest.CloseOrLog(t, client)
	defer tunneltest.CloseOrLog(t, server)
	go func() {
		if _, err := client.Write([]byte{0x16, 0x03, 0x01}); err != nil { // partial record header, then silence
			tunneltest.Logger().Debug("trickle write ended", "err", err)
		}
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

	client := newScriptConn("198.51.100.40", []byte("CLIENT-BYTES"))
	done := make(chan struct{})
	go func() {
		te.e.handleTunnel(context.Background(), client, ClientHelloInfo{SNI: sni, ALPN: "h2", TLSVersion: "1.3"})
		close(done)
	}()
	phone := waitPhone(t, te, 0)
	readFull(t, phone, "CLIENT-BYTES")
	if _, err := phone.Write([]byte("PONG-BYTES")); err != nil {
		t.Fatal(err)
	}
	tunneltest.CloseOrLog(t, phone)
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

	mu       sync.Mutex
	acquired []string
	charged  []string
	released []string

	chargeAction limit.ChargeAction
	chargeWait   time.Duration
	chargeWindow string
	chargeErr    error
}

func (c *countingLimiter) AcquireStream(ctx context.Context, name, member string, maxN int) (bool, error) {
	c.mu.Lock()
	c.acquired = append(c.acquired, member)
	c.mu.Unlock()
	if c.acquireErr != nil {
		return false, c.acquireErr
	}
	return c.Limiter.AcquireStream(ctx, name, member, maxN)
}

func (c *countingLimiter) Charge(_ context.Context, _, member, _ string, _ int64) (limit.ChargeAction, time.Duration, string, error) {
	c.mu.Lock()
	c.charged = append(c.charged, member)
	c.mu.Unlock()
	return c.chargeAction, c.chargeWait, c.chargeWindow, c.chargeErr
}

func (c *countingLimiter) ReleaseStream(ctx context.Context, name, member string) error {
	c.releases.Add(1)
	c.mu.Lock()
	c.released = append(c.released, member)
	c.mu.Unlock()
	return c.Limiter.ReleaseStream(ctx, name, member)
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
	go func() {
		c, err := te.e.EnrollListener().Accept()
		if err != nil {
			tunneltest.Logger().Warn("enroll listener accept failed", "err", err)
		}
		accepted <- c
	}()
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

func TestHandleTunnel_FailOpenStillReleases(t *testing.T) {
	sni := "abcdef01.example.test"
	cfg := baseConfig()
	cfg.Concurrent = 4
	te := newTestEdge(t, cfg, nil, nil)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
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
	te.opener.errByNode["node-a"] = errors.New("owner unreachable")

	te.e.handleTunnel(context.Background(), newScriptConn("198.51.100.50", nil), ClientHelloInfo{SNI: sni})

	if cl.releases.Load() != 1 || len(cl.released) != 1 || len(cl.acquired) != 1 || cl.released[0] != cl.acquired[0] {
		t.Fatalf("a fail-open admission must release its member exactly once: acquired=%v released=%v", cl.acquired, cl.released)
	}
}

func TestEdge_HandleTunnel_StreamMemberIsTheToken(t *testing.T) {
	sni := "abcdef012345.example.test"
	te := newTestEdge(t, baseConfig(), nil, nil)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	cl := &countingLimiter{Limiter: limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour)}
	te.e.lim = cl
	te.rtr.set("node-a", "fp", "conn", true, nil)

	client := newScriptConn("198.51.100.51", []byte("PING"))
	done := runTunnel(te, client, sni)
	phone := waitPhone(t, te, 0)
	readFull(t, phone, "PING")
	if _, err := phone.Write([]byte("PONG")); err != nil {
		t.Fatal(err)
	}
	tunneltest.CloseOrLog(t, phone)
	waitDone(t, done, 5*time.Second)

	token := te.dial.tokens[0]
	if te.opener.calls[0].token != token {
		t.Fatalf("the open must carry the waited token: open=%q wait=%q", te.opener.calls[0].token, token)
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if len(cl.acquired) != 1 || cl.acquired[0] != token || len(cl.released) != 1 || cl.released[0] != token {
		t.Fatalf("acquire/release members = %v / %v, want the token %q", cl.acquired, cl.released, token)
	}
	if len(cl.charged) < 2 {
		t.Fatalf("want a charge per direction, got %v", cl.charged)
	}
	for _, m := range cl.charged {
		if m != token {
			t.Fatalf("every Charge must carry the token, got %q", m)
		}
	}
	for _, ev := range te.sink.kinds() {
		if len(ev.Conn) != 8 || ev.Conn == token {
			t.Fatalf("the conn-log conn id must be 8 hex chars and never the token, got %q", ev.Conn)
		}
		if _, err := strconv.ParseUint(ev.Conn, 16, 32); err != nil {
			t.Fatalf("the conn-log conn id must be hex, got %q", ev.Conn)
		}
	}
}

func TestSpliceReason_PhoneGoneAttribution(t *testing.T) {
	tests := []struct {
		name         string
		set          func(as *activeStream)
		cancelParent bool
		want         string
	}{
		{name: "banned beats phoneGone", set: func(as *activeStream) { as.banned.Store(true); as.phoneGone.Store(true) }, want: store.CloseBanEvict},
		{name: "terminated beats phoneGone", set: func(as *activeStream) { as.terminated.Store(true); as.phoneGone.Store(true) }, want: store.CloseAdminTerminate},
		{name: "phoneGone beats evicted", set: func(as *activeStream) { as.phoneGone.Store(true); as.evicted.Store(true) }, want: store.ClosePhoneClose},
		{name: "drain keeps server-shutdown", set: func(as *activeStream) { as.phoneGone.Store(true) }, cancelParent: true, want: store.CloseServerShutdown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.IdleTimeout = 0
			cfg.MinRate = 0
			te := newTestEdge(t, cfg, nil, nil)
			client := newScriptConn("203.0.113.60", nil)
			far := newScriptConn("203.0.113.60", nil)
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			ctx, cancel := context.WithCancel(parent)
			as := &activeStream{tunnel: "t", parent: parent, started: time.Now(), cancel: cancel}
			as.lastAct.Store(time.Now().UnixNano())
			go func() {
				time.Sleep(20 * time.Millisecond)
				tc.set(as)
				if tc.cancelParent {
					cancelParent()
				} else {
					cancel()
				}
			}()
			if got := te.e.splice(ctx, "t", client, far, as); got != tc.want {
				t.Fatalf("close_reason = %q, want %q", got, tc.want)
			}
		})
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

// TestEvictTunnelStreams_KillsMatching: an admin terminate cancels the named tunnel's active splice
// (close_reason admin-terminate), marks it terminated, and leaves another tunnel's stream untouched.
func TestEvictTunnelStreams_KillsMatching(t *testing.T) {
	cfg := baseConfig()
	cfg.IdleTimeout = 0
	cfg.MinRate = 0
	te := newTestEdge(t, cfg, nil, nil)

	client := newScriptConn("203.0.113.40", nil) // blocks until closed
	far := newScriptConn("203.0.113.40", nil)    // blocks until closed
	ctx, cancel := context.WithCancel(context.Background())
	victim := &activeStream{tunnel: "t1", started: time.Now(), cancel: cancel}
	victim.lastAct.Store(time.Now().UnixNano())
	te.e.trackStream(victim)
	defer te.e.untrackStream(victim)

	other := &activeStream{tunnel: "t2", started: time.Now(), cancel: func() {}}
	te.e.trackStream(other)
	defer te.e.untrackStream(other)

	reasonCh := make(chan string, 1)
	go func() { reasonCh <- te.e.splice(ctx, "t1", client, far, victim) }()
	time.Sleep(20 * time.Millisecond) // let the splice watcher start

	te.e.EvictTunnelStreams("t1")

	select {
	case reason := <-reasonCh:
		if reason != store.CloseAdminTerminate {
			t.Fatalf("an admin-terminated splice must record %q, got %q", store.CloseAdminTerminate, reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the terminated splice was not torn down")
	}
	if !victim.terminated.Load() {
		t.Fatal("the matching stream must be marked terminated")
	}
	if other.terminated.Load() {
		t.Fatal("a different tunnel's stream must be left untouched")
	}
}

// TestSpliceReason_BannedBeatsTerminated: with both banned and terminated set before a ctx cancel, the
// splice attributes ban-evict (banned takes precedence).
func TestSpliceReason_BannedBeatsTerminated(t *testing.T) {
	cfg := baseConfig()
	cfg.IdleTimeout = 0
	cfg.MinRate = 0
	te := newTestEdge(t, cfg, nil, nil)

	client := newScriptConn("203.0.113.41", nil) // blocks until closed
	far := newScriptConn("203.0.113.41", nil)    // blocks until closed
	ctx, cancel := context.WithCancel(context.Background())
	as := &activeStream{tunnel: "t", started: time.Now(), cancel: cancel}
	as.lastAct.Store(time.Now().UnixNano())
	go func() {
		time.Sleep(20 * time.Millisecond)
		as.banned.Store(true)
		as.terminated.Store(true)
		cancel()
	}()
	if got := te.e.splice(ctx, "t", client, far, as); got != store.CloseBanEvict {
		t.Fatalf("banned must beat terminated: want %q, got %q", store.CloseBanEvict, got)
	}
}

// TestSpliceReason_TerminatedBeatsEvicted: with both terminated and evicted set before a ctx cancel, the
// splice attributes admin-terminate (terminated takes precedence over evicted).
func TestSpliceReason_TerminatedBeatsEvicted(t *testing.T) {
	cfg := baseConfig()
	cfg.IdleTimeout = 0
	cfg.MinRate = 0
	te := newTestEdge(t, cfg, nil, nil)

	client := newScriptConn("203.0.113.42", nil) // blocks until closed
	far := newScriptConn("203.0.113.42", nil)    // blocks until closed
	ctx, cancel := context.WithCancel(context.Background())
	as := &activeStream{tunnel: "t", started: time.Now(), cancel: cancel}
	as.lastAct.Store(time.Now().UnixNano())
	go func() {
		time.Sleep(20 * time.Millisecond)
		as.terminated.Store(true)
		as.evicted.Store(true)
		cancel()
	}()
	if got := te.e.splice(ctx, "t", client, far, as); got != store.CloseAdminTerminate {
		t.Fatalf("terminated must beat evicted: want %q, got %q", store.CloseAdminTerminate, got)
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
	te.opener.errByNode["node-a"] = errors.New("owner unreachable")

	te.e.handleTunnel(context.Background(), newScriptConn("198.51.100.60", nil), ClientHelloInfo{SNI: sni})

	reasons := te.rec.rejectReasons()
	if !containsStr(reasons, "ban") {
		t.Fatalf("a banned fresh route must reject with reason ban, got %v", reasons)
	}
	if containsStr(reasons, "no-route") {
		t.Fatalf("a banned fresh route must NOT be recorded as no-route, got %v", reasons)
	}
}
