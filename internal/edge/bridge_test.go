package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestEdge_PacedCopy_QuotaExhaustion(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil)
	// Swap in a limiter with a tiny day cap so Charge kills on the day cap immediately.
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	te.e.lim = limit.NewLimiter(rdb, 1<<30, 4, 1<<40, time.Hour) // 4-byte day cap
	te.e.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	src := &pipeStream{r: newBytesReader(make([]byte, 1024)), w: io.Discard, closed: make(chan struct{})}
	as := &activeStream{tunnel: "t1"}
	var counter int64
	got := te.e.pacedCopy(context.Background(), "t1", "in", io.Discard, src, as, &counter)
	if got != quotaHit {
		t.Fatalf("pacedCopy must stop with quotaHit on an exhausted day window, got %d", got)
	}
	if len(te.rec.quota) == 0 || te.rec.quota[0] != "day" {
		t.Fatalf("want a day QuotaExhausted record, got %v", te.rec.quota)
	}
}

func TestEdge_HandleTunnel_ReleasesStreamSlotOnce(t *testing.T) {
	name := "abcdef012345.example.test"
	cfg := baseConfig()
	cfg.Concurrent = 4
	te := newTestEdge(t, cfg, nil)
	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.connID = "conn"
	te.opener.errByNode["node-a"] = errors.New("owner unreachable")

	te.e.handleTunnel(context.Background(), newScriptConn("198.51.100.20", nil), ClientHelloInfo{SNI: name})

	if got := freeSlots(t, te, "abcdef012345", cfg.Concurrent); got != cfg.Concurrent {
		t.Fatalf("stream slot leaked: only %d/%d slots free after a failed bridge", got, cfg.Concurrent)
	}
}

func freeSlots(t *testing.T, te *testEdge, name string, n int) int {
	t.Helper()
	free := 0
	for i := range n {
		ok, err := te.e.lim.AcquireStream(context.Background(), name, fmt.Sprintf("probe-%d", i), n)
		if err != nil {
			t.Fatalf("AcquireStream: %v", err)
		}
		if ok {
			free++
		}
	}
	return free
}

func runTunnel(te *testEdge, client net.Conn, sni string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		te.e.handleTunnel(context.Background(), client, ClientHelloInfo{SNI: sni})
		close(done)
	}()
	return done
}

func waitPhone(t *testing.T, te *testEdge, i int) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		te.dial.mu.Lock()
		n := len(te.dial.phones)
		te.dial.mu.Unlock()
		if n > i {
			return te.dial.phone(i)
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial-back %d never arrived", i)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readFull(t *testing.T, r io.Reader, want string) {
	t.Helper()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read %q: %v", want, err)
	}
	if string(buf) != want {
		t.Fatalf("read %q, want %q", buf, want)
	}
}

func clientWrites(c *scriptConn) string {
	c.writesMu.Lock()
	defer c.writesMu.Unlock()
	return string(c.writes)
}

func TestEdge_OpenFar_OpensThenAwaitsWithOneToken(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil)
	te.rtr.set("node-b", "conn-7", true, nil)
	client := newScriptConn("198.51.100.70", []byte("HELLO"))
	done := runTunnel(te, client, "abcdef012345.example.test")

	phone := waitPhone(t, te, 0)
	readFull(t, phone, "HELLO")
	if _, err := phone.Write([]byte("WORLD")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for clientWrites(client) != "WORLD" {
		if time.Now().After(deadline) {
			t.Fatalf("the phone's bytes never reached the client, got %q", clientWrites(client))
		}
		time.Sleep(5 * time.Millisecond)
	}
	tunneltest.CloseOrLog(t, phone)
	waitDone(t, done, 5*time.Second)

	te.opener.mu.Lock()
	calls := append([]openCall(nil), te.opener.calls...)
	te.opener.mu.Unlock()
	te.dial.mu.Lock()
	tokens := append([]string(nil), te.dial.tokens...)
	tunnels := append([]string(nil), te.dial.tunnels...)
	te.dial.mu.Unlock()
	if len(calls) != 1 || len(tokens) != 1 {
		t.Fatalf("want one open and one wait, got opens=%+v waits=%v", calls, tokens)
	}
	want := openCall{nodeID: "node-b", name: "abcdef012345", connID: "conn-7", token: tokens[0]}
	if calls[0] != want || tunnels[0] != "abcdef012345" || len(tokens[0]) != 26 {
		t.Fatalf("open = %+v (waited for %q on %q), want %+v with a 26-char token", calls[0], tokens[0], tunnels[0], want)
	}
}

func TestEdge_HandleTunnel_RefusedWhileDialBacksUnavailable(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil)
	te.rtr.set("node-a", "conn-1", true, nil)
	te.ready.notReady.Store(true)
	client := newScriptConn("198.51.100.73", nil)
	waitDone(t, runTunnel(te, client, "abcdef012345.example.test"), 5*time.Second)
	if !client.isClosed() || !containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("closed=%v rejects=%v, want the client refused with no-route", client.isClosed(), te.rec.rejectReasons())
	}
	if len(te.opener.calls) != 0 || len(te.dial.tokens) != 0 {
		t.Fatal("no OPEN may be requested while this node cannot accept dial-backs")
	}
	if got := freeSlots(t, te, "abcdef012345", cfg.Concurrent); got != cfg.Concurrent {
		t.Fatalf("no stream slot may be taken while this node cannot accept dial-backs: %d/%d free", got, cfg.Concurrent)
	}
}

func TestEdge_OpenFar_BoundedByDialBackTimeout(t *testing.T) {
	cfg := baseConfig()
	cfg.DialBackTimeout = 100 * time.Millisecond
	te := newTestEdge(t, cfg, nil)
	te.rtr.set("node-a", "conn-1", true, nil)
	te.dial.never = true
	client := newScriptConn("198.51.100.71", nil)
	start := time.Now()
	waitDone(t, runTunnel(te, client, "abcdef012345.example.test"), 5*time.Second)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the dial-back wait was not bounded by DialBackTimeout (took %s)", elapsed)
	}
	if !client.isClosed() {
		t.Fatal("the client must be closed when the phone never dials back")
	}
	if !containsStr(te.rec.rejectReasons(), "no-route") {
		t.Fatalf("want a no-route reject, got %v", te.rec.rejectReasons())
	}
	if got := freeSlots(t, te, "abcdef012345", cfg.Concurrent); got != cfg.Concurrent {
		t.Fatalf("the stream slot leaked: %d/%d free", got, cfg.Concurrent)
	}
}

func TestEdge_Splice_RouteCheckEndsOrphanedSplice(t *testing.T) {
	prev := routeCheckInterval
	routeCheckInterval = 50 * time.Millisecond
	t.Cleanup(func() { routeCheckInterval = prev })
	tests := []struct {
		name    string
		mutate  func(r *fakeRouter)
		wantEnd bool
	}{
		{name: "route gone", mutate: func(r *fakeRouter) { r.set("", "", false, nil) }, wantEnd: true},
		{name: "route re-bound to another connection", mutate: func(r *fakeRouter) { r.set("node-a", "conn-2", true, nil) }, wantEnd: true},
		{name: "lookup error keeps the splice", mutate: func(r *fakeRouter) { r.set("", "", false, errors.New("valkey down")) }},
		{name: "unchanged route keeps the splice", mutate: func(*fakeRouter) {}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			te := newTestEdge(t, cfg, nil)
			te.rtr.set("node-a", "conn-1", true, nil)
			client := newScriptConn("198.51.100.72", nil)
			done := runTunnel(te, client, "abcdef012345.example.test")
			phone := waitPhone(t, te, 0)
			tc.mutate(te.rtr)
			select {
			case <-done:
				if !tc.wantEnd {
					t.Fatal("the splice must keep running")
				}
			case <-time.After(2500 * time.Millisecond):
				if tc.wantEnd {
					t.Fatal("the orphaned splice was not ended by the route check")
				}
				tunneltest.CloseOrLog(t, phone)
				waitDone(t, done, 5*time.Second)
				return
			}
			var end *PublicEvent
			for _, ev := range te.sink.kinds() {
				if ev.Event == "end" {
					end = &ev
				}
			}
			if end == nil || end.CloseReason != store.ClosePhoneClose {
				t.Fatalf("end event = %+v, want close_reason %q", end, store.ClosePhoneClose)
			}
			if !client.isClosed() {
				t.Fatal("the client socket must be closed")
			}
			if _, err := phone.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("the dial-back socket must be closed, read = %v", err)
			}
			if got := freeSlots(t, te, "abcdef012345", cfg.Concurrent); got != cfg.Concurrent {
				t.Fatalf("the stream slot leaked: %d/%d free", got, cfg.Concurrent)
			}
		})
	}
}

func TestEdge_EvictConnStreams_OnlyThatConnection(t *testing.T) {
	tests := []struct {
		reason string
		want   string
	}{
		{reason: store.CloseBanEvict, want: store.CloseBanEvict},
		{reason: store.CloseAdminTerminate, want: store.CloseAdminTerminate},
		{reason: store.ClosePhoneClose, want: store.ClosePhoneClose},
		{reason: "liveness-timeout", want: store.ClosePhoneClose},
	}
	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			cfg := baseConfig()
			cfg.IdleTimeout = 0
			cfg.MinRate = 0
			te := newTestEdge(t, cfg, nil)
			client := newScriptConn("203.0.113.50", nil)
			far := newScriptConn("203.0.113.50", nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			victim := &activeStream{tunnel: "t1", connID: "conn-1", parent: context.Background(), started: time.Now(), cancel: cancel}
			victim.lastAct.Store(time.Now().UnixNano())
			var otherCancels atomic.Int32
			otherConn := &activeStream{tunnel: "t1", connID: "conn-2", cancel: func() { otherCancels.Add(1) }}
			otherTunnel := &activeStream{tunnel: "t2", connID: "conn-1", cancel: func() { otherCancels.Add(1) }}
			for _, s := range []*activeStream{victim, otherConn, otherTunnel} {
				te.e.trackStream(s)
				defer te.e.untrackStream(s)
			}
			reasonCh := make(chan string, 1)
			go func() { reasonCh <- te.e.splice(ctx, "t1", client, far, victim) }()
			time.Sleep(20 * time.Millisecond)

			if !te.e.EvictConnStreams("t1", "conn-1", tc.reason) {
				t.Fatal("EvictConnStreams must report the ended splice")
			}
			select {
			case got := <-reasonCh:
				if got != tc.want {
					t.Fatalf("close_reason = %q, want %q", got, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the splice of that connection was not ended")
			}
			if otherCancels.Load() != 0 {
				t.Fatal("splices of another connection or tunnel must keep running")
			}
			if te.e.EvictConnStreams("t3", "conn-9", tc.reason) {
				t.Fatal("no splice matches: EvictConnStreams must report false")
			}
		})
	}
}

// newBytesReader returns a reader over b that yields io.EOF after the bytes.
func newBytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b   []byte
	off int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

const capTunnel = "abcdef012345"

const capSNI = capTunnel + ".example.test"

func fillSlots(t *testing.T, te *testEdge, n int) {
	t.Helper()
	for i := range n {
		ok, err := te.e.lim.AcquireStream(context.Background(), capTunnel, fmt.Sprintf("held-%d", i), n)
		if err != nil || !ok {
			t.Fatalf("hold slot %d: ok=%v err=%v", i, ok, err)
		}
	}
}

func openCalls(te *testEdge) int {
	te.opener.mu.Lock()
	defer te.opener.mu.Unlock()
	return len(te.opener.calls)
}

func countStr(ss []string, want string) int {
	n := 0
	for _, s := range ss {
		if s == want {
			n++
		}
	}
	return n
}

func TestEdge_HandleTunnel_StreamCapFreesRemoteSlot(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	cfg.Concurrent = 2
	te := newTestEdge(t, cfg, nil)
	te.rtr.set("node-a", "conn-1", true, nil)
	fillSlots(t, te, cfg.Concurrent)
	var asked string
	te.slots.free = func(ctx context.Context, tunnel string) bool {
		asked = tunnel
		return te.e.lim.ReleaseStream(ctx, tunnel, "held-0") == nil
	}

	done := runTunnel(te, newScriptConn("198.51.100.80", nil), capSNI)
	phone := waitPhone(t, te, 0)
	tunneltest.CloseOrLog(t, phone)
	waitDone(t, done, 5*time.Second)

	if containsStr(te.rec.rejectReasons(), "stream-cap") {
		t.Fatalf("a slot freed on another node must admit the connection, rejects=%v", te.rec.rejectReasons())
	}
	if got := te.slots.calls.Load(); got != 1 || asked != capTunnel {
		t.Fatalf("FreeRemoteSlot calls=%d tunnel=%q, want 1 call for %q", got, asked, capTunnel)
	}
}

func TestEdge_HandleTunnel_StreamCapNothingToFree(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		free func(context.Context, string) bool
	}{
		{name: "no node has an evictable stream", free: func(context.Context, string) bool { return false }},
		{name: "a slot may have been freed but was not", free: func(context.Context, string) bool { return true }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := baseConfig()
			cfg.Concurrent = 2
			te := newTestEdge(t, cfg, nil)
			te.rtr.set("node-a", "conn-1", true, nil)
			fillSlots(t, te, cfg.Concurrent)
			te.slots.free = tc.free

			client := newScriptConn("198.51.100.81", nil)
			waitDone(t, runTunnel(te, client, capSNI), 5*time.Second)

			if got := countStr(te.rec.rejectReasons(), "stream-cap"); got != 1 || !client.isClosed() {
				t.Fatalf("stream-cap rejects=%d closed=%v, want one rejection and the client closed", got, client.isClosed())
			}
			if got := openCalls(te); got != 0 {
				t.Fatalf("a refused connection must request no OPEN, got %d", got)
			}
			if got := te.slots.calls.Load(); got != 1 {
				t.Fatalf("FreeRemoteSlot calls = %d, want 1", got)
			}
		})
	}
}

func TestEdge_HandleTunnel_RemoteSlotOnlyWhenLocalHasNone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(t *testing.T, te *testEdge)
	}{
		{name: "local eviction frees a slot", setup: func(t *testing.T, te *testEdge) {
			fillSlots(t, te, 2)
			te.e.trackStream(&activeStream{tunnel: capTunnel, cancel: func() {}, release: func() {
				if err := te.e.lim.ReleaseStream(context.Background(), capTunnel, "held-0"); err != nil {
					t.Errorf("release the local victim's slot: %v", err)
				}
			}})
		}},
		{name: "cap not reached", setup: func(*testing.T, *testEdge) {}},
		{name: "acquire error fails open", setup: func(t *testing.T, te *testEdge) {
			mr := miniredis.RunT(t)
			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
			te.e.lim = &countingLimiter{Limiter: limit.NewLimiter(rdb, 1<<30, 1<<40, 1<<40, time.Hour), acquireErr: errors.New("valkey down")}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := baseConfig()
			cfg.Concurrent = 2
			te := newTestEdge(t, cfg, nil)
			te.rtr.set("node-a", "conn-1", true, nil)
			tc.setup(t, te)

			done := runTunnel(te, newScriptConn("198.51.100.82", nil), capSNI)
			phone := waitPhone(t, te, 0)
			tunneltest.CloseOrLog(t, phone)
			waitDone(t, done, 5*time.Second)

			if got := te.slots.calls.Load(); got != 0 {
				t.Fatalf("FreeRemoteSlot calls = %d, want 0", got)
			}
		})
	}
}

func TestEdge_PendingSlotNeverEvicted(t *testing.T) {
	t.Parallel()
	cfg := baseConfig()
	cfg.Concurrent = 1
	cfg.DialBackTimeout = time.Minute
	te := newTestEdge(t, cfg, nil)
	te.rtr.set("node-a", "conn-1", true, nil)
	te.dial.never = true

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		te.e.handleTunnel(ctx, newScriptConn("198.51.100.83", nil), ClientHelloInfo{SNI: capSNI})
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	deadline := time.Now().Add(5 * time.Second)
	for openCalls(te) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first connection never asked for its dial-back")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if idle, ok := te.e.SlotCandidate(capTunnel); ok || idle != 0 {
		t.Fatalf("SlotCandidate = (%v, %v), want (0, false) for a pending slot", idle, ok)
	}
	if te.e.FreeSlot(capTunnel) {
		t.Fatal("a pending slot must never be evicted")
	}
	second := newScriptConn("198.51.100.84", nil)
	waitDone(t, runTunnel(te, second, capSNI), 5*time.Second)
	if got := countStr(te.rec.rejectReasons(), "stream-cap"); got != 1 || !second.isClosed() {
		t.Fatalf("stream-cap rejects=%d closed=%v, want the second connection refused", got, second.isClosed())
	}
	if got := te.slots.calls.Load(); got != 1 {
		t.Fatalf("FreeRemoteSlot calls = %d, want 1", got)
	}
	select {
	case <-done:
		t.Fatal("the pending connection must still be waiting for its dial-back")
	default:
	}
	cancel()
	waitDone(t, done, 5*time.Second)
}
