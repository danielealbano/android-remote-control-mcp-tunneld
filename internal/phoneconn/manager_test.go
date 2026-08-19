package phoneconn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// syncBuf is a concurrency-safe io.Writer + reader for capturing slog output from a background goroutine.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestHeartbeatLoop_LogsPersistentError verifies a persistent route-heartbeat error is logged at Warn
// with identifiers (a silent failure would let route:{name} TTL-expire with no operator signal).
func TestHeartbeatLoop_LogsPersistentError(t *testing.T) {
	fr := newFakeRouter()
	fr.hbErr = errors.New("valkey unreachable")
	buf := &syncBuf{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := NewManager(Config{Router: fr, Logs: tunneltest.NewStore(), Recorder: &fakeRec{},
		NodeID: "nodeA", NodeHost: "host-a", NodeStart: "2026-08-18T00:00:00Z",
		RouteTTL: 30 * time.Millisecond, Logger: logger})
	c := newConn("abc")
	ctx, cancel := context.WithCancel(context.Background())
	go m.heartbeatLoop(ctx, c)

	deadline := time.After(2 * time.Second)
	for !strings.Contains(buf.String(), "heartbeat failed") {
		select {
		case <-deadline:
			cancel()
			<-c.hbDone
			t.Fatalf("a persistent heartbeat error must be logged at Warn; log = %q", buf.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-c.hbDone
}

type fakeRouter struct {
	mu       sync.Mutex
	bound    map[string]string // name → bound connID
	hbResult router.HeartbeatResult
	hbErr    error // when set, Heartbeat returns it (persistent-failure test)
	unbound  map[string]bool
	collide  int      // upcoming BindRoute calls that return router.ErrConnIDCollision
	bindErr  error    // when set (and not colliding), BindRoute returns it
	calls    []string // ordered router-method call log (teardown-ordering assertions)
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{bound: map[string]string{}, unbound: map[string]bool{}}
}
func (f *fakeRouter) BindRoute(_ context.Context, name, _, _, connID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "BindRoute")
	if f.collide > 0 {
		f.collide--
		return router.ErrConnIDCollision
	}
	if f.bindErr != nil {
		return f.bindErr
	}
	f.bound[name] = connID
	return nil
}
func (f *fakeRouter) Heartbeat(_ context.Context, _, _ string) (router.HeartbeatResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "Heartbeat")
	res, err := f.hbResult, f.hbErr
	f.mu.Unlock()
	return res, err
}
func (f *fakeRouter) Unbind(_ context.Context, name, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Unbind")
	f.unbound[name] = true
	return nil
}
func (f *fakeRouter) BindRouteIfAbsentOrOwner(_ context.Context, name, _, _, connID string) (router.SelfHealResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "BindRouteIfAbsentOrOwner")
	f.bound[name] = connID
	return router.SelfHealBound, nil
}

func (f *fakeRouter) boundConnID(name string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.bound[name]
	return v, ok
}

func (f *fakeRouter) wasUnbound(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unbound[name]
}

type fakeRec struct{ opens, closes atomic.Int64 }

func (r *fakeRec) PhoneConnOpen()        { r.opens.Add(1) }
func (r *fakeRec) PhoneConnClose(string) { r.closes.Add(1) }

func newMgr(t *testing.T) (*Manager, *fakeRouter, *tunneltest.Store, *fakeRec) {
	t.Helper()
	fr := newFakeRouter()
	st := tunneltest.NewStore()
	rec := &fakeRec{}
	m := NewManager(Config{Router: fr, Logs: st, Recorder: rec, NodeID: "nodeA", NodeHost: "host-a",
		NodeStart: "2026-08-18T00:00:00Z", RouteTTL: 30 * time.Second})
	return m, fr, st, rec
}

func newConn(name string) *conn {
	return &conn{name: name, fingerprint: "sha256:fp", keyFP: "sha256:keyfp", certSerial: "0a1b",
		connID:       "aabbccdd",
		sessionStart: time.Unix(1_700_000_000, 0), send: make(chan []byte, 8),
		pending: map[string]chan DataStream{}, cancel: func() {},
		hbDone: make(chan struct{})}
}

func TestRegisterBindsAndLogsStart(t *testing.T) {
	m, fr, st, rec := newMgr(t)
	c := newConn("abc")
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	teardown, err := m.register(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	go m.heartbeatLoop(ctx, c) // teardown waits on the heartbeat loop's exit (hbDone)
	if got, ok := fr.boundConnID("abc"); !ok || got != c.connID {
		t.Errorf("route bound connID = %q, want %q", got, c.connID)
	}
	if rec.opens.Load() != 1 {
		t.Error("PhoneConnOpen not recorded")
	}
	if len(st.ConnLogs) != 1 || st.ConnLogs[0].Event != "start" || st.ConnLogs[0].Type != "phone" {
		t.Errorf("start event not written: %+v", st.ConnLogs)
	}
	// The event carries the KEY fingerprint (registry correlation) + the cert serial (forensics).
	if st.ConnLogs[0].IdentityKeyFP != "sha256:keyfp" || st.ConnLogs[0].IdentityCertSerial != "0a1b" {
		t.Errorf("phone event must carry identity_key_fpr + identity_cert_serial: %+v", st.ConnLogs[0])
	}
	teardown()
	if !fr.wasUnbound("abc") {
		t.Error("route not unbound on teardown")
	}
	var endSeen bool
	for _, e := range st.ConnLogs {
		if e.Event == "end" {
			endSeen = true
		}
	}
	if !endSeen || rec.closes.Load() != 1 {
		t.Error("end event / PhoneConnClose missing")
	}
}

// TestManager_Register_RerollsOnCollision covers the connID-collision re-roll: BindRoute returning
// ErrConnIDCollision makes register re-mint and retry (bounded); three collisions in a row give up.
func TestManager_Register_RerollsOnCollision(t *testing.T) {
	m, fr, _, _ := newMgr(t)
	fr.collide = 2 // two collisions, then the third connID binds
	c := newConn("abc")
	first := c.connID
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	teardown, err := m.register(ctx, c)
	if err != nil {
		t.Fatalf("register must succeed after re-rolling past collisions: %v", err)
	}
	go m.heartbeatLoop(ctx, c) // teardown waits on the heartbeat loop's exit (hbDone)
	defer teardown()
	if c.connID == first {
		t.Error("a collision must re-mint the connID")
	}
	if got, ok := fr.boundConnID("abc"); !ok || got != c.connID {
		t.Errorf("bound connID = %q, want the re-minted %q", got, c.connID)
	}

	m2, fr2, _, _ := newMgr(t)
	fr2.collide = 3 // never resolves within the bound
	if _, err := m2.register(context.Background(), newConn("xyz")); !errors.Is(err, router.ErrConnIDCollision) {
		t.Fatalf("three collisions must fail with ErrConnIDCollision, got %v", err)
	}
}

func TestEvictBanned(t *testing.T) {
	m, _, _, _ := newMgr(t)
	c := newConn("abc")
	_, _ = m.register(context.Background(), c)
	m.EvictBanned(func(name, fp string) bool { return name == "abc" })
	if !c.isClosed() {
		t.Error("banned connection should be closed")
	}
}

// TestCloseAll covers the server-drain path: every live connection is closed with the given reason, so
// each handler's teardown runs the owner-conditional unbind and writes the end event with that reason.
func TestCloseAll(t *testing.T) {
	m, fr, st, _ := newMgr(t)
	c1 := newConn("abc")
	c2 := newConn("xyz")
	ctx1, cancel1 := context.WithCancel(context.Background())
	c1.cancel = cancel1
	ctx2, cancel2 := context.WithCancel(context.Background())
	c2.cancel = cancel2
	td1, err := m.register(ctx1, c1)
	if err != nil {
		t.Fatal(err)
	}
	td2, err := m.register(ctx2, c2)
	if err != nil {
		t.Fatal(err)
	}
	go m.heartbeatLoop(ctx1, c1) // teardown waits on each heartbeat loop's exit (hbDone)
	go m.heartbeatLoop(ctx2, c2)

	m.CloseAll(store.CloseServerShutdown)
	if !c1.isClosed() || !c2.isClosed() {
		t.Fatal("CloseAll must close every live connection")
	}
	if c1.closeReason() != store.CloseServerShutdown || c2.closeReason() != store.CloseServerShutdown {
		t.Errorf("close reasons = %q, %q, want %q", c1.closeReason(), c2.closeReason(), store.CloseServerShutdown)
	}

	// The handlers' deferred teardowns then unbind and write the end events with the drain reason.
	td1()
	td2()
	if !fr.wasUnbound("abc") || !fr.wasUnbound("xyz") {
		t.Error("teardown after CloseAll must unbind both routes")
	}
	for _, e := range st.ConnLogs {
		if e.Event == "end" && e.CloseReason != store.CloseServerShutdown {
			t.Errorf("end event close_reason = %q, want %q", e.CloseReason, store.CloseServerShutdown)
		}
	}
}

func TestOpenStreamNoConn(t *testing.T) {
	m, _, _, _ := newMgr(t)
	if _, err := m.OpenStream(context.Background(), "missing", "s1"); err != ErrNoConn {
		t.Errorf("expected ErrNoConn, got %v", err)
	}
}

func TestOpenStreamDialbackCorrelates(t *testing.T) {
	m, _, _, _ := newMgr(t)
	c := newConn("abc")
	_, _ = m.register(context.Background(), c)

	got := make(chan DataStream, 1)
	go func() {
		ds, err := m.OpenStream(context.Background(), "abc", "s1")
		if err == nil {
			got <- ds
		}
	}()
	// The OPEN frame is queued to the phone.
	select {
	case frame := <-c.send:
		if len(frame) == 0 {
			t.Fatal("empty OPEN frame")
		}
	case <-time.After(time.Second):
		t.Fatal("OPEN not sent")
	}
	// The phone's data stream arrives and is delivered to the waiter.
	fake := &fakeDataStream{}
	if !m.deliverStream("abc", "s1", fake) {
		t.Fatal("deliverStream failed")
	}
	select {
	case ds := <-got:
		if ds != fake {
			t.Error("wrong stream delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("stream not delivered to OpenStream")
	}
}

// TestDeliverStream_RefusesClosedConn verifies a dial-back arriving after the phone conn was closed
// (e.g. a ban reload evicted it) is refused EVEN WHEN a matching waiter is still pending, so no splice
// starts on a torn-down connection. The pending waiter is essential: without it, deliverStream returns
// false via the pending-miss path regardless of the c.closed guard, and the test would not discriminate.
func TestDeliverStream_RefusesClosedConn(t *testing.T) {
	m, _, _, _ := newMgr(t)
	c := newConn("abc")
	if _, err := m.register(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	waiter := make(chan DataStream, 1)
	c.mu.Lock()
	c.pending["s1"] = waiter
	c.mu.Unlock()
	c.close("ban-evict")
	if m.deliverStream("abc", "s1", &fakeDataStream{}) {
		t.Fatal("deliverStream must refuse delivery once the conn is closed")
	}
	select {
	case <-waiter:
		t.Fatal("a closed conn's waiter must NOT receive a delivery")
	default:
	}
}

// TestOpenStreamTimesOut covers the bounded dial-back wait both the local (edge.openFar) and the mesh
// (bridgeAdapter.OpenMesh) paths rely on: a connected phone that never opens /data must make OpenStream
// return within the caller's deadline and drop the pending waiter (releasing the caller's stream slot).
func TestOpenStreamTimesOut(t *testing.T) {
	m, _, _, _ := newMgr(t)
	c := newConn("abc")
	_, _ = m.register(context.Background(), c)
	go func() { <-c.send }() // accept the OPEN frame, then never deliver a stream

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := m.OpenStream(ctx, "abc", "s1"); err == nil {
		t.Fatal("OpenStream must fail when the phone never opens the dial-back stream")
	}
	if time.Since(start) > time.Second {
		t.Fatal("OpenStream did not honour the dial-back deadline")
	}
	c.mu.Lock()
	_, pending := c.pending["s1"]
	c.mu.Unlock()
	if pending {
		t.Error("a timed-out OpenStream must drop the pending waiter")
	}
}

// TestManager_OpenStream_DuplicateRefused covers the pending-stream duplicate refusal: a second
// OpenStream with an already-pending stream id is refused (ErrDuplicateStreamID) and the first waiter
// stays intact.
func TestManager_OpenStream_DuplicateRefused(t *testing.T) {
	m, _, _, _ := newMgr(t)
	c := newConn("abc")
	_, _ = m.register(context.Background(), c)

	go func() { <-c.send }() // accept the first OPEN frame; never deliver a stream
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	firstDone := make(chan error, 1)
	go func() {
		_, err := m.OpenStream(ctx1, "abc", "dup1")
		firstDone <- err
	}()
	waitCond(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		_, ok := c.pending["dup1"]
		return ok
	})

	if _, err := m.OpenStream(context.Background(), "abc", "dup1"); !errors.Is(err, ErrDuplicateStreamID) {
		t.Fatalf("a duplicate pending stream id must be refused, got %v", err)
	}
	c.mu.Lock()
	_, stillPending := c.pending["dup1"]
	c.mu.Unlock()
	if !stillPending {
		t.Fatal("the first waiter must remain pending after a duplicate is refused")
	}
}

func TestHeartbeatNotOwnerCloses(t *testing.T) {
	m, fr, _, _ := newMgr(t)
	fr.hbResult = router.HeartbeatNotOwner
	c := newConn("abc")
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	_, _ = m.register(ctx, c)
	m.routeTTL = 3 * time.Millisecond
	go m.heartbeatLoop(ctx, c)
	deadline := time.After(time.Second)
	for !c.isClosed() {
		select {
		case <-deadline:
			t.Fatal("not-owner heartbeat should close the connection")
		case <-time.After(2 * time.Millisecond):
		}
	}
}

type fakeDataStream struct{}

func (fakeDataStream) Read([]byte) (int, error)    { return 0, nil }
func (fakeDataStream) Write(p []byte) (int, error) { return len(p), nil }
func (fakeDataStream) Close() error                { return nil }

// TestCancelPendingClosesRacedDelivery covers the dial-back cancel/deliver race: when
// deliverStream delivers a stream to the buffered waiter at the same moment the dial-back deadline fires,
// cancelPending MUST close the orphaned stream (so its /data handler cannot leak) and drop the pending
// registration.
func TestCancelPendingClosesRacedDelivery(t *testing.T) {
	c := newConn("abc")
	waiter := make(chan DataStream, 1)
	c.pending["s1"] = waiter
	fake := &closeableStream{}
	waiter <- fake // deliverStream raced in and delivered before OpenStream observed the cancel

	c.cancelPending("s1", waiter)

	if !fake.isClosed() {
		t.Fatal("a stream delivered concurrently with the dial-back cancel must be closed, not orphaned")
	}
	if _, ok := c.pending["s1"]; ok {
		t.Fatal("cancelPending must drop the pending registration")
	}
}

type closeableStream struct {
	mu     sync.Mutex
	closed bool
}

func (s *closeableStream) Read([]byte) (int, error)    { return 0, nil }
func (s *closeableStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *closeableStream) Close() error                { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }
func (s *closeableStream) isClosed() bool              { s.mu.Lock(); defer s.mu.Unlock(); return s.closed }

// TestManager_Teardown_StopsHeartbeatBeforeUnbind proves teardown cancels the conn and waits for
// the heartbeat loop (incl. any in-flight self-heal) to exit BEFORE unbinding, so no Heartbeat or
// self-heal rebind can run after the Unbind.
func TestManager_Teardown_StopsHeartbeatBeforeUnbind(t *testing.T) {
	m, fr, _, _ := newMgr(t)
	fr.hbResult = router.HeartbeatMissing // the loop self-heals (BindRouteIfAbsentOrOwner) every tick
	m.routeTTL = 3 * time.Millisecond
	c := newConn("abc")
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	teardown, err := m.register(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	go m.heartbeatLoop(ctx, c)

	// Let the heartbeat loop tick a few times before tearing down.
	waitCond(t, func() bool {
		fr.mu.Lock()
		defer fr.mu.Unlock()
		hb := 0
		for _, name := range fr.calls {
			if name == "Heartbeat" {
				hb++
			}
		}
		return hb >= 2
	})

	teardown() // c.close → cancel → heartbeat exits (hbDone) BEFORE Unbind

	fr.mu.Lock()
	defer fr.mu.Unlock()
	unbindIdx := -1
	for i, name := range fr.calls {
		if name == "Unbind" {
			unbindIdx = i
		}
	}
	if unbindIdx < 0 {
		t.Fatalf("teardown must Unbind; calls=%v", fr.calls)
	}
	for _, name := range fr.calls[unbindIdx+1:] {
		if name == "Heartbeat" || name == "BindRouteIfAbsentOrOwner" {
			t.Fatalf("no heartbeat/self-heal may run after Unbind, saw %q; calls=%v", name, fr.calls)
		}
	}
}

// TestManager_ConcurrentSameNameBind_LocalMatchesValkey proves two concurrent registers for one
// name (backed by a real miniredis registry) are serialized by the striped bind lock, so the conn left
// in the local map is always the one whose connID Valkey holds.
func TestManager_ConcurrentSameNameBind_LocalMatchesValkey(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	reg := router.NewRegistry(rdb, 30*time.Second)
	st := tunneltest.NewStore()
	m := NewManager(Config{Router: reg, Logs: st, Recorder: &fakeRec{}, NodeID: "nodeA",
		NodeHost: "host-a", NodeStart: "2026-08-19T00:00:00Z", RouteTTL: 30 * time.Second})

	const name = "concurrent01"
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := newConn(name)
			c.connID = fmt.Sprintf("cid%05d", i) // distinct ids so both bind (same fp → no conflict)
			if _, err := m.register(context.Background(), c); err != nil {
				t.Errorf("register %d failed: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	m.mu.RLock()
	surviving := m.conns[name]
	m.mu.RUnlock()
	if surviving == nil {
		t.Fatal("one conn must survive in the local map")
	}
	_, _, storedConnID, ok, err := reg.LookupRoute(context.Background(), name)
	if err != nil || !ok {
		t.Fatalf("route must be bound: ok=%v err=%v", ok, err)
	}
	if surviving.connID != storedConnID {
		t.Fatalf("local survivor connID %q != Valkey connID %q (bind not serialized)", surviving.connID, storedConnID)
	}
}

// TestHeartbeatLoop_TinyRouteTTLNoPanic proves a pathological --route-ttl (routeTTL/3 == 0) must
// not panic time.NewTicker; the floor guard substitutes a 1s interval.
func TestHeartbeatLoop_TinyRouteTTLNoPanic(t *testing.T) {
	m, _, _, _ := newMgr(t)
	m.routeTTL = time.Nanosecond // routeTTL/3 == 0 → the floor guard must prevent a NewTicker panic
	c := newConn("tiny01")
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	if _, err := m.register(ctx, c); err != nil {
		t.Fatal(err)
	}
	go m.heartbeatLoop(ctx, c)
	cancel() // let the loop exit promptly; the test only asserts NewTicker did not panic
	select {
	case <-c.hbDone:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop did not exit")
	}
}
