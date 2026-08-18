package phoneconn

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type fakeRouter struct {
	mu       sync.Mutex
	bound    map[string]time.Time // name → startedAt
	hbResult router.HeartbeatResult
	unbound  map[string]bool
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{bound: map[string]time.Time{}, unbound: map[string]bool{}}
}
func (f *fakeRouter) BindRoute(_ context.Context, name, _, _, _ string, startedAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound[name] = startedAt
	return nil
}
func (f *fakeRouter) Heartbeat(_ context.Context, _, _ string) (router.HeartbeatResult, error) {
	return f.hbResult, nil
}
func (f *fakeRouter) Unbind(_ context.Context, name, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unbound[name] = true
	return nil
}
func (f *fakeRouter) BindRouteIfAbsentOrOwner(_ context.Context, name, _, _, _ string, s time.Time) (router.SelfHealResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bound[name] = s
	return router.SelfHealBound, nil
}

func (f *fakeRouter) boundAt(name string) (time.Time, bool) {
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
		connID:       "aabbccddee",
		sessionStart: time.Unix(1_700_000_000, 0), send: make(chan []byte, 8),
		pending: map[string]chan DataStream{}, cancel: func() {}}
}

func TestRegisterBindsAndLogsStart(t *testing.T) {
	m, fr, st, rec := newMgr(t)
	c := newConn("abc")
	teardown, err := m.register(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := fr.boundAt("abc"); !ok || !got.Equal(c.sessionStart) {
		t.Errorf("route startedAt = %v, want %v", got, c.sessionStart)
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
	td1, err := m.register(context.Background(), c1)
	if err != nil {
		t.Fatal(err)
	}
	td2, err := m.register(context.Background(), c2)
	if err != nil {
		t.Fatal(err)
	}

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

// TestOpenStreamTimesOut covers the bounded dial-back wait both the local (edge.openFar) and the mesh
// (bridgeAdapter.BridgeMesh) paths rely on: a connected phone that never opens /data must make OpenStream
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
