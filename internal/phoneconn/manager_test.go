package phoneconn

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type fakeRouter struct {
	bound    map[string]time.Time // name → startedAt
	hbResult router.HeartbeatResult
	unbound  map[string]bool
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{bound: map[string]time.Time{}, unbound: map[string]bool{}}
}
func (f *fakeRouter) BindRoute(_ context.Context, name, _, _, _ string, startedAt time.Time) error {
	f.bound[name] = startedAt
	return nil
}
func (f *fakeRouter) Heartbeat(_ context.Context, _, _ string) (router.HeartbeatResult, error) {
	return f.hbResult, nil
}
func (f *fakeRouter) Unbind(_ context.Context, name, _ string) error {
	f.unbound[name] = true
	return nil
}
func (f *fakeRouter) BindRouteIfAbsentOrOwner(_ context.Context, name, _, _, _ string, s time.Time) (router.SelfHealResult, error) {
	f.bound[name] = s
	return router.SelfHealBound, nil
}

type fakeRec struct{ opens, closes int }

func (r *fakeRec) PhoneConnOpen()        { r.opens++ }
func (r *fakeRec) PhoneConnClose(string) { r.closes++ }

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
	return &conn{name: name, fingerprint: "sha256:fp", connID: "aabbccddee",
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
	if got := fr.bound["abc"]; !got.Equal(c.sessionStart) {
		t.Errorf("route startedAt = %v, want %v", got, c.sessionStart)
	}
	if rec.opens != 1 {
		t.Error("PhoneConnOpen not recorded")
	}
	if len(st.ConnLogs) != 1 || st.ConnLogs[0].Event != "start" || st.ConnLogs[0].Type != "phone" {
		t.Errorf("start event not written: %+v", st.ConnLogs)
	}
	teardown()
	if !fr.unbound["abc"] {
		t.Error("route not unbound on teardown")
	}
	var endSeen bool
	for _, e := range st.ConnLogs {
		if e.Event == "end" {
			endSeen = true
		}
	}
	if !endSeen || rec.closes != 1 {
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

// TestCancelPendingClosesRacedDelivery covers the dial-back cancel/deliver race (R3-001): when
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

var _ = store.Event{}
