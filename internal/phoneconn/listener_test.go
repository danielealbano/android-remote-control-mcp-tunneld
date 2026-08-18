package phoneconn

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// flushRecorder is an httptest.ResponseRecorder that satisfies http.Flusher and tracks writes safely
// across goroutines (serveControl writes from its own goroutine in these tests).
type flushRecorder struct {
	mu sync.Mutex
	rr *httptest.ResponseRecorder
}

func newFlushRecorder() *flushRecorder { return &flushRecorder{rr: httptest.NewRecorder()} }

func (f *flushRecorder) Header() http.Header { f.mu.Lock(); defer f.mu.Unlock(); return f.rr.Header() }
func (f *flushRecorder) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rr.Write(p)
}
func (f *flushRecorder) WriteHeader(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rr.WriteHeader(code)
}
func (f *flushRecorder) Flush() {}

func (f *flushRecorder) code() int { f.mu.Lock(); defer f.mu.Unlock(); return f.rr.Code }

// blockedReader blocks reads until closed (a phone that sends nothing on the control stream).
type blockedReader struct {
	ch   chan struct{}
	once sync.Once
}

func newBlockedReader() *blockedReader { return &blockedReader{ch: make(chan struct{})} }
func (b *blockedReader) Read([]byte) (int, error) {
	<-b.ch
	return 0, io.EOF
}
func (b *blockedReader) close() { b.once.Do(func() { close(b.ch) }) }

func newTestHandler(t *testing.T, pending int, ping time.Duration) (*Handler, *Manager) {
	t.Helper()
	m, _, _, _ := newMgr(t)
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: ping, StreamPending: pending})
	return h, m
}

// TestServeControlReleasesPendingSlotAfterBind covers the --limit-stream-pending semantics: the
// semaphore bounds concurrent PRE-BIND handshakes only — a BOUND phone must not hold a slot, so a
// second phone binds fine with StreamPending=1.
func TestServeControlReleasesPendingSlotAfterBind(t *testing.T) {
	h, m := newTestHandler(t, 1, time.Hour)

	start := func(name string) (*blockedReader, context.CancelFunc, chan struct{}) {
		body := newBlockedReader()
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("GET", "/control", body).WithContext(ctx)
		done := make(chan struct{})
		go func() {
			h.serveControl(newFlushRecorder(), req, name, "sha256:fp-"+name)
			close(done)
		}()
		return body, cancel, done
	}

	bodyA, cancelA, doneA := start("phonea")
	waitCond(t, func() bool { return m.HasConn("phonea") })

	// With phone A BOUND (slot released), phone B must also bind under StreamPending=1.
	bodyB, cancelB, doneB := start("phoneb")
	waitCond(t, func() bool { return m.HasConn("phoneb") })

	cancelA()
	cancelB()
	bodyA.close()
	bodyB.close()
	<-doneA
	<-doneB
}

// TestServeControlPendingCapRefuses covers the pre-bind refusal: a saturated pre-bind semaphore
// answers 503 without touching the manager.
func TestServeControlPendingCapRefuses(t *testing.T) {
	h, m := newTestHandler(t, 1, time.Hour)
	h.sem <- struct{}{} // saturate the pre-bind slot

	rec := newFlushRecorder()
	req := httptest.NewRequest("GET", "/control", newBlockedReader())
	h.serveControl(rec, req, "phonec", "sha256:fp")
	if rec.code() != 503 {
		t.Fatalf("saturated pre-bind semaphore must answer 503, got %d", rec.code())
	}
	if m.HasConn("phonec") {
		t.Fatal("a refused handshake must not register a connection")
	}
}

// TestLivenessTimeoutCloses covers the missed-PONG teardown: a phone that never PONGs is closed with
// the liveness reason after livenessMissedPings intervals.
func TestLivenessTimeoutCloses(t *testing.T) {
	h, m := newTestHandler(t, 4, 5*time.Millisecond)
	body := newBlockedReader()
	defer body.close()
	req := httptest.NewRequest("GET", "/control", body)
	done := make(chan struct{})
	go func() {
		h.serveControl(newFlushRecorder(), req, "phoned", "sha256:fp")
		close(done)
	}()
	waitCond(t, func() bool { return m.HasConn("phoned") })

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a silent phone must be torn down by the liveness bound")
	}
	c, ok := m.lookup("phoned")
	if ok && c.closeReason() != "liveness-timeout" {
		t.Fatalf("close reason = %q, want liveness-timeout", c.closeReason())
	}
}

// TestReadPumpPongStampsLiveness covers the PONG path: a PONG frame advances lastPong; a malformed
// frame tears the connection down with protocol-error.
func TestReadPumpPongStampsLiveness(t *testing.T) {
	h, _ := newTestHandler(t, 4, time.Hour)
	c := newConn("phonee")
	before := c.lastPong.Load()

	pong, _ := wire.EncodeControl(wire.CtrlPong, nil)
	h.readPump(bytes.NewReader(pong), c) // EOF after the frame → phone-close
	if c.lastPong.Load() <= before {
		t.Fatal("a PONG frame must advance lastPong")
	}

	c2 := newConn("phonef")
	// A frame with an oversize length prefix is malformed: the read fails and tears the conn down.
	bad := []byte{0x01, 0xff, 0xff, 0xff, 0xff}
	h.readPump(bytes.NewReader(bad), c2)
	if c2.closeReason() != "phone-close" {
		t.Fatalf("close reason = %q, want phone-close", c2.closeReason())
	}
	if !c2.isClosed() {
		t.Fatal("a malformed frame must tear the connection down")
	}
}

// TestServeHTTPIPBanFirst covers the peer-IP ban gate: a banned IP is refused BEFORE any identity
// check (no client cert present here — the ban answer must come first).
func TestServeHTTPIPBanFirst(t *testing.T) {
	m, _, _, _ := newMgr(t)
	banned := netip.MustParseAddr("198.51.100.99")
	h := NewHandler(HandlerConfig{Manager: m, PingInterval: time.Hour, StreamPending: 4,
		BanIP: func(a netip.Addr) bool { return a == banned }})

	req := httptest.NewRequest("GET", "/control", nil)
	req.RemoteAddr = "198.51.100.99:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("banned peer IP must get 403, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/control", nil)
	req2.RemoteAddr = "198.51.100.98:40000"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code == 403 && rec2.Body.String() == "banned\n" {
		t.Fatal("an unbanned IP must not hit the ban gate")
	}
}

// TestServeDataNoWaiterIs404 covers the undeliverable dial-back stream: serveData must answer a REAL
// 404 (no premature 200) when no waiter exists for the stream id.
func TestServeDataNoWaiterIs404(t *testing.T) {
	h, _ := newTestHandler(t, 4, time.Hour)
	rec := newFlushRecorder()
	req := httptest.NewRequest("POST", "/data", newBlockedReader())
	req.Header.Set("X-Stream-Id", "nosuch")
	h.serveData(rec, req, "phoneg")
	if rec.code() != 404 {
		t.Fatalf("undeliverable stream must answer 404, got %d", rec.code())
	}
}

func waitCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}
