package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestCrashOnPanic(t *testing.T) {
	t.Parallel()
	errWant := errors.New("worker failed")
	if err := crashOnPanic(context.Background(), slog.New(slog.DiscardHandler), "worker", func() error { return errWant })(); !errors.Is(err, errWant) {
		t.Fatalf("crashOnPanic must return the worker's error, got %v", err)
	}
	rep, tr := tunneltest.NewReporter(t, 0)
	var got any
	func() {
		defer func() { got = recover() }()
		_ = crashOnPanic(rep.Context(context.Background()), slog.New(slog.DiscardHandler), "worker", func() error { panic("worker boom") })()
	}()
	if got != "worker boom" {
		t.Fatalf("a background worker panic must crash the process, recovered %v", got)
	}
	if events := tr.Events(""); len(events) != 1 || events[0].Tags["where"] != "worker" || tr.Flushes() == 0 {
		t.Fatalf("the crash must be reported and flushed first, got %d events and %d flushes", len(events), tr.Flushes())
	}
}

func TestTracePredicates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		method, path string
		want         bool
	}{
		{name: "issue is traced", method: "POST", path: "/api/v1/issue", want: true},
		{name: "another method on issue is not traced", method: "GET", path: "/api/v1/issue", want: false},
		{name: "the control stream is not traced", method: "POST", path: "/api/v1/control", want: false},
		{name: "a dial-back is not traced", method: "GET", path: "/api/v1/data", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := traceIssue(httptest.NewRequest(tc.method, tc.path, nil)); got != tc.want {
				t.Fatalf("traceIssue(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
			}
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	if !traceAll(r) || traceNone(r) {
		t.Fatal("traceAll must trace and traceNone must not")
	}
}

func TestBroadcastControl_PanicMarksOnlyThatNodeFailed(t *testing.T) {
	t.Parallel()
	mc := &fakeMeshControl{applied: map[string]bool{"b:9443": true}, panics: map[string]bool{"c:9443": true}}
	nodes := map[string]router.NodeInfo{"nodeA": {Advertise: "a:9443"}, "nodeB": {Advertise: "b:9443"}, "nodeC": {Advertise: "c:9443"}}
	applied, failed := broadcastControl(context.Background(), "nodeA", nodes, mc, mesh.ControlRequest{Op: "terminate", Tunnel: "t"},
		slog.New(slog.DiscardHandler))
	if !applied || !failed["nodeC"] || failed["nodeB"] {
		t.Fatalf("applied = %v, failed = %v: a panic on one node must mark only that node failed", applied, failed)
	}
}

func TestTraceEnroll(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		method, path string
		want         bool
	}{
		{name: "enrollment is traced", method: "POST", path: "/api/v1/enroll", want: true},
		{name: "the nonce is traced", method: "GET", path: "/api/v1/enroll/nonce", want: true},
		{name: "the health check is not traced", method: "GET", path: "/api/v1/health", want: false},
		{name: "another method on enroll is not traced", method: "GET", path: "/api/v1/enroll", want: false},
		{name: "an unknown path is not traced", method: "GET", path: "/unknown", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := traceEnroll(httptest.NewRequest(tc.method, tc.path, nil)); got != tc.want {
				t.Fatalf("traceEnroll(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

func TestRemoteSlots_PanicSkipsOnlyThatNode(t *testing.T) {
	t.Parallel()
	mc := &fakeMeshControl{panics: map[string]bool{"c:9443": true}, byOp: map[string]fakeMeshResult{
		"slot-candidate@b:9443": slotOfferResult(500),
		"slot-candidate@d:9443": slotOfferResult(900),
	}}
	r := newTestRemoteSlots(fakeLiveNodes{nodes: slotTestNodes}, mc)
	offers := r.offers(context.Background(), "t")
	if len(offers) != 2 {
		t.Fatalf("offers = %+v, want the two nodes that answered", offers)
	}
}

func TestSpliceEvictor_BroadcastPanicIsContained(t *testing.T) {
	t.Parallel()
	nodes := map[string]router.NodeInfo{"nodeA": {Advertise: "a:9443"}, "nodeB": {Advertise: "b:9443"}}
	mc := &fakeMeshControl{panics: map[string]bool{"b:9443": true}}
	buf := &syncBuffer{}
	s, calls, mu := newTestEvictor(t, fakeLiveNodes{nodes: nodes}, mc, slog.New(slog.NewTextHandler(buf, nil)))
	s.PhoneConnClosed(context.Background(), "t", "conn-1", store.CloseBanEvict)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Drain(ctx)
	if ctx.Err() != nil {
		t.Fatal("the drain must not wait for a panicked broadcast")
	}
	mu.Lock()
	n := len(*calls)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("local evictions = %d, want 1", n)
	}
	out := buf.String()
	if !strings.Contains(out, `msg="recovered from a crash; only the affected work was stopped" where="mesh control broadcast"`) {
		t.Fatalf("the broadcast panic must be logged; log = %q", out)
	}
	for _, id := range []string{"tunnel=t", "conn_id=conn-1", "peer_node=nodeB"} {
		if !strings.Contains(out, id) {
			t.Fatalf("the broadcast panic must carry %s; log = %q", id, out)
		}
	}
}

func TestGuardedListener_PanicClosesOnlyThatConnection(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	g, _ := newProbedGuard(t, func(netip.Addr) bool {
		if calls.Add(1) == 1 {
			panic("ban check boom")
		}
		return false
	}, func(context.Context, netip.Addr) bool { return true }, func() bool { return true })
	first := dialGuard(t, g)
	expectClosedByPeer(t, first)
	dialGuard(t, g)
	c, err := g.Accept()
	if err != nil {
		t.Fatalf("the listener must keep accepting after a panic: %v", err)
	}
	tunneltest.CloseOrLog(t, c)
}

func TestIssueFunc_RefusesMalformedRequestsWithoutATrace(t *testing.T) {
	t.Parallel()
	rep, tr := tunneltest.NewReporter(t, 1)
	issue := issueFunc(nil)
	var got *phoneconn.IssueError
	h := rep.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, got = issue(r.Context(), "abcdef234567", "198.51.100.30", phoneconn.IssueRequest{Nonce: "not hex"})
		w.WriteHeader(http.StatusBadRequest)
	}), slog.New(slog.DiscardHandler), "control request", func(*http.Request) bool { return true })
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/issue", nil))
	rep.Flush(context.Background())
	if got == nil || got.Reason != "bad_nonce" {
		t.Fatalf("issue error = %+v, want bad_nonce", got)
	}
	if n := len(tr.Events("transaction")); n != 0 {
		t.Fatalf("a malformed issue request must not be traced, got %d transactions", n)
	}
}
