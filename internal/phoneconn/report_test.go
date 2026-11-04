package phoneconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

type panicHeaderWriter struct{ *flushRecorder }

func (panicHeaderWriter) WriteHeader(int) { panic("write header boom") }

func newClosedHookManager(t *testing.T, fr *fakeRouter, routeTTL time.Duration) (*Handler, *Manager, *recordingClosedHook) {
	t.Helper()
	hook := &recordingClosedHook{fr: fr}
	m := NewManager(Config{Router: fr, Logs: tunneltest.NewStore(), Recorder: &fakeRec{}, Closed: hook, NodeID: "nodeA",
		NodeHost: "host-a", NodeStart: "2026-08-18T00:00:00Z", RouteTTL: routeTTL})
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4})
	return h, m, hook
}

func closedReasons(hook *recordingClosedHook) []string {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	var out []string
	for _, c := range hook.calls {
		out = append(out, c.reason)
	}
	return out
}

func TestServeControl_HeartbeatPanicClosesOnlyThatPhone(t *testing.T) {
	t.Parallel()
	fr := newFakeRouter()
	fr.hbPanic = true
	h, m, hook := newClosedHookManager(t, fr, 30*time.Millisecond)
	rep, tr := tunneltest.NewReporter(t, 0)
	req := httptest.NewRequest("POST", "/api/v1/control", newBlockedReader()).WithContext(report.WithScope(rep.Context(context.Background())))
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.serveControl(newFlushRecorder(), req, phoneIdentity{name: "abcdef234567"})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the control handler must return after its heartbeat panicked")
	}
	if m.HasConn("abcdef234567") {
		t.Fatal("the phone must be unbound")
	}
	if got := closedReasons(hook); len(got) != 1 || got[0] != store.CloseError {
		t.Fatalf("close reasons = %v, want one %q", got, store.CloseError)
	}
	rep.Flush(context.Background())
	if events := tr.Events(""); len(events) != 1 || events[0].Tags["where"] != "phone control heartbeat" {
		t.Fatalf("want one panic event from the heartbeat, got %d", len(events))
	}
}

func TestServeControl_PanicBeforeTheStreamDoesNotHang(t *testing.T) {
	t.Parallel()
	h, m, hook := newClosedHookManager(t, newFakeRouter(), 30*time.Second)
	req := httptest.NewRequest("POST", "/api/v1/control", newBlockedReader())
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		h.serveControl(panicHeaderWriter{newFlushRecorder()}, req, phoneIdentity{name: "abcdef234567"})
	}()
	select {
	case v := <-done:
		if v != "write header boom" {
			t.Fatalf("the panic must reach the HTTP guard, recovered %v", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a panic between the bind and the stream must not hang the teardown")
	}
	if m.HasConn("abcdef234567") {
		t.Fatal("the phone must be unbound")
	}
	if got := closedReasons(hook); len(got) != 1 || got[0] != store.CloseError {
		t.Fatalf("close reasons = %v, want one %q", got, store.CloseError)
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("control read boom") }

func TestServeControl_ReaderPanicClosesOnlyThatPhone(t *testing.T) {
	t.Parallel()
	fr := newFakeRouter()
	hook := &recordingClosedHook{fr: fr}
	m := NewManager(Config{Router: fr, Logs: tunneltest.NewStore(), Recorder: &fakeRec{}, Closed: hook, NodeID: "nodeA",
		NodeHost: "host-a", NodeStart: "2026-08-18T00:00:00Z", RouteTTL: 30 * time.Second})
	h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4})
	rep, tr := tunneltest.NewReporter(t, 0)
	ctx := rep.Context(context.Background())
	req := httptest.NewRequest("POST", "/api/v1/control", panicReader{}).WithContext(report.WithScope(ctx))
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.serveControl(newFlushRecorder(), req, phoneIdentity{name: "abcdef234567"})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the control handler must return after its reader panicked")
	}
	if m.HasConn("abcdef234567") {
		t.Fatal("the phone must be unbound after its reader panicked")
	}
	hook.mu.Lock()
	calls := append([]closedCall(nil), hook.calls...)
	hook.mu.Unlock()
	if len(calls) != 1 || calls[0].reason != store.CloseError {
		t.Fatalf("closed calls = %+v, want one with reason %q", calls, store.CloseError)
	}
	rep.Flush(context.Background())
	events := tr.Events("")
	if len(events) != 1 || events[0].Tags["where"] != "phone control reader" || events[0].Tags["tunnel"] != "abcdef234567" ||
		events[0].Tags["conn_id"] != calls[0].connID {
		t.Fatalf("want one panic event tagged with the phone, got %d", len(events))
	}
}

type panicConnLogs struct{}

func (panicConnLogs) PutConnLog(context.Context, store.Event) error { panic("conn-log boom") }

func TestRegister_PanicUndoesTheRegistration(t *testing.T) {
	t.Parallel()
	fr := newFakeRouter()
	rec := &fakeRec{}
	m := NewManager(Config{Router: fr, Logs: panicConnLogs{}, Recorder: rec, Closed: nopClosedHook{}, NodeID: "nodeA",
		NodeHost: "host-a", NodeStart: "2026-08-18T00:00:00Z", RouteTTL: 30 * time.Second})
	c := newConn("abcdef234567")
	func() {
		defer func() {
			if recover() == nil {
				t.Error("register must let the panic reach the handler's guard")
			}
		}()
		if _, err := m.register(context.Background(), c); err != nil {
			t.Errorf("register = %v", err)
		}
	}()
	if m.HasConn(c.name) || m.LiveConns() != 0 {
		t.Fatal("a registration that panicked must not leave the phone connection behind")
	}
	if !fr.wasUnbound(c.name) || c.closeReason() != store.CloseError {
		t.Fatalf("unbound = %v, close reason = %q: want the route unbound and the connection closed as %q",
			fr.wasUnbound(c.name), c.closeReason(), store.CloseError)
	}
	if rec.opens.Load() != rec.closes.Load() {
		t.Fatalf("phone connection gauge opens = %d, closes = %d: want them balanced", rec.opens.Load(), rec.closes.Load())
	}
}

func TestServeHTTP_PanicCarriesTheConnectionIdentifiers(t *testing.T) {
	t.Parallel()
	meta := ConnMeta{SNI: "control.example.test", ALPN: "h2", TLSVersion: "1.3", JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1"}
	dialBack := func(t *testing.T) *http.Request {
		req := httptest.NewRequest(http.MethodGet, wire.DialBackPath, nil)
		req.Header.Set(wire.DialBackHeader, "TOKEN")
		req.Header.Set("Upgrade", wire.DialUpgrade)
		req.RemoteAddr = "198.51.100.50:40000"
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{selfSignedCert(t, "abcdef234567", false)}}
		return req
	}
	tests := []struct {
		name string
		req  func(*testing.T) *http.Request
	}{
		{name: "issue", req: func(t *testing.T) *http.Request { return issuePost(t, "{}") }},
		{name: "dial-back", req: dialBack},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, _, _, _ := newMgr(t)
			h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
				DialBackMTLS: true, BanTunnel: func(string) bool { panic("ban check boom") }})
			rep, tr := tunneltest.NewReporter(t, 0)
			req := tc.req(t)
			req = req.WithContext(context.WithValue(req.Context(), connMetaKey{}, meta))
			rec := httptest.NewRecorder()
			rep.Handler(h, slog.New(slog.DiscardHandler), "control request", func(*http.Request) bool { return false }).ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
			rep.Flush(context.Background())
			events := tr.Events("")
			if len(events) != 1 {
				t.Fatalf("want one panic event, got %d", len(events))
			}
			want := map[string]string{"tunnel": "abcdef234567", "client_ip": "198.51.100.50", "client_port": "40000",
				"sni": meta.SNI, "alpn": meta.ALPN, "tls_version": meta.TLSVersion, "ja4": meta.JA4}
			for k, v := range want {
				if got := events[0].Tags[k]; got != v {
					t.Errorf("tag %s = %q, want %q", k, got, v)
				}
			}
		})
	}
}

func TestServeIssue_TracesOnlyRequestsThatWereNotRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     func(*testing.T) *http.Request
		wantTxs int
	}{
		{name: "no identity", req: func(*testing.T) *http.Request {
			return httptest.NewRequest(http.MethodPost, "/api/v1/issue", strings.NewReader("{}"))
		}, wantTxs: 0},
		{name: "malformed body", req: func(t *testing.T) *http.Request { return issuePost(t, "{") }, wantTxs: 0},
		{name: "the issuance failed", req: func(t *testing.T) *http.Request { return issuePost(t, "{}") }, wantTxs: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, _, _, _ := newMgr(t)
			h := NewHandler(HandlerConfig{DialBacks: NewDialBacks(tunneltest.Logger()), Manager: m, PingInterval: time.Hour, StreamPending: 4,
				OnIssue: func(context.Context, string, string, IssueRequest) (IssueResponse, *IssueError) {
					return IssueResponse{}, &IssueError{Reason: "acme_failed"}
				}})
			rep, tr := tunneltest.NewReporter(t, 1)
			rep.Handler(h, slog.New(slog.DiscardHandler), "control request", func(*http.Request) bool { return true }).
				ServeHTTP(httptest.NewRecorder(), tc.req(t))
			rep.Flush(context.Background())
			if n := len(tr.Events("transaction")); n != tc.wantTxs {
				t.Fatalf("sent %d transactions, want %d", n, tc.wantTxs)
			}
		})
	}
}
