package report_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const testDSN = "https://public@example.test/1"

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newEnabled(t *testing.T, rate float64) (*report.Reporter, *tunneltest.SentryTransport) {
	t.Helper()
	rep, tr := tunneltest.NewReporter(t, rate)
	if !rep.Enabled() {
		t.Fatal("a reporter with a DSN must be enabled")
	}
	return rep, tr
}

func textLogger(buf *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func panicEvents(tr *tunneltest.SentryTransport) []*sentry.Event {
	var out []*sentry.Event
	for _, e := range tr.Events("") {
		if len(e.Exception) > 0 {
			out = append(out, e)
		}
	}
	return out
}

func TestNew_WithoutDSNSendsNothing(t *testing.T) {
	t.Parallel()
	rep, err := report.New(report.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Enabled() {
		t.Fatal("a reporter without a DSN must be disabled")
	}
	ctx := context.Background()
	if rep.Context(ctx) != ctx {
		t.Fatal("a disabled reporter must not change the context")
	}
	base := slog.New(slog.DiscardHandler)
	if rep.Logger(base) != base {
		t.Fatal("a disabled reporter must not change the logger")
	}
	if !rep.Flush(context.Background()) {
		t.Fatal("flushing a disabled reporter must succeed")
	}
}

func TestNew_RejectsBadSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  report.Config
		opts []report.Option
	}{
		{name: "negative sample rate", cfg: report.Config{DSN: testDSN, TracesSampleRate: -0.1}},
		{name: "sample rate above one", cfg: report.Config{DSN: testDSN, TracesSampleRate: 1.5}},
		{name: "sample rate not a number", cfg: report.Config{DSN: testDSN, TracesSampleRate: math.NaN()}},
		{name: "nil transport", cfg: report.Config{DSN: testDSN}, opts: []report.Option{report.WithTransport(nil)}},
		{name: "malformed DSN", cfg: report.Config{DSN: "not a dsn"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := report.New(tc.cfg, tc.opts...); err == nil {
				t.Fatal("New must fail")
			}
		})
	}
}

func TestHandler_PanicAnswers500AndReportsOnce(t *testing.T) {
	t.Parallel()
	for _, traced := range []bool{false, true} {
		t.Run(map[bool]string{false: "untraced", true: "traced"}[traced], func(t *testing.T) {
			t.Parallel()
			rep, tr := newEnabled(t, 1)
			var logs syncBuffer
			logger := rep.Logger(textLogger(&logs))
			h := rep.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
				logger, "test request", func(*http.Request) bool { return traced })
			srv := httptest.NewServer(h)
			defer srv.Close()

			resp, err := http.Get(srv.URL + "/path")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusInternalServerError || resp.Header.Get("Content-Type") != "application/json" ||
				string(body) != `{"reason":"internal_error","retryable":true}`+"\n" {
				t.Fatalf("got %d %q %q, want the retryable internal_error JSON 500", resp.StatusCode, resp.Header.Get("Content-Type"), body)
			}
			rep.Flush(context.Background())
			events := panicEvents(tr)
			if len(events) != 1 {
				t.Fatalf("want exactly one panic event, got %d (all error events: %d)", len(events), len(tr.Events("")))
			}
			if n := len(tr.Events("")); n != 1 {
				t.Fatalf("the panic log line must not raise a second issue, got %d error events", n)
			}
			ev := events[0]
			if ev.Tags["client_ip"] != "127.0.0.1" || ev.Tags["client_port"] == "" {
				t.Fatalf("event tags %v must carry the client address", ev.Tags)
			}
			if ev.Tags["node"] != "node-1" || ev.Release != "tunneld@test" || ev.Environment != "test" || ev.ServerName != "host-1" {
				t.Fatalf("event must carry the node, release, environment and host, got tags %v release %q env %q host %q",
					ev.Tags, ev.Release, ev.Environment, ev.ServerName)
			}
			if ev.Tags["where"] != "test request" || ev.Exception[0].Stacktrace == nil {
				t.Fatalf("a panic must be an exception with a stack, tagged with where it happened; tags %v", ev.Tags)
			}
			out := logs.String()
			if !strings.Contains(out, `msg="recovered from a crash; only the affected work was stopped"`) || !strings.Contains(out, "sentry_event_id="+string(ev.EventID)) ||
				!strings.Contains(out, "client_ip=127.0.0.1") {
				t.Fatalf("the panic must be logged with its event id and client address; log = %q", out)
			}
			txs := tr.Events("transaction")
			if got := len(txs) > 0; got != traced {
				t.Fatalf("transaction sent = %v, want %v", got, traced)
			}
			if traced {
				if tc := txs[0].Contexts["trace"]; tc["data"] == nil || txs[0].Transaction != "GET /path" {
					t.Fatalf("the transaction must be named after the request and carry its data, got %q %v", txs[0].Transaction, tc)
				}
				if status := fmt.Sprint(txs[0].Contexts["trace"]["status"]); status != "internal_error" {
					t.Fatalf("the transaction status = %v, want internal_error", status)
				}
			}
		})
	}
}

func TestHandler_PanicAfterWritingAbortsTheConnection(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	h := rep.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic("boom after the headers")
	}), slog.New(slog.DiscardHandler), "test request", func(*http.Request) bool { return false })
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := io.Copy(io.Discard, resp.Body)
	if cerr := resp.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if resp.StatusCode != http.StatusOK || rerr == nil {
		t.Fatalf("a panic after the headers must abort the response: status %d, read error %v", resp.StatusCode, rerr)
	}
	rep.Flush(context.Background())
	if n := len(panicEvents(tr)); n != 1 {
		t.Fatalf("want one panic event, got %d", n)
	}
}

func TestHandler_AbortHandlerIsNotReported(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	h := rep.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }),
		slog.New(slog.DiscardHandler), "test request", func(*http.Request) bool { return false })
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err == nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Fatal(cerr)
		}
		t.Fatalf("an aborted handler must not answer, got status %d", resp.StatusCode)
	}
	rep.Flush(context.Background())
	if n := len(tr.Events("")); n != 0 {
		t.Fatalf("http.ErrAbortHandler must not be reported, got %d events", n)
	}
}

func TestHandler_DisabledStillContainsPanics(t *testing.T) {
	t.Parallel()
	rep, err := report.New(report.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	h := rep.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
		textLogger(&logs), "test request", func(*http.Request) bool { return true })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, `where="test request"`) ||
		strings.Contains(out, "sentry_event_id") || !strings.Contains(out, "client_ip=192.0.2.1") {
		t.Fatalf("the panic must be logged at Error with the client address and no event id; log = %q", out)
	}
}

func TestHandler_IgnoresIncomingTraceHeaders(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 1e-9)
	h := rep.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		slog.New(slog.DiscardHandler), "test request", func(*http.Request) bool { return true })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("sentry-trace", "0123456789abcdef0123456789abcdef-0123456789abcdef-1")
	req.Header.Set("baggage", "sentry-sample_rate=1,sentry-sampled=true")
	h.ServeHTTP(httptest.NewRecorder(), req)
	rep.Flush(context.Background())
	if n := len(tr.Events("transaction")); n != 0 {
		t.Fatalf("a client's trace header must not force a trace past the sample rate, got %d transactions", n)
	}
}

func TestHandler_DoesNotTraceRefusedRequests(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		refuse  bool
		status  int
		panics  bool
		wantTxs int
	}{
		{name: "served", status: http.StatusOK, wantTxs: 1},
		{name: "refused as banned", refuse: true, status: http.StatusForbidden, wantTxs: 0},
		{name: "refused while draining", refuse: true, status: http.StatusServiceUnavailable, wantTxs: 0},
		{name: "work failed with a 503", status: http.StatusServiceUnavailable, wantTxs: 1},
		{name: "work failed with a 400", status: http.StatusBadRequest, wantTxs: 1},
		{name: "refused and then panicked", refuse: true, panics: true, wantTxs: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep, tr := newEnabled(t, 1)
			h := rep.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.refuse {
					report.Refuse(r.Context())
				}
				if tc.panics {
					panic("boom after the refusal")
				}
				w.WriteHeader(tc.status)
			}), slog.New(slog.DiscardHandler), "test request", func(*http.Request) bool { return true })
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			rep.Flush(context.Background())
			if n := len(tr.Events("transaction")); n != tc.wantTxs {
				t.Fatalf("sent %d transactions, want %d", n, tc.wantTxs)
			}
		})
	}
}

func TestHandler_LeavesTheBodyToTheHandler(t *testing.T) {
	t.Parallel()
	rep, _ := newEnabled(t, 1)
	var got string
	h := rep.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got = string(b)
	}), slog.New(slog.DiscardHandler), "test request", func(*http.Request) bool { return true })
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader("the request body")))
	if got != "the request body" {
		t.Fatalf("the handler read %q, want the whole body", got)
	}
}

func TestGetCertificate_PanicFailsTheHandshake(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	get := report.GetCertificate(rep.Context(context.Background()), slog.New(slog.DiscardHandler), "test certificate",
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { panic("certificate boom") })
	cert, err := get(&tls.ClientHelloInfo{ServerName: "enroll.example.test"})
	if cert != nil || !errors.Is(err, report.ErrPanicked) {
		t.Fatalf("GetCertificate = %v, %v; want no certificate and ErrPanicked", cert, err)
	}
	rep.Flush(context.Background())
	if events := panicEvents(tr); len(events) != 1 || events[0].Tags["sni"] != "enroll.example.test" || events[0].Tags["where"] != "test certificate" {
		t.Fatalf("want one panic event tagged with the SNI, got %d", len(events))
	}
	ok := report.GetCertificate(context.Background(), slog.New(slog.DiscardHandler), "test certificate",
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil })
	if cert, err := ok(&tls.ClientHelloInfo{}); cert == nil || err != nil {
		t.Fatalf("a working callback must pass through, got %v, %v", cert, err)
	}
}

func TestScopes_DoNotLeakBetweenConnections(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	root := rep.Context(context.Background())
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := report.WithScope(root)
			report.SetAttrs(ctx, slog.String("tunnel", fmt.Sprintf("t%02d", i)))
			report.CaptureError(ctx, errors.New("per connection"), slog.String("ca", fmt.Sprintf("ca%02d", i)))
		}()
	}
	wg.Wait()
	report.CaptureError(root, errors.New("on the root scope"))
	rep.Flush(context.Background())
	for _, e := range tr.Events("") {
		if e.Message == "" && len(e.Exception) > 0 && e.Exception[len(e.Exception)-1].Value == "on the root scope" {
			if e.Tags["tunnel"] != "" || e.Tags["ca"] != "" {
				t.Fatalf("the root scope picked up a connection's tags: %v", e.Tags)
			}
			continue
		}
		if e.Tags["tunnel"][1:] != e.Tags["ca"][2:] {
			t.Fatalf("an event mixed two connections' tags: %v", e.Tags)
		}
	}
}

func TestClose(t *testing.T) {
	t.Parallel()
	rep, _ := newEnabled(t, 0)
	if !rep.Close(context.Background(), slog.New(slog.DiscardHandler)) {
		t.Fatal("closing must flush")
	}
	disabled, err := report.New(report.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if !disabled.Close(context.Background(), slog.New(slog.DiscardHandler)) {
		t.Fatal("closing a disabled reporter must succeed")
	}
}

type stuckTransport struct {
	tunneltest.SentryTransport
	release chan struct{}
}

func (s *stuckTransport) Close() { <-s.release }

func TestClose_IsBounded(t *testing.T) {
	t.Parallel()
	tr := &stuckTransport{release: make(chan struct{})}
	defer close(tr.release)
	rep, err := report.New(report.Config{DSN: testDSN}, report.WithTransport(tr))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if rep.Close(context.Background(), slog.New(slog.DiscardHandler)) {
		t.Fatal("a close that does not finish must report it")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("close took %s, want it bounded", elapsed)
	}
}

func TestHandler_KeepsFlusherAndHijacker(t *testing.T) {
	t.Parallel()
	rep, _ := newEnabled(t, 1)
	got := make(chan error, 1)
	h := rep.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := w.(http.Flusher); !ok {
			got <- errors.New("the writer lost http.Flusher")
			return
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			got <- err
			return
		}
		got <- conn.Close()
	}), slog.New(slog.DiscardHandler), "test request", func(*http.Request) bool { return true })
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err == nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Fatal(cerr)
		}
	}
	if herr := <-got; herr != nil {
		t.Fatal(herr)
	}
}

func TestHandler_PanicAfterHijackClosesTheConnection(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	h := rep.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, _, err := http.NewResponseController(w).Hijack(); err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		panic("boom after the hijack")
	}), slog.New(slog.DiscardHandler), "test request", func(*http.Request) bool { return false })
	srv := httptest.NewServer(h)
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tunneltest.CloseOrLog(t, conn)
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, rerr := conn.Read(make([]byte, 1))
	if ne, ok := errors.AsType[net.Error](rerr); rerr == nil || ok && ne.Timeout() {
		t.Fatalf("a panic after a hijack must close the connection, read = %v", rerr)
	}
	rep.Flush(context.Background())
	if n := len(panicEvents(tr)); n != 1 {
		t.Fatalf("want one panic event, got %d", n)
	}
}

func TestGetClientCertificateAndVerifyConnection_ContainPanics(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	ctx := rep.Context(context.Background())
	logger := slog.New(slog.DiscardHandler)
	get := report.GetClientCertificate(ctx, logger, "test client certificate",
		func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { panic("client cert boom") })
	if cert, err := get(&tls.CertificateRequestInfo{}); cert != nil || !errors.Is(err, report.ErrPanicked) {
		t.Fatalf("GetClientCertificate = %v, %v; want no certificate and the panic error", cert, err)
	}
	verify := report.VerifyConnection(ctx, logger, "test verification", func(tls.ConnectionState) error { panic("verify boom") })
	if err := verify(tls.ConnectionState{}); !errors.Is(err, report.ErrPanicked) {
		t.Fatalf("VerifyConnection = %v, want the panic error", err)
	}
	rep.Flush(context.Background())
	if n := len(panicEvents(tr)); n != 2 {
		t.Fatalf("want two panic events, got %d", n)
	}
}

func TestRecover_ContainsThePanicWithTheScopeTags(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	root := rep.Context(context.Background())
	ctx := report.WithScope(root)
	report.SetAttrs(ctx, slog.String("tunnel", "abc123"), slog.String("client_ip", "198.51.100.7"))
	var logs syncBuffer
	called := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer report.Recover(ctx, textLogger(&logs), "test goroutine", func() { close(called) })
		panic("boom")
	}()
	<-done
	select {
	case <-called:
	default:
		t.Fatal("onPanic must run")
	}
	rep.Flush(context.Background())
	events := panicEvents(tr)
	if len(events) != 1 {
		t.Fatalf("want one panic event, got %d", len(events))
	}
	if tags := events[0].Tags; tags["tunnel"] != "abc123" || tags["client_ip"] != "198.51.100.7" || tags["where"] != "test goroutine" {
		t.Fatalf("event tags = %v", tags)
	}
	if out := logs.String(); !strings.Contains(out, "sentry_event_id="+string(events[0].EventID)) || !strings.Contains(out, "stack=") {
		t.Fatalf("the panic must be logged with its stack and event id; log = %q", out)
	}

	report.CaptureError(root, errors.New("on the root scope"))
	rep.Flush(context.Background())
	all := tr.Events("")
	if last := all[len(all)-1]; last.Tags["tunnel"] != "" {
		t.Fatalf("a connection's tags must not leak to the root scope, got %v", last.Tags)
	}
}

func TestRecover_NoPanicDoesNothing(t *testing.T) {
	t.Parallel()
	called := false
	func() {
		defer report.Recover(context.Background(), slog.New(slog.DiscardHandler), "test", func() { called = true })
	}()
	if called {
		t.Fatal("onPanic must not run without a panic")
	}
}

func TestCrash_ReportsFlushesAndPanicsAgain(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	ctx := rep.Context(context.Background())
	var logs syncBuffer
	var repanicked any
	func() {
		defer func() { repanicked = recover() }()
		defer report.Crash(ctx, textLogger(&logs), "test worker")
		panic("boom")
	}()
	if repanicked != "boom" {
		t.Fatalf("Crash must panic again with the same value, got %v", repanicked)
	}
	if out := logs.String(); !strings.Contains(out, `level=ERROR msg="a crash could not be contained; tunneld stops so it can be restarted" where="test worker"`) {
		t.Fatalf("Crash must log that the process stops; log = %q", out)
	}
	if tr.Flushes() == 0 {
		t.Fatal("Crash must flush before panicking again")
	}
	if events := panicEvents(tr); len(events) != 1 || events[0].Tags["where"] != "test worker" {
		t.Fatalf("want one panic event from the worker, got %d", len(events))
	}
}

func TestLogger_SendsWarningsAsLogsAndErrorsAsIssues(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	var base syncBuffer
	logger := rep.Logger(textLogger(&base)).With("version", "v-test").WithGroup("g")
	logger.Info("an info line")
	logger.Warn("a warning", "client_ip", "198.51.100.7")
	logger.Error("an error", "tunnel", "abc123", "stack", strings.Repeat("x", 300), "err", errors.New("disk full"),
		slog.Group("peer", "ip", "198.51.100.7"))
	rep.Flush(context.Background())

	out := base.String()
	for _, want := range []string{"an info line", "a warning", "an error"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the local log must keep every line; missing %q in %q", want, out)
		}
	}
	issues := tr.Events("")
	if len(issues) != 1 || issues[0].Message != "an error" {
		t.Fatalf("want one issue for the error line, got %d", len(issues))
	}
	ev := issues[0]
	if ev.Tags["g.tunnel"] != "abc123" || ev.Tags["version"] != "v-test" {
		t.Fatalf("issue tags = %v", ev.Tags)
	}
	if _, ok := ev.Tags["g.stack"]; ok {
		t.Fatal("a value longer than a tag allows must not become a tag")
	}
	fields := ev.Contexts["log"]
	if fields["g.stack"] == nil || fields["g.err"] != "disk full" || fields["g.peer.ip"] != "198.51.100.7" || fields["version"] != "v-test" {
		t.Fatalf("the event context must keep long values, error text and grouped fields, got %v", fields)
	}
	var messages []string
	for _, e := range tr.Events("log") {
		for _, l := range e.Logs {
			messages = append(messages, l.Body)
		}
	}
	got := strings.Join(messages, "|")
	if !strings.Contains(got, "a warning") || !strings.Contains(got, "an error") || strings.Contains(got, "an info line") {
		t.Fatalf("Sentry logs must hold the warning and error lines only, got %q", got)
	}
}

func TestCaptureError_WithoutAReporterDoesNothing(t *testing.T) {
	t.Parallel()
	report.CaptureError(context.Background(), errors.New("nobody listens"))
	report.SetAttrs(context.Background(), slog.String("k", "v"))
	ctx := report.WithScope(context.Background())
	report.SetAttrs(ctx, slog.String("tunnel", "abc123"), slog.String("client_ip", "198.51.100.7"))
	report.SetAttrs(ctx, slog.String("tunnel", "def456"))
	var logs syncBuffer
	func() {
		defer report.Recover(ctx, textLogger(&logs), "test", func() {})
		panic("boom")
	}()
	if out := logs.String(); !strings.Contains(out, "tunnel=def456") || !strings.Contains(out, "client_ip=198.51.100.7") ||
		strings.Contains(out, "abc123") {
		t.Fatalf("without a reporter the panic line must still carry the latest identifiers; log = %q", out)
	}
}

func TestCaptureError_SendsTheErrorWithTags(t *testing.T) {
	t.Parallel()
	rep, tr := newEnabled(t, 0)
	report.CaptureError(rep.Context(context.Background()), errors.New("order failed"), slog.String("ca", "letsencrypt"))
	rep.Flush(context.Background())
	issues := tr.Events("")
	if len(issues) != 1 || issues[0].Tags["ca"] != "letsencrypt" || len(issues[0].Exception) == 0 {
		t.Fatalf("want one exception event tagged with the CA, got %d", len(issues))
	}
}

func TestStartSpan(t *testing.T) {
	t.Parallel()
	t.Run("without a reporter", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		got, span := report.StartSpan(ctx, "op", "name")
		span.SetAttrs(slog.String("k", "v"))
		span.Finish()
		if got != ctx {
			t.Fatal("StartSpan without a reporter must not change the context")
		}
	})
	t.Run("with a reporter", func(t *testing.T) {
		t.Parallel()
		rep, tr := newEnabled(t, 1)
		_, span := report.StartSpan(rep.Context(context.Background()), "tunnel.connection", "public connection")
		span.SetAttrs(slog.String("tunnel", "abc123"), slog.Int64("bytes_in", 42), slog.String("alpn", strings.Repeat("a", 255)))
		span.Finish()
		rep.Flush(context.Background())
		txs := tr.Events("transaction")
		if len(txs) != 1 || txs[0].Transaction != "public connection" || txs[0].Tags["tunnel"] != "abc123" {
			t.Fatalf("want one tagged transaction, got %d", len(txs))
		}
		if _, ok := txs[0].Tags["alpn"]; ok {
			t.Fatal("a value longer than a tag allows must not become a tag")
		}
	})
}
