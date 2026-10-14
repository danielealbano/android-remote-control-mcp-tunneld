package metrics

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/admin"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/caplog"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/redis/go-redis/v9"
)

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// fakeNodeSrc is a NodeSource test double for the /api/v1/admin/nodes handler.
type fakeNodeSrc struct {
	nodes map[string]router.NodeInfo
	err   error
}

func (f *fakeNodeSrc) Nodes(context.Context) (map[string]router.NodeInfo, error) {
	return f.nodes, f.err
}

// fakeTunnelSrc is a TunnelSource test double for the /api/v1/admin/tunnels/list + /stats handlers.
type fakeTunnelSrc struct {
	names             []string
	next              uint64
	stats             map[string]admin.TunnelStats
	listErr, statsErr error
}

func (f *fakeTunnelSrc) List(context.Context, uint64, int64) ([]string, uint64, error) {
	return f.names, f.next, f.listErr
}

func (f *fakeTunnelSrc) Stats(context.Context, []string) (map[string]admin.TunnelStats, error) {
	return f.stats, f.statsErr
}

// fakeSink is a TrafficSink test double recording per-tunnel byte deltas (the recorder writes here instead
// of router.AddTraffic in unit tests). Setting err makes AddTraffic fail (for the re-queue test).
type fakeSink struct {
	mu      sync.Mutex
	in, out map[string]int64
	err     error
}

func newFakeSink() *fakeSink { return &fakeSink{in: map[string]int64{}, out: map[string]int64{}} }

func (f *fakeSink) AddTraffic(_ context.Context, name string, bytesIn, bytesOut int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.in[name] += bytesIn
	f.out[name] += bytesOut
	return nil
}

func (f *fakeSink) got(name string) (int64, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in[name], f.out[name]
}

func (f *fakeSink) empty() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.in) == 0 && len(f.out) == 0
}

func (f *fakeSink) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// setup builds the recorder over a fakeSink (its traffic sink); the returned *fakeTunnelSrc backs the
// admin.Handler's tunnels endpoints. Access the sink for flush assertions via rec.traffic.(*fakeSink).
func setup(t *testing.T) (*Metrics, *PromRecorder, *fakeTunnelSrc, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	m := NewMetrics()
	rec := NewPromRecorder(m, caplog.New(testLog()), newFakeSink(), testLog())
	return m, rec, &fakeTunnelSrc{}, mr, rdb
}

func TestAdminTunnelsHandler(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	store.names = []string{"t1", "t2"}
	store.next = 7
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/admin/tunnels/list?cursor=0&count=100", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "t1") || !strings.Contains(rr.Body.String(), `"cursor":"7"`) {
		t.Errorf("/api/v1/admin/tunnels/list = %d body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want json", ct)
	}

	store.listErr = errors.New("valkey down") // List now errors → 500
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest("GET", "/api/v1/admin/tunnels/list", nil))
	if rr2.Code != http.StatusInternalServerError {
		t.Errorf("/api/v1/admin/tunnels/list with a list error = %d, want 500", rr2.Code)
	}
}

func TestAdminTunnelsStatsHandler(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	store.stats = map[string]admin.TunnelStats{"t1": {Node: "n1", BytesIn: 100, Conc: 2, BwIn: 10}}
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())

	// POST {names} → merged stats.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/admin/tunnels/stats", strings.NewReader(`{"names":["t1"]}`)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "n1") {
		t.Errorf("/stats POST = %d body=%q", rr.Code, rr.Body.String())
	}
	// A non-POST is rejected.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest("GET", "/api/v1/admin/tunnels/stats", nil))
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /stats = %d, want 405", rr2.Code)
	}
	// A malformed body is a 400.
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, httptest.NewRequest("POST", "/api/v1/admin/tunnels/stats", strings.NewReader(`not json`)))
	if rr3.Code != http.StatusBadRequest {
		t.Errorf("bad-body /stats = %d, want 400", rr3.Code)
	}
	// An oversized body (past the MaxBytesReader cap) is a 413.
	big := `{"names":["` + strings.Repeat("a", 70*1024) + `"]}`
	rr4 := httptest.NewRecorder()
	h.ServeHTTP(rr4, httptest.NewRequest("POST", "/api/v1/admin/tunnels/stats", strings.NewReader(big)))
	if rr4.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized /stats = %d, want 413", rr4.Code)
	}
}

func TestRunFlusherCadenceAndFinalFlush(t *testing.T) {
	_, rec, _, _, _ := setup(t)
	sink := rec.traffic.(*fakeSink)
	rec.Bytes("t1", "in", 500)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := rec.RunFlusher(ctx, 20*time.Millisecond); err != nil && ctx.Err() == nil {
			testLog().Warn("flusher failed", "err", err)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if in, _ := sink.got("t1"); in == 500 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the flusher did not drain the accumulator to the traffic sink")
}

func TestHealthz200WhenRedisUp(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", rr.Code)
	}
}

func TestHealthz503WhenRedisDown(t *testing.T) {
	m, _, store, mr, rdb := setup(t)
	mr.Close()
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("healthz (redis down) = %d, want 503", rr.Code)
	}
	if body := rr.Body.String(); !strings.HasPrefix(body, "redis unavailable: ") || len(strings.TrimSpace(body)) <= len("redis unavailable:") {
		t.Errorf("healthz (redis down) body must carry the Valkey error, got %q", body)
	}
}

func TestMetricsEndpointExposesFamilies(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	// Exercise each family so CounterVecs emit at least one series (Prometheus omits empty families).
	rec.Reject("ban", "t", "1.1.1.1")
	rec.Bytes("t", "in", 10)
	rec.AttestVerify("ok")
	rec.QuotaExhausted("t", "day")
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	for _, name := range []string{
		"tunneld_rejections_total", "tunneld_bytes_total",
		"tunneld_attest_verify_total", "tunneld_quota_exhausted_total",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics missing %s", name)
		}
	}
}

func TestNoPerTunnelMetricLabels(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	rec.Bytes("secret-tunnel-name", "in", 100)
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if strings.Contains(body, `tunnel="`) || strings.Contains(body, `name="`) {
		t.Error("metrics MUST NOT carry per-tunnel labels (cardinality guard)")
	}
	if strings.Contains(body, "secret-tunnel-name") {
		t.Error("tunnel name leaked into metrics")
	}
}

func TestGoroutineAndMemGaugesPresent(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	rec.MeshPool("10.0.0.2:9443", 4) // populate the mesh-pool gauge
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "go_goroutines") {
		t.Error("/metrics must export go_goroutines")
	}
	// The per-conn memory estimate gauge is exported with a non-zero static estimate.
	if !strings.Contains(body, "tunneld_per_conn_mem_bytes 32768") {
		t.Errorf("/metrics must export the per-conn memory estimate (2*ChunkSize):\n%s", body)
	}
	// The mesh pool size is exported per peer once reported.
	if !strings.Contains(body, `tunneld_mesh_pool_size{peer="10.0.0.2:9443"} 4`) {
		t.Errorf("/metrics must export mesh pool size:\n%s", body)
	}
}

func TestProcessMetricsPresent(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	for _, name := range []string{"process_open_fds ", "process_max_fds ", "process_resident_memory_bytes ", "process_cpu_seconds_total "} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics must export %s", strings.TrimSpace(name))
		}
	}
}

func TestRejectionIncrementsReasonCounter(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	rec.Reject("stream-cap", "t", "1.1.1.1")
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rr.Body.String(), `tunneld_rejections_total{reason="stream-cap"} 1`) {
		t.Errorf("rejection counter not incremented:\n%s", rr.Body.String())
	}
}

func TestRejectionIncrementsACMEHTTPMiss(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	var buf bytes.Buffer
	rec := NewPromRecorder(m, caplog.New(testLog()), newFakeSink(), slog.New(slog.NewTextHandler(&buf, nil)))
	rec.Reject("acme-http-miss", "", "192.0.2.1")
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rr.Body.String(), `tunneld_rejections_total{reason="acme-http-miss"} 1`) {
		t.Errorf("acme-http-miss counter not incremented:\n%s", rr.Body.String())
	}
	if strings.Contains(buf.String(), "unregistered rejection reason") {
		t.Errorf("acme-http-miss must be a registered reason; log = %q", buf.String())
	}
}

func TestRejectRefusesUnregisteredReason(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	rec.Reject("made-up-reason", "t", "1.1.1.1")
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(rr.Body.String(), "made-up-reason") {
		t.Error("an unregistered rejection reason must be refused, not exported")
	}
}

func TestEnrollmentResultLabelled(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	rec.EnrollmentResult("ok")
	rec.EnrollmentResult("unauthorized")
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `tunneld_enrollments_total{result="ok"} 1`) ||
		!strings.Contains(body, `tunneld_enrollments_total{result="unauthorized"} 1`) {
		t.Errorf("enrollments must be labelled by result:\n%s", body)
	}
}

func TestPromRecorder_FlushCallsAddTraffic(t *testing.T) {
	_, rec, _, _, _ := setup(t)
	sink := rec.traffic.(*fakeSink)
	rec.Bytes("tunA", "in", 100)
	rec.Bytes("tunA", "out", 50)
	rec.flush(context.Background()) // the real async write path, driven synchronously in the test
	if in, out := sink.got("tunA"); in != 100 || out != 50 {
		t.Errorf("flush wrote (in=%d, out=%d) via AddTraffic, want (100, 50)", in, out)
	}
}

// TestPromRecorder_NilSinkFlushNoPanic verifies flush/FinalFlush do not panic when the traffic sink is
// nil (metrics-only test wiring): the recorder treats a nil sink as a no-op.
func TestPromRecorder_NilSinkFlushNoPanic(t *testing.T) {
	m := NewMetrics()
	rec := NewPromRecorder(m, nil, nil, nil) // nil traffic sink
	rec.Bytes("tunA", "in", 100)             // accumulate a delta so flush has work
	rec.flush(context.Background())          // must not panic
	rec.FinalFlush()                         // must not panic
}

// TestQuotaExhaustedDedupedViaCaplog: the exhaustion LOG is caplog-deduped — the first hit per
// (tunnel, window) logs immediately, an immediate repeat does not.
func TestQuotaExhaustedDedupedViaCaplog(t *testing.T) {
	m := NewMetrics()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	rec := NewPromRecorder(m, caplog.New(logger), nil, logger)

	rec.QuotaExhausted("tunA", "day")
	first := strings.Count(buf.String(), "quota-day")
	rec.QuotaExhausted("tunA", "day")
	second := strings.Count(buf.String(), "quota-day")
	if first != 1 {
		t.Fatalf("first exhaustion must log immediately, got %d lines", first)
	}
	if second != first {
		t.Fatalf("an immediate repeat must be deduped (no new log), got %d lines", second)
	}
}

// TestPromRecorder_Reject_NoRouteDebugOnly: a no-route rejection increments the metric and logs a
// Debug line only — it must NEVER key the attacker-controlled tunnel value into the caplog dedup map
// (which would emit a WARN), while every other reason still routes through caplog.
func TestPromRecorder_Reject_NoRouteDebugOnly(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rec := NewPromRecorder(m, caplog.New(logger), newFakeSink(), logger)

	rec.Reject("no-route", "ATTACKER-CONTROLLED-sni", "203.0.113.7")

	// The reason counter is still incremented (observed via the /metrics endpoint).
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rr.Body.String(), `tunneld_rejections_total{reason="no-route"} 1`) {
		t.Fatalf("no-route rejection metric not incremented:\n%s", rr.Body.String())
	}

	out := buf.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "no-route rejection") {
		t.Fatalf("no-route must log a Debug line, got %q", out)
	}
	if strings.Contains(out, "level=WARN") || strings.Contains(out, "cap hit") {
		t.Fatalf("no-route must NOT hit caplog (no WARN cap-hit line), got %q", out)
	}

	// A different reason DOES go through caplog (control): it emits the WARN cap-hit line.
	rec.Reject("stream-cap", "tunA", "203.0.113.8")
	if !strings.Contains(buf.String(), "cap hit") {
		t.Fatal("a non-no-route reason must still be logged via caplog")
	}
}

// TestPromRecorder_FlushErrorRequeuesDelta: a failed AddTraffic must re-accumulate the delta so the next
// flush retries it — a counter write is never dropped on a transient sink error.
func TestPromRecorder_FlushErrorRequeuesDelta(t *testing.T) {
	_, rec, _, _, _ := setup(t)
	sink := rec.traffic.(*fakeSink)
	rec.Bytes("tunA", "in", 100)
	rec.Bytes("tunA", "out", 50)
	sink.setErr(errors.New("sink down")) // AddTraffic now errors

	rec.flush(context.Background())

	rec.mu.Lock()
	e := rec.agg["tunA"]
	rec.mu.Unlock()
	if e == nil || e.bytesIn != 100 || e.bytesOut != 50 {
		t.Fatalf("a failed flush must re-queue the delta for the next flush, got %+v", e)
	}
}

// TestRunFlusher_NoFlushOnCancel: RunFlusher must return on ctx cancel WITHOUT flushing — the ordered
// server drain owns the final flush (FinalFlush), so a cancel-time flush that races live producers is gone.
func TestRunFlusher_NoFlushOnCancel(t *testing.T) {
	_, rec, _, _, _ := setup(t)
	rec.Bytes("tunA", "in", 100)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rec.RunFlusher(ctx, time.Hour); err == nil {
		t.Fatal("RunFlusher must return ctx.Err() on cancel")
	}
	if !rec.traffic.(*fakeSink).empty() {
		t.Fatal("RunFlusher must NOT flush on cancel")
	}
	rec.mu.Lock()
	e := rec.agg["tunA"]
	rec.mu.Unlock()
	if e == nil || e.bytesIn != 100 {
		t.Fatalf("the delta must remain accumulated (FinalFlush will drain it), got %+v", e)
	}
}

// TestPromRecorder_FlushCapLogEmitsPending: a pending multi-hit cap summary is emitted by FlushCapLog at
// shutdown (the first hit logs immediately; the second accrues a summary that only a flush emits).
func TestPromRecorder_FlushCapLogEmitsPending(t *testing.T) {
	m := NewMetrics()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	rec := NewPromRecorder(m, caplog.New(logger), nil, logger)

	rec.Reject("stream-cap", "tunA", "1.1.1.1")
	rec.Reject("stream-cap", "tunA", "1.1.1.2")
	if strings.Contains(buf.String(), "cap hit summary") {
		t.Fatal("the pending summary must NOT be emitted before FlushCapLog")
	}

	rec.FlushCapLog()

	if !strings.Contains(buf.String(), "cap hit summary") {
		t.Fatalf("FlushCapLog must emit the pending cap-hit summary, got %q", buf.String())
	}
}

// TestHandler_AdminNodes: the endpoint returns the node registry JSON; a source error → 500.
func TestHandler_AdminNodes(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	nodes := &fakeNodeSrc{nodes: map[string]router.NodeInfo{
		"n1": {Advertise: "10.0.0.1:9443", Hostname: "host-1", Version: "v1"},
	}}
	h := Handler(m.Registry(), rdb, store, nodes, testLog())

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/admin/nodes", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "10.0.0.1:9443") || !strings.Contains(rr.Body.String(), "host-1") {
		t.Errorf("/api/v1/admin/nodes = %d body=%q", rr.Code, rr.Body.String())
	}

	nodes.err = errors.New("valkey down")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest("GET", "/api/v1/admin/nodes", nil))
	if rr2.Code != http.StatusInternalServerError {
		t.Errorf("/api/v1/admin/nodes with source error = %d, want 500", rr2.Code)
	}
}

func TestAdminTunnelsList_RejectsMalformedParams(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	h := Handler(m.Registry(), rdb, store, &fakeNodeSrc{}, testLog())
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{name: "defaults", query: "", want: http.StatusOK},
		{name: "malformed cursor", query: "?cursor=abc", want: http.StatusBadRequest},
		{name: "malformed count", query: "?count=x", want: http.StatusBadRequest},
		{name: "zero count", query: "?count=0", want: http.StatusBadRequest},
		{name: "negative count", query: "?count=-3", want: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/admin/tunnels/list"+tc.query, nil))
			if rr.Code != tc.want {
				t.Fatalf("list%s = %d, want %d (body %q)", tc.query, rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestRegisterLogSinkErrors(t *testing.T) {
	m := NewMetrics()
	if err := m.RegisterLogSinkErrors(func() float64 { return 5 }); err != nil {
		t.Fatal(err)
	}
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var got float64 = -1
	for _, mf := range mfs {
		if mf.GetName() == "tunneld_log_sink_errors_total" {
			got = mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	if got != 5 {
		t.Fatalf("tunneld_log_sink_errors_total = %v, want 5", got)
	}
	if err := m.RegisterLogSinkErrors(func() float64 { return 0 }); err == nil {
		t.Fatal("a second registration must be refused")
	}
	if err := NewMetrics().RegisterLogSinkErrors(nil); err == nil {
		t.Fatal("a nil counter must be refused")
	}
}
