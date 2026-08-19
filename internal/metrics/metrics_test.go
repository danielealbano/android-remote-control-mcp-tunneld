package metrics

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/admin"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/caplog"
	"github.com/redis/go-redis/v9"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func setup(t *testing.T) (*Metrics, *PromRecorder, *admin.Store, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	m := NewMetrics()
	store := admin.NewStore(rdb, time.Hour)
	rec := NewPromRecorder(m, caplog.New(discardLog()), store, discardLog())
	return m, rec, store, mr, rdb
}

func TestAdminTunnelsHandler(t *testing.T) {
	m, _, store, mr, rdb := setup(t)
	_ = store.Incr(context.Background(), "t1", "bytes_in", 100)
	h := Handler(m.Registry(), rdb, store, discardLog())

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/admin/tunnels", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "t1") {
		t.Errorf("admin/tunnels = %d body=%q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want json", ct)
	}

	mr.Close() // TopN now errors → 500
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, httptest.NewRequest("GET", "/admin/tunnels", nil))
	if rr2.Code != http.StatusInternalServerError {
		t.Errorf("admin/tunnels with Redis down = %d, want 500", rr2.Code)
	}
}

func TestRunFlusherCadenceAndFinalFlush(t *testing.T) {
	_, rec, store, _, _ := setup(t)
	rec.Bytes("t1", "in", 500)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = rec.RunFlusher(ctx, 20*time.Millisecond) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if stats, _ := store.TopN(context.Background(), 10); len(stats) == 1 && stats[0].BytesIn == 500 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the flusher did not drain the accumulator to the store")
}

func TestHealthz200WhenRedisUp(t *testing.T) {
	m, _, store, _, rdb := setup(t)
	h := Handler(m.Registry(), rdb, store, discardLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", rr.Code)
	}
}

func TestHealthz503WhenRedisDown(t *testing.T) {
	m, _, store, mr, rdb := setup(t)
	mr.Close()
	h := Handler(m.Registry(), rdb, store, discardLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("healthz (redis down) = %d, want 503", rr.Code)
	}
}

func TestMetricsEndpointExposesFamilies(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	// Exercise each family so CounterVecs emit at least one series (Prometheus omits empty families).
	rec.Reject("ban", "t", "1.1.1.1")
	rec.Bytes("t", "in", 10)
	rec.AttestVerify("ok")
	rec.QuotaExhausted("t", "day")
	h := Handler(m.Registry(), rdb, store, discardLog())
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
	h := Handler(m.Registry(), rdb, store, discardLog())
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
	h := Handler(m.Registry(), rdb, store, discardLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "go_goroutines") {
		t.Error("/metrics must export go_goroutines")
	}
	// The per-conn memory estimate gauge is exported with a non-zero static estimate.
	if !strings.Contains(body, "tunneld_per_conn_mem_bytes 65536") {
		t.Errorf("/metrics must export the per-conn memory estimate (2*ChunkSize):\n%s", body)
	}
	// The mesh pool size is exported per peer once reported.
	if !strings.Contains(body, `tunneld_mesh_pool_size{peer="10.0.0.2:9443"} 4`) {
		t.Errorf("/metrics must export mesh pool size:\n%s", body)
	}
}

func TestRejectionIncrementsReasonCounter(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	rec.Reject("stream-cap", "t", "1.1.1.1")
	h := Handler(m.Registry(), rdb, store, discardLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rr.Body.String(), `tunneld_rejections_total{reason="stream-cap"} 1`) {
		t.Errorf("rejection counter not incremented:\n%s", rr.Body.String())
	}
}

func TestRejectRefusesUnregisteredReason(t *testing.T) {
	m, rec, store, _, rdb := setup(t)
	rec.Reject("made-up-reason", "t", "1.1.1.1")
	h := Handler(m.Registry(), rdb, store, discardLog())
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
	h := Handler(m.Registry(), rdb, store, discardLog())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `tunneld_enrollments_total{result="ok"} 1`) ||
		!strings.Contains(body, `tunneld_enrollments_total{result="unauthorized"} 1`) {
		t.Errorf("enrollments must be labelled by result:\n%s", body)
	}
}

func TestPromRecorderFlushesTcnt(t *testing.T) {
	_, rec, store, _, _ := setup(t)
	rec.Bytes("tunA", "in", 100)
	rec.Bytes("tunA", "out", 50)
	rec.flush(context.Background()) // the real async write path, driven synchronously in the test
	stats, err := store.TopN(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Name != "tunA" {
		t.Fatalf("expected tunA stats, got %+v", stats)
	}
	if stats[0].BytesIn != 100 || stats[0].BytesOut != 50 {
		t.Errorf("flushed counters wrong: %+v", stats[0])
	}
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
	rec := NewPromRecorder(m, caplog.New(logger), store, logger)

	rec.Reject("no-route", "ATTACKER-CONTROLLED-sni", "203.0.113.7")

	// The reason counter is still incremented (observed via the /metrics endpoint).
	h := Handler(m.Registry(), rdb, store, discardLog())
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

// TestPromRecorder_FlushErrorRequeuesDelta: a failed admin.Incr must re-accumulate the delta so the next
// flush retries it — a counter write is never dropped on a transient store error.
func TestPromRecorder_FlushErrorRequeuesDelta(t *testing.T) {
	_, rec, _, mr, _ := setup(t)
	rec.Bytes("tunA", "in", 100)
	rec.Bytes("tunA", "out", 50)
	mr.Close() // admin.Incr now errors (Redis down)

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
	_, rec, store, _, _ := setup(t)
	rec.Bytes("tunA", "in", 100)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rec.RunFlusher(ctx, time.Hour); err == nil {
		t.Fatal("RunFlusher must return ctx.Err() on cancel")
	}
	stats, _ := store.TopN(context.Background(), 10)
	if len(stats) != 0 {
		t.Fatalf("RunFlusher must NOT flush on cancel, got %+v", stats)
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
