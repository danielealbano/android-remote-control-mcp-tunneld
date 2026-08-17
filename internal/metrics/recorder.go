package metrics

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/admin"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/caplog"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
)

// flushShutdownTimeout bounds the final counter flush on shutdown so it cannot block the drain.
const flushShutdownTimeout = 5 * time.Second

// PromRecorder implements observ.Recorder by combining the metric registry, the cap-hit deduping
// logger, and the async per-tunnel counter flusher. It is the single object injected into the ingress,
// enroll, and WS handlers (docs/ARCHITECTURE.md §7).
type PromRecorder struct {
	m      *Metrics
	caplog *caplog.Logger
	admin  *admin.Store
	log    *slog.Logger

	mu  sync.Mutex
	agg map[string]*aggEntry
}

type aggEntry struct {
	requests int64
	bytesIn  int64
	bytesOut int64
}

var _ observ.Recorder = (*PromRecorder)(nil)

// NewPromRecorder builds the recorder.
func NewPromRecorder(m *Metrics, cl *caplog.Logger, store *admin.Store, log *slog.Logger) *PromRecorder {
	return &PromRecorder{m: m, caplog: cl, admin: store, log: log, agg: map[string]*aggEntry{}}
}

// Reject bumps the reason counter AND emits a deduped cap-hit log.
func (p *PromRecorder) Reject(reason, tunnelName, clientIP string) {
	p.m.rejections.WithLabelValues(reason).Inc()
	p.caplog.Hit(tunnelName, reason, clientIP)
}

// Request bumps the request counter + duration histogram and accumulates the per-tunnel requests
// counter in-process (flushed async — never a synchronous Redis write on the data plane).
func (p *PromRecorder) Request(tunnelName, class string, code int, dur time.Duration) {
	p.m.httpRequests.WithLabelValues(class, strconv.Itoa(code)).Inc()
	p.m.httpDuration.Observe(dur.Seconds())
	p.accum(tunnelName, func(e *aggEntry) { e.requests++ })
}

// Bytes bumps the direction counter and accumulates the per-tunnel byte counters.
func (p *PromRecorder) Bytes(tunnelName, direction string, n int64) {
	p.m.bytesTotal.WithLabelValues(direction).Add(float64(n))
	p.accum(tunnelName, func(e *aggEntry) {
		if direction == "in" {
			e.bytesIn += n
		} else {
			e.bytesOut += n
		}
	})
}

func (p *PromRecorder) WSConnect() {
	p.m.wsConnects.Inc()
	p.m.tunnelsConnected.Inc()
}

func (p *PromRecorder) WSDisconnect(reason string) {
	p.m.wsDisconnects.WithLabelValues(reason).Inc()
	p.m.tunnelsConnected.Dec()
}

func (p *PromRecorder) Enrollment()           { p.m.enrollments.Inc() }
func (p *PromRecorder) InflightAdd(delta int) { p.m.httpInflight.Add(float64(delta)) }
func (p *PromRecorder) Timeout()              { p.m.requestTimeouts.Inc() }
func (p *PromRecorder) PublishError()         { p.m.pubsubPublishErrors.Inc() }

// --- Plan 3 (E2E) event set: stub bodies here; the real family/counter updates land in US10 when the
// registry gains the E2E families. Declared now so the extended observ.Recorder assertion and the
// server.Run wiring compile at every story boundary (additive-until-teardown). ---

func (p *PromRecorder) PublicConnOpen()                          {}
func (p *PromRecorder) PublicConnClose(reason string)            {}
func (p *PromRecorder) PhoneConnOpen()                           {}
func (p *PromRecorder) PhoneConnClose(reason string)             {}
func (p *PromRecorder) StreamOpen()                              {}
func (p *PromRecorder) StreamClose()                             {}
func (p *PromRecorder) EnrollmentResult(result string)           {}
func (p *PromRecorder) AttestVerify(result string)               {}
func (p *PromRecorder) ACMEIssue(ca, result string)              {}
func (p *PromRecorder) ACMERenew(ca, result string)              {}
func (p *PromRecorder) QuotaExhausted(tunnelName, window string) {}
func (p *PromRecorder) ACMECooldown(ca string)                   {}
func (p *PromRecorder) MeshPool(peer string, size int)           {}

func (p *PromRecorder) accum(name string, f func(*aggEntry)) {
	if name == "" {
		return
	}
	p.mu.Lock()
	e := p.agg[name]
	if e == nil {
		e = &aggEntry{}
		p.agg[name] = e
	}
	f(e)
	p.mu.Unlock()
}

// RunFlusher periodically drains the accumulated deltas into the admin.Store (a real async write
// path). A final flush runs on ctx cancel.
func (p *PromRecorder) RunFlusher(ctx context.Context, every time.Duration) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), flushShutdownTimeout)
			p.flush(fctx)
			cancel()
			return ctx.Err()
		case <-ticker.C:
			p.flush(ctx)
		}
	}
}

// flush swaps in a fresh empty map (so flushed names are dropped) and applies the deltas.
func (p *PromRecorder) flush(ctx context.Context) {
	p.mu.Lock()
	drained := p.agg
	p.agg = map[string]*aggEntry{}
	p.mu.Unlock()

	for name, e := range drained {
		if e.requests != 0 {
			if err := p.admin.Incr(ctx, name, "requests", e.requests); err != nil {
				p.log.Warn("admin counter flush failed", "tunnel", name, "field", "requests", "err", err)
			}
		}
		if e.bytesIn != 0 {
			if err := p.admin.Incr(ctx, name, "bytes_in", e.bytesIn); err != nil {
				p.log.Warn("admin counter flush failed", "tunnel", name, "field", "bytes_in", "err", err)
			}
		}
		if e.bytesOut != 0 {
			if err := p.admin.Incr(ctx, name, "bytes_out", e.bytesOut); err != nil {
				p.log.Warn("admin counter flush failed", "tunnel", name, "field", "bytes_out", "err", err)
			}
		}
	}
}
