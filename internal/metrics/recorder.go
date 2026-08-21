package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/caplog"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
)

// TrafficSink is the existence-guarded per-tunnel byte counter (router.Registry.AddTraffic). Defined at the
// consumer site; a nil sink is a no-op (metrics-only test wiring).
type TrafficSink interface {
	AddTraffic(ctx context.Context, name string, bytesIn, bytesOut int64) error
}

// flushShutdownTimeout bounds the final counter flush on shutdown so it cannot block the drain.
const flushShutdownTimeout = 5 * time.Second

// PromRecorder implements observ.Recorder by combining the metric registry, the cap-hit deduping
// logger, and the async per-tunnel counter flusher. It is the single recorder injected into the
// enroll, edge, and phone-control handlers (docs/ARCHITECTURE.md §8).
type PromRecorder struct {
	m       *Metrics
	caplog  *caplog.Logger
	traffic TrafficSink
	log     *slog.Logger

	mu  sync.Mutex
	agg map[string]*aggEntry
}

type aggEntry struct {
	bytesIn  int64
	bytesOut int64
}

var _ observ.Recorder = (*PromRecorder)(nil)

// knownRejectReasons is the observ.RejectReasons set as a lookup (Reject refuses anything else, so an
// unregistered reason string can never be invented at a call site).
var knownRejectReasons = func() map[string]struct{} {
	set := make(map[string]struct{}, len(observ.RejectReasons))
	for _, r := range observ.RejectReasons {
		set[r] = struct{}{}
	}
	return set
}()

// NewPromRecorder builds the recorder. A nil caplog/log defaults to a discarding sink; a nil traffic
// sink is accepted and treated as a no-op (flush becomes a no-op) — used by metrics-only test wiring
// that never records per-tunnel counters.
func NewPromRecorder(m *Metrics, cl *caplog.Logger, sink TrafficSink, log *slog.Logger) *PromRecorder {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cl == nil {
		cl = caplog.New(log)
	}
	return &PromRecorder{m: m, caplog: cl, traffic: sink, log: log, agg: map[string]*aggEntry{}}
}

// Reject bumps the reason counter and emits a deduped cap-hit log — except "no-route", whose tunnel
// value is attacker-controlled and so gets a metric + Debug-only line (never the dedup map). A reason
// outside observ.RejectReasons is refused (logged as an error) so call sites cannot invent labels.
func (p *PromRecorder) Reject(reason, tunnelName, clientIP string) {
	if _, ok := knownRejectReasons[reason]; !ok {
		p.log.Error("unregistered rejection reason refused", "reason", reason, "tunnel", tunnelName)
		return
	}
	p.m.rejections.WithLabelValues(reason).Inc()
	if reason == "no-route" {
		// The tunnel value on this path is attacker-controlled (raw SNI / unrouted name): it must
		// never key the dedup map or emit per-hit WARNs. Metric + debug-only line.
		p.log.Debug("no-route rejection", "sni", tunnelName, "client_ip", clientIP)
		return
	}
	p.caplog.Hit(tunnelName, reason, clientIP)
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

// --- E2E event set (real implementations). ---

func (p *PromRecorder) PublicConnOpen()               { p.m.publicConnsUp.Inc() }
func (p *PromRecorder) PublicConnClose(reason string) { p.m.publicConnsUp.Dec() }
func (p *PromRecorder) PhoneConnOpen()                { p.m.phoneConnsUp.Inc() }
func (p *PromRecorder) PhoneConnClose(reason string)  { p.m.phoneConnsUp.Dec() }
func (p *PromRecorder) StreamOpen()                   { p.m.streamsActive.Inc() }
func (p *PromRecorder) StreamClose()                  { p.m.streamsActive.Dec() }
func (p *PromRecorder) EnrollmentResult(result string) {
	p.m.enrollments.WithLabelValues(result).Inc()
}
func (p *PromRecorder) AttestVerify(result string) { p.m.attestVerify.WithLabelValues(result).Inc() }
func (p *PromRecorder) ACMEIssue(ca, result string) {
	p.m.acmeIssue.WithLabelValues(ca, result).Inc()
}
func (p *PromRecorder) ACMERenew(ca, result string) {
	p.m.acmeRenew.WithLabelValues(ca, result).Inc()
}
func (p *PromRecorder) QuotaExhausted(tunnelName, window string) {
	p.m.quotaExhausted.WithLabelValues(window).Inc()
	// The exhaustion LOG is deduped like any cap hit (first per (tunnel, window) immediately, then ≤1
	// summary/min) — attacker-driven log flooding must stay impossible.
	p.caplog.Hit(tunnelName, "quota-"+window, "")
}
func (p *PromRecorder) ACMECooldown(ca string) { p.m.acmeCooldown.WithLabelValues(ca).Inc() }
func (p *PromRecorder) MeshPool(peer string, size int) {
	p.m.meshPoolSize.WithLabelValues(peer).Set(float64(size))
}

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

// RunFlusher periodically drains the accumulated deltas into the TrafficSink (router.AddTraffic — a real async write path).
// On ctx cancel it returns WITHOUT a final flush: the ordered server drain calls FinalFlush AFTER every
// producer has stopped, so no late delta is lost to a flush that races the still-running data plane.
func (p *PromRecorder) RunFlusher(ctx context.Context, every time.Duration) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			p.flush(ctx)
		}
	}
}

// FinalFlush drains the accumulated deltas once, bounded by flushShutdownTimeout (called from the
// ordered server drain AFTER every producer has stopped).
func (p *PromRecorder) FinalFlush() {
	ctx, cancel := context.WithTimeout(context.Background(), flushShutdownTimeout)
	defer cancel()
	p.flush(ctx)
}

// FlushCapLog emits any pending cap-hit summaries (shutdown).
func (p *PromRecorder) FlushCapLog() { p.caplog.Flush() }

// flush swaps in a fresh empty map (so flushed names are dropped) and applies the deltas via
// router.AddTraffic (both directions in one call). A failed write re-accumulates BOTH deltas into the (new)
// map so the next flush retries them — a counter write is never dropped on a transient sink error.
func (p *PromRecorder) flush(ctx context.Context) {
	if p.traffic == nil {
		return // no traffic sink wired (e.g. metrics-only test wiring) — nothing to flush
	}
	p.mu.Lock()
	drained := p.agg
	p.agg = map[string]*aggEntry{}
	p.mu.Unlock()

	for name, e := range drained {
		if e.bytesIn == 0 && e.bytesOut == 0 {
			continue
		}
		if err := p.traffic.AddTraffic(ctx, name, e.bytesIn, e.bytesOut); err != nil {
			// Re-queue BOTH deltas for the next flush — a transient sink error never drops a counter write.
			p.accum(name, func(a *aggEntry) { a.bytesIn += e.bytesIn; a.bytesOut += e.bytesOut })
			p.log.Warn("tunnel traffic flush failed (delta re-queued)", "tunnel", name, "err", err)
		}
	}
}
