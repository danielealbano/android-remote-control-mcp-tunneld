// Package metrics registers the Prometheus metric families into a CUSTOM registry (never the default
// one), plus the internal listener (/metrics, /healthz, /api/v1/admin/tunnels/list) and the PromRecorder that
// implements observ.Recorder. NO per-tunnel metric labels (cardinality).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/observ"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// perConnMemEstimateBytes is the steady-state per-connection heap estimate a bridged public connection
// holds: two directional paced-copy buffers of ~ChunkSize each. It is a capacity-planning ESTIMATE
// (static), not a live measurement — the live process footprint is exported by the Go collector.
const perConnMemEstimateBytes = 2 * wire.ChunkSize

// Metrics holds the registered families and their custom registry.
type Metrics struct {
	reg *prometheus.Registry

	enrollments *prometheus.CounterVec // {result}
	rejections  *prometheus.CounterVec // {reason} — labels pre-registered from observ.RejectReasons
	bytesTotal  *prometheus.CounterVec // {direction}

	// --- E2E families ---
	publicConnsUp  prometheus.Gauge
	phoneConnsUp   prometheus.Gauge
	streamsActive  prometheus.Gauge
	quotaExhausted *prometheus.CounterVec // {window}
	attestVerify   *prometheus.CounterVec // {result}
	acmeIssue      *prometheus.CounterVec // {ca, result}
	acmeRenew      *prometheus.CounterVec // {ca, result}
	acmeCooldown   *prometheus.CounterVec // {ca}
	meshPoolSize   *prometheus.GaugeVec   // {peer}
	perConnMem     prometheus.Gauge
	connLogDropped prometheus.Counter
}

// NewMetrics registers every family into a fresh registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		enrollments: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_enrollments_total", Help: "Enrollment outcomes by result.",
		}, []string{"result"}),
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_rejections_total", Help: "Rejections by reason.",
		}, []string{"reason"}),
		bytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_bytes_total", Help: "Bridged bytes by direction.",
		}, []string{"direction"}),
		publicConnsUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tunneld_public_connections", Help: "Currently open public connections.",
		}),
		phoneConnsUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tunneld_phone_connections", Help: "Currently connected phones.",
		}),
		streamsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tunneld_streams_active", Help: "Currently active data streams.",
		}),
		quotaExhausted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_quota_exhausted_total", Help: "Per-tunnel quota exhaustion by window.",
		}, []string{"window"}),
		attestVerify: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_attest_verify_total", Help: "Attestation verify outcomes.",
		}, []string{"result"}),
		acmeIssue: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_acme_issue_total", Help: "ACME issuances by CA and result.",
		}, []string{"ca", "result"}),
		acmeRenew: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_acme_renew_total", Help: "ACME renewals by CA and result.",
		}, []string{"ca", "result"}),
		acmeCooldown: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_acme_cooldown_total", Help: "Per-CA cooldown activations.",
		}, []string{"ca"}),
		meshPoolSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tunneld_mesh_pool_size", Help: "Mesh connection pool size by peer.",
		}, []string{"peer"}),
		perConnMem: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tunneld_per_conn_mem_bytes", Help: "Estimated per-connection memory.",
		}),
		connLogDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tunneld_connlog_dropped_total", Help: "Connection-log events dropped: queue full or retries exhausted.",
		}),
	}
	reg.MustRegister(
		m.enrollments, m.rejections, m.bytesTotal,
		m.publicConnsUp, m.phoneConnsUp, m.streamsActive, m.quotaExhausted,
		m.attestVerify, m.acmeIssue, m.acmeRenew, m.acmeCooldown, m.meshPoolSize, m.perConnMem,
		m.connLogDropped,
		collectors.NewGoCollector(),
	)
	// Pre-register the EXACT rejection-reason label set so the family always exposes every registered
	// reason (and only those — PromRecorder.Reject refuses labels outside observ.RejectReasons).
	for _, r := range observ.RejectReasons {
		m.rejections.WithLabelValues(r)
	}
	m.perConnMem.Set(float64(perConnMemEstimateBytes))
	return m
}

// Registry returns the custom registry (mounted at /metrics; the default registry exposes none of
// these families).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// ConnLogDropped returns the dropped-connection-log-events counter (wired to the async conn-log
// writer's drop callback in server.Run).
func (m *Metrics) ConnLogDropped() prometheus.Counter { return m.connLogDropped }
