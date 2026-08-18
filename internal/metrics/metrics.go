// Package metrics registers the Prometheus metric families into a CUSTOM registry (never the default
// one), plus the internal listener (/metrics, /healthz, /admin/tunnels) and the PromRecorder that
// implements observ.Recorder. NO per-tunnel metric labels (cardinality).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds the registered families and their custom registry.
type Metrics struct {
	reg *prometheus.Registry

	tunnelsConnected    prometheus.Gauge
	enrollments         prometheus.Counter
	wsConnects          prometheus.Counter
	wsDisconnects       *prometheus.CounterVec // {reason}
	httpRequests        *prometheus.CounterVec // {class, code}
	httpDuration        prometheus.Histogram
	httpInflight        prometheus.Gauge
	rejections          *prometheus.CounterVec // {reason}
	bytesTotal          *prometheus.CounterVec // {direction}
	pubsubPublishErrors prometheus.Counter
	requestTimeouts     prometheus.Counter

	// --- Plan 3 (E2E) families ---
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
}

// NewMetrics registers every family into a fresh registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		tunnelsConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tunneld_tunnels_connected", Help: "Currently connected tunnels.",
		}),
		enrollments: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tunneld_enrollments_total", Help: "Total enrollments.",
		}),
		wsConnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tunneld_ws_connects_total", Help: "Total WebSocket connects.",
		}),
		wsDisconnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_ws_disconnects_total", Help: "WebSocket disconnects by reason.",
		}, []string{"reason"}),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_http_requests_total", Help: "Forwarded HTTP requests by class and code.",
		}, []string{"class", "code"}),
		httpDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "tunneld_http_request_duration_seconds", Help: "Forwarded request duration.",
			Buckets: prometheus.DefBuckets,
		}),
		httpInflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tunneld_http_inflight", Help: "In-flight forwarded requests.",
		}),
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_rejections_total", Help: "Rejections by reason.",
		}, []string{"reason"}),
		bytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_bytes_total", Help: "Bridged bytes by direction.",
		}, []string{"direction"}),
		pubsubPublishErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tunneld_pubsub_publish_errors_total", Help: "Redis publish errors.",
		}),
		requestTimeouts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tunneld_request_timeouts_total", Help: "Request timeouts.",
		}),
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
	}
	reg.MustRegister(
		m.tunnelsConnected, m.enrollments, m.wsConnects, m.wsDisconnects,
		m.httpRequests, m.httpDuration, m.httpInflight, m.rejections,
		m.bytesTotal, m.pubsubPublishErrors, m.requestTimeouts,
		m.publicConnsUp, m.phoneConnsUp, m.streamsActive, m.quotaExhausted,
		m.attestVerify, m.acmeIssue, m.acmeRenew, m.acmeCooldown, m.meshPoolSize, m.perConnMem,
		collectors.NewGoCollector(),
	)
	return m
}

// Registry returns the custom registry (mounted at /metrics; the default registry exposes none of
// these families).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }
