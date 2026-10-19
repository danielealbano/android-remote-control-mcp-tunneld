package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/admin"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

// NodeSource is the node-registry read surface (implemented by *router.Registry).
type NodeSource interface {
	Nodes(ctx context.Context) (map[string]router.NodeInfo, error)
}

// TunnelSource is the admin tunnels read surface (implemented by internal/admin composing router + limit).
type TunnelSource interface {
	List(ctx context.Context, cursor uint64, count int64) (names []string, next uint64, err error)
	Stats(ctx context.Context, names []string) (map[string]admin.TunnelStats, error)
}

const (
	defaultTunnelCount = 100
	maxTunnelCount     = 500
	maxStatsBody       = 64 << 10 // 64 KiB cap on the /stats request body
)

// Handler builds the internal listener mux: /metrics (custom registry), /healthz (Redis PING),
// /api/v1/admin/tunnels/list (paginated names) + /api/v1/admin/tunnels/stats (batch stats), and
// /api/v1/admin/nodes (node registry JSON). This listener is NEVER proxied.
func Handler(reg *prometheus.Registry, rdb redis.UniversalClient, tunnelSrc TunnelSource, nodeSrc NodeSource, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := rdb.Ping(r.Context()).Err(); err != nil {
			http.Error(w, "redis unavailable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Debug("healthz response write failed", "err", err)
		}
	})
	// GET /api/v1/admin/tunnels/list?cursor=&count= → ONE SCAN step: {names, cursor}. No backend ranking;
	// the client drives pagination by feeding the returned cursor back (cursor "0" = iteration complete).
	mux.HandleFunc("/api/v1/admin/tunnels/list", func(w http.ResponseWriter, r *http.Request) {
		var cursor uint64
		if v := r.URL.Query().Get("cursor"); v != "" {
			c, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				http.Error(w, "bad cursor", http.StatusBadRequest)
				return
			}
			cursor = c
		}
		count := int64(defaultTunnelCount)
		if v := r.URL.Query().Get("count"); v != "" {
			c, err := strconv.Atoi(v)
			if err != nil || c <= 0 {
				http.Error(w, "bad count", http.StatusBadRequest)
				return
			}
			count = int64(c)
		}
		if count > maxTunnelCount {
			count = maxTunnelCount
		}
		names, next, err := tunnelSrc.List(r.Context(), cursor, count)
		if err != nil {
			log.Warn("admin tunnels list failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			Names  []string `json:"names"`
			Cursor string   `json:"cursor"`
		}{Names: names, Cursor: strconv.FormatUint(next, 10)}); err != nil {
			log.Debug("admin tunnels list response write failed", "err", err)
		}
	})
	// POST /api/v1/admin/tunnels/stats {names:[…]} → per-name merged stats (live tunnels only).
	mux.HandleFunc("/api/v1/admin/tunnels/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxStatsBody)
		var body struct {
			Names []string `json:"names"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(body.Names) > maxTunnelCount {
			http.Error(w, "too many names", http.StatusBadRequest)
			return
		}
		stats, err := tunnelSrc.Stats(r.Context(), body.Names)
		if err != nil {
			log.Warn("admin tunnels stats failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			log.Debug("admin tunnels stats response write failed", "err", err)
		}
	})
	mux.HandleFunc("/api/v1/admin/nodes", func(w http.ResponseWriter, r *http.Request) {
		nodes, err := nodeSrc.Nodes(r.Context())
		if err != nil {
			log.Warn("admin nodes failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nodes); err != nil {
			log.Debug("admin nodes response write failed", "err", err)
		}
	})
	return mux
}
