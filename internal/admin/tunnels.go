// Package admin composes the per-tunnel admin read surface over the router (routing meta) and the limiter
// (live windows), backing the internal /api/v1/admin/tunnels/list + /stats endpoints. Consumer-site
// interfaces keep it decoupled and avoid an import cycle.
package admin

import (
	"context"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
)

// tunnelMetaReader is the routing-side read surface (implemented by *router.Registry).
type tunnelMetaReader interface {
	ScanTunnels(ctx context.Context, cursor uint64, count int64) (names []string, next uint64, err error)
	TunnelMeta(ctx context.Context, names []string) (map[string]router.TunnelMetaInfo, error)
}

// tunnelWindowReader is the limiter-side read surface (implemented by *limit.Limiter).
type tunnelWindowReader interface {
	TunnelWindows(ctx context.Context, names []string) (map[string]limit.TunnelStat, error)
}

// TunnelStats is one tunnel's merged admin view: routing meta (node + bytes) + live windows.
type TunnelStats struct {
	Node     string `json:"node"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Conc     int64  `json:"conc"`
	BwIn     int64  `json:"bw_in"`
	BwOut    int64  `json:"bw_out"`
	DayIn    int64  `json:"day_in"`
	DayOut   int64  `json:"day_out"`
	WeekIn   int64  `json:"week_in"`
	WeekOut  int64  `json:"week_out"`
}

// Tunnels composes the tunnels admin read surface.
type Tunnels struct {
	meta tunnelMetaReader
	win  tunnelWindowReader
}

// NewTunnels builds the composer over the routing-meta reader and the window reader.
func NewTunnels(meta tunnelMetaReader, win tunnelWindowReader) *Tunnels {
	return &Tunnels{meta: meta, win: win}
}

// List returns ONE SCAN step of tunnel names + the next cursor (0 = complete). No ranking.
func (t *Tunnels) List(ctx context.Context, cursor uint64, count int64) ([]string, uint64, error) {
	return t.meta.ScanTunnels(ctx, cursor, count)
}

// Stats returns per-name merged stats. A name is included ONLY if it has a live route (TunnelMeta returned
// it); a name whose route is gone (a byte-only orphan / just-disconnected tunnel) is OMITTED — live tunnels
// only, consistent with the merged-key live-scoped model.
func (t *Tunnels) Stats(ctx context.Context, names []string) (map[string]TunnelStats, error) {
	meta, err := t.meta.TunnelMeta(ctx, names)
	if err != nil {
		return nil, err
	}
	win, err := t.win.TunnelWindows(ctx, names)
	if err != nil {
		return nil, err
	}
	out := make(map[string]TunnelStats, len(meta))
	for name, m := range meta {
		w := win[name]
		out[name] = TunnelStats{
			Node: m.Node, BytesIn: m.BytesIn, BytesOut: m.BytesOut,
			Conc: w.Conc, BwIn: w.BwIn, BwOut: w.BwOut,
			DayIn: w.DayIn, DayOut: w.DayOut, WeekIn: w.WeekIn, WeekOut: w.WeekOut,
		}
	}
	return out, nil
}
