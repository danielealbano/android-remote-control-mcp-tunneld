package router

import (
	"context"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// TunnelMetaInfo is the routing-key view for the admin stats endpoint: the owning node + the merged byte
// counters from tunnel:{name}.
type TunnelMetaInfo struct {
	Node     string `json:"node"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// ScanTunnels returns ONE SCAN step over tunnel:{name} keys: the batch of names and the next cursor
// (0 = iteration complete). The caller (admin endpoint) exposes the cursor to the client for pagination —
// no request ever materializes the whole keyspace. count is the SCAN COUNT hint (~100).
func (r *Registry) ScanTunnels(ctx context.Context, cursor uint64, count int64) (names []string, next uint64, err error) {
	keys, next, err := r.rdb.Scan(ctx, cursor, "tunnel:*", count).Result()
	if err != nil {
		return nil, 0, err
	}
	for _, k := range keys {
		names = append(names, k[len("tunnel:"):])
	}
	return names, next, nil
}

// TunnelMeta batch-reads node + byte counters for the given names (one pipeline of HMGETs). Names with no
// live route (no `node` field — e.g. a byte-only orphan) are omitted.
func (r *Registry) TunnelMeta(ctx context.Context, names []string) (map[string]TunnelMetaInfo, error) {
	if len(names) == 0 {
		return map[string]TunnelMetaInfo{}, nil
	}
	pipe := r.rdb.Pipeline()
	cmds := make([]*redis.SliceCmd, len(names))
	for i, n := range names {
		cmds[i] = pipe.HMGet(ctx, key(n), "node", "bytes_in", "bytes_out")
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	out := make(map[string]TunnelMetaInfo, len(names))
	for i, n := range names {
		v := cmds[i].Val()
		node, _ := v[0].(string)
		if node == "" {
			continue // no live route (or a byte-only orphan) — not reported
		}
		out[n] = TunnelMetaInfo{Node: node, BytesIn: r.atoiVal(n, v[1]), BytesOut: r.atoiVal(n, v[2])}
	}
	return out, nil
}

// atoiVal parses an HMGET result element (string | nil) to int64; a missing/unparseable value → 0.
func (r *Registry) atoiVal(name string, v any) int64 {
	if v == nil {
		return 0
	}
	s, ok := v.(string)
	if !ok {
		r.logger.Warn("unexpected route byte counter type (reported as 0)", "tunnel", name, "type", fmt.Sprintf("%T", v))
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		r.logger.Warn("unparseable route byte counter (reported as 0)", "tunnel", name, "err", err)
		return 0
	}
	return n
}
