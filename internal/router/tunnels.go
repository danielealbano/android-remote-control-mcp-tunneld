package router

import (
	"context"
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
		v, _ := cmds[i].Result()
		node, _ := v[0].(string)
		if node == "" {
			continue // no live route (or a byte-only orphan) — not reported
		}
		out[n] = TunnelMetaInfo{Node: node, BytesIn: atoiVal(v[1]), BytesOut: atoiVal(v[2])}
	}
	return out, nil
}

// atoiVal parses an HMGET result element (string | nil) to int64; a missing/unparseable value → 0.
func atoiVal(v any) int64 {
	s, ok := v.(string)
	if !ok {
		return 0
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
