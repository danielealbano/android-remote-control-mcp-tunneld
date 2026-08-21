package router

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// The node registry maps a node id to its NodeInfo (mesh dial address + ops metadata) so an edge that
// resolves a tunnel's owning node (via LookupRoute) can find where to dial. node:{id} → JSON value, TTL'd,
// heartbeat-refreshed at route-ttl/3. Nodes() is an ops/admin SCAN, never on the data path.

// NodeInfo is the node-registry value (JSON in node:{id}). Advertise is the mesh dial address that
// LookupNode returns to the edge; the rest is ops metadata for /api/v1/admin/nodes.
type NodeInfo struct {
	Advertise     string `json:"advertise"`
	Hostname      string `json:"hostname"`
	Version       string `json:"version"`
	StartedAt     string `json:"started_at"`     // RFC3339
	LastHeartbeat string `json:"last_heartbeat"` // RFC3339, stamped by the caller on each (Register|Refresh)Node
}

func nodeKey(id string) string { return "node:" + id }

// RegisterNode writes node:{id} = JSON(info) with a TTL in one call.
func (r *Registry) RegisterNode(ctx context.Context, nodeID string, info NodeInfo, ttl time.Duration) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return r.rdb.Set(ctx, nodeKey(nodeID), b, ttl).Err()
}

// RefreshNode extends the node's TTL (re-writing the JSON, incl. the refreshed last_heartbeat).
func (r *Registry) RefreshNode(ctx context.Context, nodeID string, info NodeInfo, ttl time.Duration) error {
	return r.RegisterNode(ctx, nodeID, info, ttl)
}

// DeregisterNode removes node:{id} at drain time so peers stop mesh-dialing a drained node
// immediately (the TTL remains the crash backstop).
func (r *Registry) DeregisterNode(ctx context.Context, nodeID string) error {
	return r.rdb.Del(ctx, nodeKey(nodeID)).Err()
}

// LookupNode resolves a node id to its mesh advertise address (the edge dial path).
func (r *Registry) LookupNode(ctx context.Context, nodeID string) (advertise string, ok bool, err error) {
	v, err := r.rdb.Get(ctx, nodeKey(nodeID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var info NodeInfo
	if err := json.Unmarshal([]byte(v), &info); err != nil {
		return "", false, err
	}
	return info.Advertise, true, nil
}

// Nodes enumerates all currently-registered nodes (id → NodeInfo). SCAN-based; ops/admin only, never
// on the data path.
func (r *Registry) Nodes(ctx context.Context) (map[string]NodeInfo, error) {
	out := map[string]NodeInfo{}
	var cursor uint64
	for {
		keys, next, err := r.rdb.Scan(ctx, cursor, "node:*", 256).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			v, err := r.rdb.Get(ctx, k).Result()
			if errors.Is(err, redis.Nil) {
				continue
			}
			if err != nil {
				return nil, err
			}
			var info NodeInfo
			if err := json.Unmarshal([]byte(v), &info); err != nil {
				continue // skip a malformed value rather than failing the whole listing
			}
			out[k[len("node:"):]] = info
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return out, nil
}
