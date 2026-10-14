package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// The node registry maps a node id to its NodeInfo (mesh dial address + ops metadata). node:{id} → JSON
// value, TTL'd, heartbeat-refreshed at route-ttl/3. Nodes() is an ops/admin SCAN, never on the data path.

// NodeInfo is the node-registry value (JSON in node:{id}). Advertise is the mesh dial address; the rest
// is ops metadata for /api/v1/admin/nodes.
type NodeInfo struct {
	Advertise     string `json:"advertise"`
	Hostname      string `json:"hostname"`
	Version       string `json:"version"`
	StartedAt     string `json:"started_at"`     // RFC3339
	LastHeartbeat string `json:"last_heartbeat"` // RFC3339, stamped by the caller on each (Register|Refresh)Node
}

func nodeKey(id string) string { return "node:" + id }

const nodeSetKey = "nodes"

// RegisterNode writes node:{id} = JSON(info) with a TTL in one call.
func (r *Registry) RegisterNode(ctx context.Context, nodeID string, info NodeInfo, ttl time.Duration) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	pipe := r.rdb.Pipeline()
	pipe.Set(ctx, nodeKey(nodeID), b, ttl)
	pipe.SAdd(ctx, nodeSetKey, nodeID)
	pipe.PExpire(ctx, nodeSetKey, 3*ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("register node %s: %w", nodeID, err)
	}
	return nil
}

// RefreshNode extends the node's TTL (re-writing the JSON, incl. the refreshed last_heartbeat).
func (r *Registry) RefreshNode(ctx context.Context, nodeID string, info NodeInfo, ttl time.Duration) error {
	return r.RegisterNode(ctx, nodeID, info, ttl)
}

// DeregisterNode removes node:{id} at drain time so peers stop mesh-dialing a drained node
// immediately (the TTL remains the crash backstop).
func (r *Registry) DeregisterNode(ctx context.Context, nodeID string) error {
	pipe := r.rdb.Pipeline()
	pipe.Del(ctx, nodeKey(nodeID))
	pipe.SRem(ctx, nodeSetKey, nodeID)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("deregister node %s: %w", nodeID, err)
	}
	return nil
}

func (r *Registry) LiveNodes(ctx context.Context) (map[string]NodeInfo, error) {
	ids, err := r.rdb.SMembers(ctx, nodeSetKey).Result()
	if err != nil {
		return nil, fmt.Errorf("list node ids: %w", err)
	}
	out := map[string]NodeInfo{}
	if len(ids) == 0 {
		return out, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = nodeKey(id)
	}
	vals, err := r.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("read node entries: %w", err)
	}
	var gone []any
	for i, v := range vals {
		s, ok := v.(string)
		if !ok {
			gone = append(gone, ids[i])
			continue
		}
		var info NodeInfo
		if err := json.Unmarshal([]byte(s), &info); err != nil {
			r.logger.Warn("malformed node registry entry skipped", "node", ids[i], "err", err)
			continue
		}
		out[ids[i]] = info
	}
	if len(gone) > 0 {
		if err := r.rdb.SRem(ctx, nodeSetKey, gone...).Err(); err != nil {
			r.logger.Debug("expired node ids not pruned (retried on the next read)", "err", err)
		}
	}
	return out, nil
}

// LookupNode resolves a node id to its mesh advertise address.
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
				r.logger.Warn("malformed node registry entry skipped", "key", k, "err", err)
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
