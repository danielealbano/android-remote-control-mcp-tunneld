package router

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// The node registry maps a node id to its mesh dial address so an edge that resolves a tunnel's owning
// node (via LookupRoute) can find where to dial. node:{id} → advertise address, TTL'd, heartbeat-
// refreshed at route-ttl/3. Nodes() is an ops/admin SCAN, never on the data path.

func nodeKey(id string) string { return "node:" + id }

// RegisterNode / RefreshNode write node:{id} = advertise with a TTL in one call.
func (r *Registry) RegisterNode(ctx context.Context, nodeID, advertise string, ttl time.Duration) error {
	return r.rdb.Set(ctx, nodeKey(nodeID), advertise, ttl).Err()
}

// RefreshNode extends the node's TTL (re-writing the advertise address).
func (r *Registry) RefreshNode(ctx context.Context, nodeID, advertise string, ttl time.Duration) error {
	return r.rdb.Set(ctx, nodeKey(nodeID), advertise, ttl).Err()
}

// DeregisterNode removes node:{id} at drain time so peers stop mesh-dialing a drained node
// immediately (the TTL remains the crash backstop).
func (r *Registry) DeregisterNode(ctx context.Context, nodeID string) error {
	return r.rdb.Del(ctx, nodeKey(nodeID)).Err()
}

// LookupNode resolves a node id to its mesh advertise address.
func (r *Registry) LookupNode(ctx context.Context, nodeID string) (advertise string, ok bool, err error) {
	v, err := r.rdb.Get(ctx, nodeKey(nodeID)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// Nodes enumerates all currently-registered nodes (id → advertise). SCAN-based; ops/admin only, never
// on the data path.
func (r *Registry) Nodes(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	var cursor uint64
	for {
		keys, next, err := r.rdb.Scan(ctx, cursor, "node:*", 256).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			v, err := r.rdb.Get(ctx, k).Result()
			if err == redis.Nil {
				continue
			}
			if err != nil {
				return nil, err
			}
			out[k[len("node:"):]] = v
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return out, nil
}
