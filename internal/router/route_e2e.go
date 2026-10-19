package router

import (
	"context"
	"errors"
)

// ErrConnIDCollision is returned by BindRoute when the connID it is asked to bind equals the connID
// already stored for the name (a re-roll signal): the caller re-mints the connID and retries.
var ErrConnIDCollision = errors.New("router: connID collides with the current route owner")

// BindRoute writes tunnel:{name} with node and per-connection connID (a connID equal to the currently-stored
// one → ErrConnIDCollision, the re-roll signal), serialized by the per-name lock. Otherwise last-writer-wins.
// Heartbeat/Unbind stay owner-conditional on connID.
func (r *Registry) BindRoute(ctx context.Context, name, nodeID, connID string) error {
	return r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "connID").Result()
		if err != nil {
			return err
		}
		if cid, _ := vals[0].(string); cid == connID {
			return ErrConnIDCollision
		}
		return bindHSet(ctx, r, name, nodeID, connID, true) // fresh owner → zero the byte fields
	})
}

// BindRouteIfAbsentOrOwner is the self-heal variant used by the phone heartbeat's "missing" path: it binds
// only if the key is absent or still owned by this connID, under the per-name lock.
func (r *Registry) BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, connID string) (SelfHealResult, error) {
	var res SelfHealResult
	err := r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "node", "connID").Result()
		if err != nil {
			return err
		}
		node, _ := vals[0].(string)
		cid, _ := vals[1].(string)
		if node == "" { // absent → fresh bind (zero the byte fields)
			res = SelfHealBound
			return bindHSet(ctx, r, name, nodeID, connID, true)
		}
		if cid != connID {
			res = SelfHealNotOwner
			return nil
		}
		res = SelfHealBound
		return bindHSet(ctx, r, name, nodeID, connID, false) // same connID → keep the live byte counters
	})
	return res, err
}

// bindHSet writes the routing fields + TTL (shared by bind + self-heal). resetBytes zeroes the
// live-scoped byte counters on a FRESH owner (new connID / absent) so a reconnect within the TTL window
// never sums onto the old session; a same-connID self-heal passes resetBytes=false to keep the ongoing
// counters. The identity-scoped traf: day/week quotas are separate keys and are NEVER touched here.
func bindHSet(ctx context.Context, r *Registry, name, nodeID, connID string, resetBytes bool) error {
	fields := []any{"node", nodeID, "connID", connID}
	if resetBytes {
		fields = append(fields, "bytes_in", 0, "bytes_out", 0)
	}
	pipe := r.rdb.Pipeline()
	pipe.HSet(ctx, key(name), fields...)
	pipe.PExpire(ctx, key(name), r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// LookupRoute returns the owning node and the phone-connection connID, or ok=false when no tunnel is bound.
func (r *Registry) LookupRoute(ctx context.Context, name string) (nodeID, connID string, ok bool, err error) {
	vals, err := r.rdb.HMGet(ctx, key(name), "node", "connID").Result()
	if err != nil {
		return "", "", false, err
	}
	node, _ := vals[0].(string)
	cid, _ := vals[1].(string)
	if node == "" {
		return "", "", false, nil
	}
	return node, cid, true, nil
}
