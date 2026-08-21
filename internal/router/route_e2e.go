package router

import (
	"context"
	"errors"
)

// ErrConnIDCollision is returned by BindRoute when the connID it is asked to bind equals the connID
// already stored for the name (a re-roll signal): the caller re-mints the connID and retries.
var ErrConnIDCollision = errors.New("router: connID collides with the current route owner")

// BindRoute writes tunnel:{name} with node, fingerprint, and per-connection connID (fingerprint guard →
// ErrNameHeldByOther; a connID equal to the currently-stored one → ErrConnIDCollision, the re-roll
// signal), serialized by the per-name lock. Otherwise last-writer-wins. Heartbeat/Unbind stay
// owner-conditional on connID.
func (r *Registry) BindRoute(ctx context.Context, name, nodeID, fingerprint, connID string) error {
	return r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "fingerprint", "connID").Result()
		if err != nil {
			return err
		}
		if fp, _ := vals[0].(string); fp != "" && fp != fingerprint {
			return ErrNameHeldByOther
		}
		if cid, _ := vals[1].(string); cid == connID {
			return ErrConnIDCollision
		}
		pipe := r.rdb.Pipeline()
		pipe.HSet(ctx, key(name), "node", nodeID, "fingerprint", fingerprint, "connID", connID)
		pipe.PExpire(ctx, key(name), r.ttl)
		_, err = pipe.Exec(ctx)
		return err
	})
}

// BindRouteIfAbsentOrOwner is the self-heal variant used by the phone heartbeat's "missing" path: it binds
// only if the key is absent or still owned by this connID (same fingerprint), under the per-name lock.
func (r *Registry) BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, fingerprint, connID string) (SelfHealResult, error) {
	var res SelfHealResult
	err := r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "node", "fingerprint", "connID").Result()
		if err != nil {
			return err
		}
		node, _ := vals[0].(string)
		fp, _ := vals[1].(string)
		cid, _ := vals[2].(string)
		if node == "" { // absent → bind
			res = SelfHealBound
			return bindHSet(ctx, r, name, nodeID, fingerprint, connID)
		}
		if fp != fingerprint {
			res = SelfHealConflict
			return ErrNameHeldByOther
		}
		if cid != connID {
			res = SelfHealNotOwner
			return nil
		}
		res = SelfHealBound
		return bindHSet(ctx, r, name, nodeID, fingerprint, connID)
	})
	return res, err
}

// bindHSet writes the three routing fields + TTL in one pipeline (shared by bind + self-heal).
func bindHSet(ctx context.Context, r *Registry, name, nodeID, fingerprint, connID string) error {
	pipe := r.rdb.Pipeline()
	pipe.HSet(ctx, key(name), "node", nodeID, "fingerprint", fingerprint, "connID", connID)
	pipe.PExpire(ctx, key(name), r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// LookupRoute returns the owning node, the identity-cert fingerprint, and the phone-connection connID,
// or ok=false when no tunnel is bound.
func (r *Registry) LookupRoute(ctx context.Context, name string) (nodeID, fingerprint, connID string, ok bool, err error) {
	vals, err := r.rdb.HMGet(ctx, key(name), "node", "fingerprint", "connID").Result()
	if err != nil {
		return "", "", "", false, err
	}
	node, _ := vals[0].(string)
	fp, _ := vals[1].(string)
	cid, _ := vals[2].(string)
	if node == "" {
		return "", "", "", false, nil
	}
	return node, fp, cid, true, nil
}
