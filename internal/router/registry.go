// Package router implements the cross-replica routing table (name→node, heartbeat TTL) over Redis.
// route:{name} stores {node, fingerprint, connID}; teardown/refresh are owner-conditional on the
// per-connection connID so same-node reconnects and cross-node re-binds are both safe.
package router

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNameHeldByOther is returned when a bind for name arrives with a fingerprint different from the
// one already stored (a name held by a different certificate).
var ErrNameHeldByOther = errors.New("router: name held by a different fingerprint")

// HeartbeatResult is the three-state outcome of Heartbeat.
type HeartbeatResult int

const (
	// HeartbeatRefreshed: still the owner, TTL refreshed.
	HeartbeatRefreshed HeartbeatResult = iota
	// HeartbeatNotOwner: route now points at a DIFFERENT connID (superseded).
	HeartbeatNotOwner
	// HeartbeatMissing: no route:{name} at all (TTL lapsed) — the caller self-heals by re-Binding.
	HeartbeatMissing
)

// SelfHealResult is the three-state outcome of BindIfAbsentOrOwner.
type SelfHealResult int

const (
	// SelfHealBound: the route was absent (or still owned by this connID) and is now bound.
	SelfHealBound SelfHealResult = iota
	// SelfHealNotOwner: the route is held by a DIFFERENT connID (same fingerprint) — do NOT clobber.
	SelfHealNotOwner
	// SelfHealConflict: the route is held by a DIFFERENT fingerprint (returned with ErrNameHeldByOther).
	SelfHealConflict
)

// Registry is the Redis-backed routing table.
type Registry struct {
	rdb redis.UniversalClient
	ttl time.Duration
}

// NewRegistry constructs a Registry; ttl is --route-ttl (the WS heartbeat refreshes at ttl/3).
func NewRegistry(rdb redis.UniversalClient, ttl time.Duration) *Registry {
	return &Registry{rdb: rdb, ttl: ttl}
}

// heartbeatScript is owner-conditional on connID and reports refreshed | not-owner | missing.
var heartbeatScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 'missing'
end
if redis.call('HGET', KEYS[1], 'connID') ~= ARGV[1] then
  return 'not-owner'
end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 'refreshed'
`)

// unbindScript deletes route:{name} ONLY if its stored connID still matches (never clobbers a route
// re-bound by a newer connection).
var unbindScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'connID') == ARGV[1] then
  redis.call('DEL', KEYS[1])
end
return 'ok'
`)

func key(name string) string { return "route:" + name }

// Heartbeat refreshes route:{name} ONLY while it still belongs to connID, returning the three-state
// result.
func (r *Registry) Heartbeat(ctx context.Context, name, connID string) (HeartbeatResult, error) {
	res, err := heartbeatScript.Run(ctx, r.rdb, []string{key(name)}, connID, r.ttl.Milliseconds()).Text()
	if err != nil {
		return HeartbeatMissing, err
	}
	switch res {
	case "refreshed":
		return HeartbeatRefreshed, nil
	case "not-owner":
		return HeartbeatNotOwner, nil
	default:
		return HeartbeatMissing, nil
	}
}

// Unbind removes route:{name} ONLY while it still belongs to connID.
func (r *Registry) Unbind(ctx context.Context, name, connID string) error {
	return unbindScript.Run(ctx, r.rdb, []string{key(name)}, connID).Err()
}
