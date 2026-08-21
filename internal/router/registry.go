// Package router implements the cross-replica routing table (name→node, heartbeat TTL) over Redis.
// tunnel:{name} stores {node, fingerprint, connID}; teardown/refresh are owner-conditional on the
// per-connection connID (serialized by the per-name lock) so same-node reconnects and cross-node re-binds
// are both safe.
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

// ErrLockContended is returned when the per-name route lock cannot be taken within the retry bound.
var ErrLockContended = errors.New("router: route lock contended")

// HeartbeatResult is the three-state outcome of Heartbeat.
type HeartbeatResult int

const (
	// HeartbeatRefreshed: still the owner, TTL refreshed.
	HeartbeatRefreshed HeartbeatResult = iota
	// HeartbeatNotOwner: route now points at a DIFFERENT connID (superseded).
	HeartbeatNotOwner
	// HeartbeatMissing: no tunnel:{name} at all (TTL lapsed) — the caller self-heals by re-Binding.
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

// NewRegistry constructs a Registry; ttl is --route-ttl (the phone control heartbeat refreshes at ttl/3).
func NewRegistry(rdb redis.UniversalClient, ttl time.Duration) *Registry {
	return &Registry{rdb: rdb, ttl: ttl}
}

func key(name string) string { return "tunnel:" + name }

// Heartbeat refreshes tunnel:{name}'s TTL ONLY (PEXPIRE — never rewrites the value), and ONLY while this
// connID still owns the route: it reads connID first, and issues the PEXPIRE only on an ownership match, so
// a stale/superseded connection can NEVER extend the current owner's route lifetime (owner-conditional
// TTL). Three-state result: absent key → Missing (caller self-heals); a different connID → NotOwner (no
// refresh); our connID → PEXPIRE → Refreshed (or Missing if it vanished between the read and the refresh).
// No lock is needed — a spurious PEXPIRE can at worst extend the CORRECT (already re-bound) owner's TTL,
// which is harmless (it never changes the value/owner).
func (r *Registry) Heartbeat(ctx context.Context, name, connID string) (HeartbeatResult, error) {
	owner, err := r.rdb.HGet(ctx, key(name), "connID").Result()
	if errors.Is(err, redis.Nil) {
		return HeartbeatMissing, nil // key gone (or a byte-only orphan with no connID) → self-heal
	}
	if err != nil {
		return HeartbeatMissing, err
	}
	if owner != connID {
		return HeartbeatNotOwner, nil // superseded — do NOT refresh the new owner's TTL
	}
	ok, err := r.rdb.PExpire(ctx, key(name), r.ttl).Result()
	if err != nil {
		return HeartbeatMissing, err
	}
	if !ok {
		return HeartbeatMissing, nil // key expired between the read and the refresh → self-heal
	}
	return HeartbeatRefreshed, nil
}

// Unbind deletes tunnel:{name} ONLY while it still belongs to connID, serialized by the per-name lock so no
// concurrent bind can interleave between the connID read and the DEL (deterministic — replaces the CAS
// Lua). A stale connection reads a different connID and declines to delete.
func (r *Registry) Unbind(ctx context.Context, name, connID string) error {
	return r.withLock(ctx, name, func() error {
		owner, err := r.rdb.HGet(ctx, key(name), "connID").Result()
		if errors.Is(err, redis.Nil) {
			return nil // already gone
		}
		if err != nil {
			return err
		}
		if owner != connID {
			return nil // superseded by a newer bind — never clobber it
		}
		return r.rdb.Del(ctx, key(name)).Err()
	})
}
