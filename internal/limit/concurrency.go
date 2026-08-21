package limit

import (
	"context"
	"errors"

	"github.com/redis/go-redis/v9"
)

// AcquireStream reserves one of maxN concurrent-stream slots for (name, connID). conc:{name} is a hash
// {connID, count} guarded by the per-name lock so every op verifies ownership. A fresh owner (stored connID
// differs, or the key is absent) RESETS the counter — a new phone connection's prior streams are dead, so
// this acquire is the only live stream (this replaces the old reset-on-bind). The owner path HINCRBYs and,
// if over cap, rolls back and denies (fail-safe — never breaches). The count is global across replicas
// (every edge reads the same connID from the route). Every write sets the TTL in the same lock section.
func (l *Limiter) AcquireStream(ctx context.Context, name, connID string, maxN int) (bool, error) {
	var admit bool
	err := l.withConcLock(ctx, name, func() error {
		owner, herr := l.rdb.HGet(ctx, concKey(name), "connID").Result()
		if herr != nil && !errors.Is(herr, redis.Nil) {
			return herr
		}
		var c int64
		if errors.Is(herr, redis.Nil) || owner != connID {
			if e := l.rdb.HSet(ctx, concKey(name), "connID", connID, "count", 1).Err(); e != nil {
				return e
			}
			c = 1
		} else if c, herr = l.rdb.HIncrBy(ctx, concKey(name), "count", 1).Result(); herr != nil {
			return herr
		}
		if c > int64(maxN) { // over cap → roll back this slot (DEL a fresh reset, else DECR)
			if c == 1 {
				_ = l.rdb.Del(ctx, concKey(name)).Err()
			} else {
				_ = l.rdb.HIncrBy(ctx, concKey(name), "count", -1).Err()
			}
			admit = false
			return nil
		}
		admit = true
		return l.rdb.PExpire(ctx, concKey(name), l.streamTTL).Err()
	})
	if err != nil {
		return false, err
	}
	return admit, nil
}

// ReleaseStream frees a slot for (name, connID): under the lock it decrements ONLY if this connID still owns
// the counter — a straggler release from a superseded connection is a NO-OP (it can never corrupt the new
// owner's count). At zero the key is DELeted (safe under the lock — no acquire can interleave). NO Lua.
func (l *Limiter) ReleaseStream(ctx context.Context, name, connID string) error {
	return l.withConcLock(ctx, name, func() error {
		owner, err := l.rdb.HGet(ctx, concKey(name), "connID").Result()
		if errors.Is(err, redis.Nil) {
			return nil // already gone
		}
		if err != nil {
			return err
		}
		if owner != connID {
			return nil // superseded — not ours to decrement
		}
		c, err := l.rdb.HIncrBy(ctx, concKey(name), "count", -1).Result()
		if err != nil {
			return err
		}
		if c <= 0 {
			return l.rdb.Del(ctx, concKey(name)).Err()
		}
		return l.rdb.PExpire(ctx, concKey(name), l.streamTTL).Err()
	})
}
