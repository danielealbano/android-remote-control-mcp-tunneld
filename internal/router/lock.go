package router

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// lockTTL bounds a create/delete critical section (a single SET or HGET+DEL — microseconds). It is far
// larger than the section, so the lock cannot expire mid-section; on a process crash it self-clears.
const lockTTL = 5 * time.Second

func lockKey(name string) string { return "lock:" + name }

// mintToken returns a random lock-holder token (best-effort release checks it).
func mintToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// acquire takes the per-name lock (SET NX PX). ok=false means another create/delete holds it — the caller
// retries briefly. The token is returned for release.
func (r *Registry) acquire(ctx context.Context, name string) (token string, ok bool, err error) {
	token = mintToken()
	set, err := r.rdb.SetNX(ctx, lockKey(name), token, lockTTL).Result()
	if err != nil {
		return "", false, err
	}
	return token, set, nil
}

// release drops the lock only if we still hold it. Best-effort: a GET+DEL race is negligible because the
// section is microseconds and the TTL is seconds, and the lock self-expires regardless (posture: no Lua).
func (r *Registry) release(ctx context.Context, name, token string) {
	if v, err := r.rdb.Get(ctx, lockKey(name)).Result(); err == nil && v == token {
		_ = r.rdb.Del(ctx, lockKey(name)).Err()
	}
}

// withLock runs fn while holding the per-name lock, retrying acquisition on contention up to a short bound
// (the section is microseconds; contention is rare). A Valkey error acquiring is returned to the caller.
func (r *Registry) withLock(ctx context.Context, name string, fn func() error) error {
	const attempts = 50
	for range attempts {
		token, ok, err := r.acquire(ctx, name)
		if err != nil {
			return err
		}
		if ok {
			defer r.release(ctx, name, token)
			return fn()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ErrLockContended
}
