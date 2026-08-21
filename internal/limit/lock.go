package limit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

const concLockTTL = 5 * time.Second

// ErrConcLockContended is returned when the per-name concurrency lock cannot be taken within the retry bound.
var ErrConcLockContended = errors.New("limit: concurrency lock contended")

func concKey(name string) string     { return "conc:" + name }
func concLockKey(name string) string { return "conclock:" + name }

// mintToken returns a random lock-holder token (best-effort release checks it). Shared by the concurrency
// lock here and the issuance lock.
func mintToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// withConcLock runs fn while holding conclock:{name} (SET NX EX), retrying briefly on contention (the
// section is a couple of hash ops — microseconds). Released only if still held (best-effort token check);
// self-clears via the TTL on a crash. NO Lua.
func (l *Limiter) withConcLock(ctx context.Context, name string, fn func() error) error {
	token := mintToken()
	const attempts = 50
	for range attempts {
		ok, err := l.rdb.SetNX(ctx, concLockKey(name), token, concLockTTL).Result()
		if err != nil {
			return err
		}
		if ok {
			defer func() {
				if v, gerr := l.rdb.Get(ctx, concLockKey(name)).Result(); gerr == nil && v == token {
					_ = l.rdb.Del(ctx, concLockKey(name)).Err()
				}
			}()
			return fn()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ErrConcLockContended
}
