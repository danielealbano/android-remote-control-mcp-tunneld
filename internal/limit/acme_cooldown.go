// Package limit implements tunneld's abuse-control primitives: rate windows, the enroll quota, the
// global stream counter, per-process bandwidth buckets, and the per-CA ACME cooldown/backoff.
package limit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// The ACME rate-limit protection is REACTIVE (no proactive order counter, no budget): a CA answering
// rate-limited gets a per-CA cooldown ("retry-after") in Valkey honoring its Retry-After; other repeated
// failures apply exponential per-CA backoff; the spillover skips a cooling CA.

func cooldownKey(ca string) string { return "acme-cooldown:" + ca }
func failuresKey(ca string) string { return "acme-fail:" + ca }

// SetCACooldown marks ca as cooling for d (SET EX — the TTL IS the cooldown).
func (l *Limiter) SetCACooldown(ctx context.Context, ca string, d time.Duration) error {
	return l.rdb.Set(ctx, cooldownKey(ca), "1", d).Err()
}

// CACooldown returns the remaining cooldown for ca (0 = not cooling).
func (l *Limiter) CACooldown(ctx context.Context, ca string) (time.Duration, error) {
	d, err := l.rdb.PTTL(ctx, cooldownKey(ca)).Result()
	if err != nil {
		return 0, err
	}
	if d < 0 { // -1 (no TTL) / -2 (absent)
		return 0, nil
	}
	return d, nil
}

// bumpFailuresScript INCRs the per-CA failure counter and (re)sets its TTL to `window` so a streak
// older than the largest backoff expires.
var bumpFailuresScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return c
`)

// BumpCAFailures increments the consecutive-failure counter for ca (window is always
// --acme-backoff-max) and returns the new streak length; the caller derives the exponential backoff.
func (l *Limiter) BumpCAFailures(ctx context.Context, ca string, window time.Duration) (int, error) {
	c, err := bumpFailuresScript.Run(ctx, l.rdb, []string{failuresKey(ca)}, window.Milliseconds()).Int()
	if err != nil {
		return 0, err
	}
	return c, nil
}

// ResetCAFailures clears the failure streak on a successful order.
func (l *Limiter) ResetCAFailures(ctx context.Context, ca string) error {
	return l.rdb.Del(ctx, failuresKey(ca)).Err()
}
