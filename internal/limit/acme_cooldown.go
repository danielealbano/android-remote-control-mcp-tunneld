// Package limit implements tunneld's abuse-control primitives: rate windows, the enroll quota, the
// global stream counter, the per-second bandwidth + packet windows, and the ACME cooldown/backoff.
package limit

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/redis/go-redis/v9"
)

func cooldownKey(ca string) string { return "acme-cooldown:" + ca }
func failuresKey(ca string) string { return "acme-fail:" + ca }
func limitedKey(ca string) string  { return "acme-429:" + ca }

// SetCACooldown marks ca as cooling for d (the TTL IS the cooldown).
func (l *Limiter) SetCACooldown(ctx context.Context, ca string, d time.Duration) error {
	d = max(time.Duration(math.Ceil(d.Seconds()))*time.Second, time.Second)
	pipe := l.rdb.Pipeline()
	pipe.ExpireGT(ctx, cooldownKey(ca), d)
	pipe.SetNX(ctx, cooldownKey(ca), "1", d)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("set acme wait-until %s: %w", ca, err)
	}
	return nil
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

func (l *Limiter) MarkCALimited(ctx context.Context, ca string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("set acme 429 mark %s: ttl must be positive, got %s", ca, ttl)
	}
	if err := l.rdb.Set(ctx, limitedKey(ca), rand.Text(), ttl).Err(); err != nil {
		return fmt.Errorf("set acme 429 mark %s: %w", ca, err)
	}
	return nil
}

func (l *Limiter) CAWaitState(ctx context.Context, ca string) (time.Duration, string, error) {
	pipe := l.rdb.Pipeline()
	wait := pipe.PTTL(ctx, cooldownKey(ca))
	mark := pipe.Get(ctx, limitedKey(ca))
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return 0, "", fmt.Errorf("read acme wait state %s: %w", ca, err)
	}
	m, err := mark.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return 0, "", fmt.Errorf("read acme 429 mark %s: %w", ca, err)
	}
	return max(wait.Val(), 0), m, nil
}

// BumpCAFailures increments the consecutive-failure counter for ca (window is always
// --acme-backoff-max) and returns the new streak length; the caller derives the exponential backoff.
// INCR + PEXPIRE(window) are ONE plain pipeline so a streak older than the largest backoff expires — NO Lua.
func (l *Limiter) BumpCAFailures(ctx context.Context, ca string, window time.Duration) (int, error) {
	pipe := l.rdb.Pipeline()
	c := pipe.Incr(ctx, failuresKey(ca))
	pipe.PExpire(ctx, failuresKey(ca), window)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return int(c.Val()), nil
}

// ResetCAFailures clears the failure streak on a successful order.
func (l *Limiter) ResetCAFailures(ctx context.Context, ca string) error {
	return l.rdb.Del(ctx, failuresKey(ca)).Err()
}
