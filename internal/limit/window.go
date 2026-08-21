package limit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"
)

// Allow increments the wall-clock-aligned window bucket for (scope, ip) and reports allow/deny plus the
// Retry-After to the window boundary. Key: "rl:{scope}:{ip}:{windowStartUnix}"; the INCR and its EXPIRE NX
// (self-healing TTL set on the first hit) are ONE plain pipeline — no un-TTL'd key, NO Lua. It uses the
// Limiter's injected clock (frozen in tests so a burst never straddles a real window boundary).
func (l *Limiter) Allow(ctx context.Context, scope string, ip netip.Addr, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error) {
	now := l.now()
	winStart := now.Truncate(window)
	key := fmt.Sprintf("rl:%s:%s:%d", scope, ip.String(), winStart.Unix())
	pipe := l.rdb.Pipeline()
	c := pipe.Incr(ctx, key)
	pipe.ExpireNX(ctx, key, window*2) // TTL on the first hit; self-heals on the next same-window write
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}
	if int(c.Val()) > limit {
		return false, winStart.Add(window).Sub(now), nil
	}
	return true, 0, nil
}

// Over is the READ-ONLY companion to Allow: it reports whether (scope, ip) has already reached its
// window limit WITHOUT consuming a slot. Used as a pre-gate before side effects (e.g. minting a nonce
// key) so an over-limit caller cannot trigger them; the authoritative consume still happens via Allow.
func (l *Limiter) Over(ctx context.Context, scope string, ip netip.Addr, limit int, window time.Duration) (over bool, retryAfter time.Duration, err error) {
	now := l.now()
	winStart := now.Truncate(window)
	key := fmt.Sprintf("rl:%s:%s:%d", scope, ip.String(), winStart.Unix())
	count, err := l.rdb.Get(ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, 0, nil
		}
		return false, 0, err
	}
	if int(count) >= limit {
		return true, winStart.Add(window).Sub(now), nil
	}
	return false, 0, nil
}
