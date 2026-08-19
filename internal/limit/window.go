package limit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/redis/go-redis/v9"
)

// allowScript atomically increments the window bucket and sets its TTL on the first hit (so a key is
// never left un-TTL'd). Returns the post-increment count.
var allowScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`)

// Allow increments the wall-clock-aligned window bucket for (scope, ip) and reports allow/deny plus
// the Retry-After to the window boundary. Key: "rl:{scope}:{ip}:{windowStartUnix}"; the INCR and its
// PEXPIRE(window*2) are a single Lua script (atomic — no un-TTL'd key). It uses the Limiter's injected
// clock (frozen in tests so a burst never straddles a real window boundary).
func (l *Limiter) Allow(ctx context.Context, scope string, ip netip.Addr, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error) {
	now := l.now()
	winStart := now.Truncate(window)
	key := fmt.Sprintf("rl:%s:%s:%d", scope, ip.String(), winStart.Unix())
	ttlMS := (window * 2).Milliseconds()

	count, err := allowScript.Run(ctx, l.rdb, []string{key}, ttlMS).Int64()
	if err != nil {
		return false, 0, err
	}
	if int(count) > limit {
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
