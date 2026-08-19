package limit

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// acquireScript atomically INCRs conc:{name}; if the result exceeds max it DECRs back and denies;
// otherwise it sets the safety TTL and admits. Single Lua so a crash can never leave an un-TTL'd
// counter (matches window.go and the "every Redis key has a TTL" invariant, docs/ARCHITECTURE.md §5).
var acquireScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c > tonumber(ARGV[1]) then
  redis.call('DECR', KEYS[1])
  return 0
end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
`)

// releaseScript DECRs and DELs the key at zero, so a fully-released tunnel leaves no key behind
// (and a post-expiry DECR that would create a fresh -1 key is immediately removed — never un-TTL'd).
var releaseScript = redis.NewScript(`
local c = redis.call('DECR', KEYS[1])
if c <= 0 then
  redis.call('DEL', KEYS[1])
end
return c
`)

// AcquireStream reserves one of `cap` GLOBAL concurrent-stream slots for tunnel name across replicas
// (reusing the conc:{name} counter). Returns false when the tunnel is at its cap. The safety TTL
// (l.streamTTL = 3 × --limit-conn-idle) is set on every acquire and refreshed by every traffic chunk,
// so a live stream's counter never expires while a crashed node's stale count self-heals.
func (l *Limiter) AcquireStream(ctx context.Context, name string, maxN int) (bool, error) {
	res, err := acquireScript.Run(ctx, l.rdb, []string{"conc:" + name}, maxN, l.streamTTL.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

// ReleaseStream frees a global stream slot for name (DECR floored at 0; the key is removed at zero).
func (l *Limiter) ReleaseStream(ctx context.Context, name string) error {
	return releaseScript.Run(ctx, l.rdb, []string{"conc:" + name}).Err()
}
