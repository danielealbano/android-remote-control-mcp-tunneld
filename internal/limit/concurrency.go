package limit

import (
	"context"
	"sync"
	"time"

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

// Acquire reserves one of max in-flight slots for tunnel name. ttl is the safety expiry
// (2×request-timeout at the call site) so a crashed holder's slot self-heals. The returned release
// DECRs exactly once (idempotent via sync.Once); it MUST always be deferred.
func Acquire(ctx context.Context, rdb redis.UniversalClient, name string, maxInFlight int, ttl time.Duration) (release func(), ok bool, err error) {
	key := "conc:" + name
	res, err := acquireScript.Run(ctx, rdb, []string{key}, maxInFlight, ttl.Milliseconds()).Int64()
	if err != nil {
		return nil, false, err
	}
	if res == 0 {
		return nil, false, nil
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			// Background ctx: release must succeed even after the request ctx is cancelled.
			_ = releaseScript.Run(context.Background(), rdb, []string{key}).Err()
		})
	}
	return release, true, nil
}

// streamCapTTL bounds leakage of the global per-tunnel stream counter from a crashed node: streams die
// with their bridges, but a stale count self-heals after this TTL. It is refreshed on every acquire and
// is generous enough to outlast any realistic stream (the connection policy caps idle streams at 120s;
// there is no hard stream-lifetime cap, but an hour is far beyond any real MCP request/OAuth flow).
const streamCapTTL = time.Hour

// AcquireStream reserves one of `cap` GLOBAL concurrent-stream slots for tunnel name across replicas
// (reusing the conc:{name} counter). Returns false when the tunnel is at its cap. The TTL is refreshed
// on every acquire (the Plan-1 Acquire release-func API is kept for legacy; this is the E2E form).
func (l *Limiter) AcquireStream(ctx context.Context, name string, maxN int) (bool, error) {
	res, err := acquireScript.Run(ctx, l.rdb, []string{"conc:" + name}, maxN, streamCapTTL.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

// ReleaseStream frees a global stream slot for name (DECR floored at 0; the key is removed at zero).
func (l *Limiter) ReleaseStream(ctx context.Context, name string) error {
	return releaseScript.Run(ctx, l.rdb, []string{"conc:" + name}).Err()
}
