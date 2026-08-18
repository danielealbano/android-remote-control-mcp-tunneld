package limit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// The issuance counter is consumed ONLY on a SUCCESSFUL public-cert issuance (via IssuanceRecord),
// never at the pre-issuance gate — so the 3/tunnel/week cap counts successes only. IssuanceAllowed is a
// READ-ONLY check (no mutation).

func issuanceKey(name string) string { return "iss:" + name }

// IssuanceAllowed reports whether the rolling-7d per-tunnel issuance counter is below cap WITHOUT
// mutating it.
func (l *Limiter) IssuanceAllowed(ctx context.Context, name string, maxN int) (bool, error) {
	v, err := l.rdb.Get(ctx, issuanceKey(name)).Int()
	if err == redis.Nil {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return v < maxN, nil
}

// recordIssuanceScript INCRs the counter and sets a 7d TTL on the first increment (a sliding 7d window
// anchored at the first issuance in it).
var recordIssuanceScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`)

// IssuanceRecord atomically increments the rolling-7d per-tunnel issuance counter (called ONLY after a
// public cert is successfully issued).
func (l *Limiter) IssuanceRecord(ctx context.Context, name string) error {
	return recordIssuanceScript.Run(ctx, l.rdb, []string{issuanceKey(name)}, (7 * 24 * time.Hour).Milliseconds()).Err()
}
