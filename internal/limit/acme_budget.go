package limit

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// The ACME rate-limit protection is REACTIVE (no proactive order counter): a CA answering rate-limited
// gets a per-CA cooldown in Valkey honoring its Retry-After; other repeated failures apply exponential
// per-CA backoff; the spillover skips a cooling CA. SEPARATELY, a weekly LE new-order budget is
// reserved-then-refunded (a failed order never burns budget).

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

// consumeLEOrderScript reserves one LE weekly-budget slot iff the current count is below budget (the
// INCR + first-set TTL are atomic). Returns 1 on reserve, 0 when the budget is exhausted.
var consumeLEOrderScript = redis.NewScript(`
local budget = tonumber(ARGV[1])
local c = redis.call('GET', KEYS[1])
if c and tonumber(c) >= budget then
  return 0
end
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 1
`)

func leWeekKey(now time.Time) string {
	weekStart := now.UTC().Truncate(7 * 24 * time.Hour)
	return "acme-le-week:" + strconv.FormatInt(weekStart.Unix(), 10)
}

// ConsumeLEOrder reserves one LE new-order slot for the current rolling week iff below budget (called
// BEFORE an LE new-order attempt). Reserve-then-refund: ReleaseLEOrder undoes it if the attempt fails.
func (l *Limiter) ConsumeLEOrder(ctx context.Context, budget int) (bool, error) {
	key := leWeekKey(l.now())
	ok, err := consumeLEOrderScript.Run(ctx, l.rdb, []string{key}, budget, (7 * 24 * time.Hour).Milliseconds()).Int()
	if err != nil {
		return false, err
	}
	return ok == 1, nil
}

// releaseLEOrderScript DECRs the current week's counter, floored at 0 (never negative).
var releaseLEOrderScript = redis.NewScript(`
local c = redis.call('GET', KEYS[1])
if c and tonumber(c) > 0 then
  redis.call('DECR', KEYS[1])
end
return 1
`)

// ReleaseLEOrder refunds a previously reserved LE order slot (the attempt failed).
func (l *Limiter) ReleaseLEOrder(ctx context.Context) error {
	return releaseLEOrderScript.Run(ctx, l.rdb, []string{leWeekKey(l.now())}).Err()
}
