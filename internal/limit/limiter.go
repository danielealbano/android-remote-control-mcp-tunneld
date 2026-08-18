package limit

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter holds the E2E control-plane rate/quota primitives (Plan 3), added alongside the Plan-1 free
// functions (Allow/Acquire). It carries the Valkey client, the per-tunnel/per-direction bandwidth rate,
// and the day/week traffic caps, with an injectable clock for tests. Every key's TTL is set in the SAME
// Lua script as its mutation (or SET EX for the cooldown/budget windows).
type Limiter struct {
	rdb     redis.UniversalClient
	bwRate  int64 // bytes/sec per tunnel per direction
	dayCap  int64
	weekCap int64
	now     func() time.Time
}

// NewLimiter builds the Limiter. bwRate is --limit-bandwidth in bytes/sec; dayCap/weekCap are the
// combined-direction traffic caps in bytes.
func NewLimiter(rdb redis.UniversalClient, bwRate, dayCap, weekCap int64) *Limiter {
	return &Limiter{rdb: rdb, bwRate: bwRate, dayCap: dayCap, weekCap: weekCap, now: time.Now}
}

// SetClock overrides the clock (tests only).
func (l *Limiter) SetClock(f func() time.Time) { l.now = f }

// claimBandwidthScript is a token bucket keyed bw:{name}:{dir} holding {tokens, last_ns}. It refills at
// `rate` bytes/sec up to a one-second burst, grants min(want, tokens), and TTLs the key. now_ns is
// passed from Go (Lua clocks are non-deterministic).
var claimBandwidthScript = redis.NewScript(`
local rate = tonumber(ARGV[1])
local want = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local burst = rate
local vals = redis.call('HMGET', KEYS[1], 'tokens', 'last')
local tokens = tonumber(vals[1])
local last = tonumber(vals[2])
if tokens == nil then
  tokens = burst
  last = now
end
local elapsed = (now - last) / 1e9
if elapsed > 0 then
  tokens = math.min(burst, tokens + elapsed * rate)
end
local granted = math.min(want, tokens)
if granted < 0 then granted = 0 end
tokens = tokens - granted
redis.call('HSET', KEYS[1], 'tokens', tokens, 'last', now)
redis.call('PEXPIRE', KEYS[1], ttl)
return math.floor(granted)
`)

// ClaimBandwidth claims up to want bytes from the per-tunnel, per-direction global token bucket,
// returning how many bytes were granted (the pacer draws ~1 MB at a time, so this is ~one Valkey op
// per megabyte, never per chunk).
func (l *Limiter) ClaimBandwidth(ctx context.Context, name, dir string, want int64) (int64, error) {
	key := "bw:" + name + ":" + dir
	// TTL: two seconds of idle refill is enough to discard a stale bucket; keep it generous so an
	// active but slow tunnel never loses its bucket.
	ttl := (10 * time.Second).Milliseconds()
	granted, err := claimBandwidthScript.Run(ctx, l.rdb, []string{key},
		l.bwRate, want, l.now().UnixNano(), ttl).Int64()
	if err != nil {
		return 0, err
	}
	return granted, nil
}

// claimTrafficScript INCRBYs both the day and week counters and reports per-window exhaustion against
// the caps. The TTL — set in-script on the FIRST write — IS the window: each counter measures a 24h/7d
// span anchored at the first byte after the previous window expired (the same TTL-anchored-window
// semantics as the issuance and enroll counters), never a calendar-aligned bucket.
var claimTrafficScript = redis.NewScript(`
local n = tonumber(ARGV[1])
local dayCap = tonumber(ARGV[2])
local weekCap = tonumber(ARGV[3])
local dayTTL = tonumber(ARGV[4])
local weekTTL = tonumber(ARGV[5])
local d = redis.call('INCRBY', KEYS[1], n)
if d == n then redis.call('PEXPIRE', KEYS[1], dayTTL) end
local w = redis.call('INCRBY', KEYS[2], n)
if w == n then redis.call('PEXPIRE', KEYS[2], weekTTL) end
local dayOK = 1
local weekOK = 1
if d > dayCap then dayOK = 0 end
if w > weekCap then weekOK = 0 end
return {dayOK, weekOK}
`)

func trafficKeys(name string) (dayKey, weekKey string) {
	return "traf:" + name + ":day", "traf:" + name + ":week"
}

// ClaimTraffic adds n bytes to the combined day+week counters (both directions) and reports whether
// each window is still within its cap AFTER the add.
func (l *Limiter) ClaimTraffic(ctx context.Context, name string, n int64) (dayOK, weekOK bool, err error) {
	dayKey, weekKey := trafficKeys(name)
	res, err := claimTrafficScript.Run(ctx, l.rdb, []string{dayKey, weekKey},
		n, l.dayCap, l.weekCap, (24 * time.Hour).Milliseconds(), (7 * 24 * time.Hour).Milliseconds()).Slice()
	if err != nil {
		return false, false, err
	}
	d, _ := res[0].(int64)
	w, _ := res[1].(int64)
	return d == 1, w == 1, nil
}

// TrafficExhausted reports whether either traffic window is already AT or over its cap, WITHOUT
// mutating the counters — the admission-time quota gate: a new stream is refused when no further byte
// could be accepted.
func (l *Limiter) TrafficExhausted(ctx context.Context, name string) (dayOver, weekOver bool, err error) {
	dayKey, weekKey := trafficKeys(name)
	vals, err := l.rdb.MGet(ctx, dayKey, weekKey).Result()
	if err != nil {
		return false, false, err
	}
	parse := func(v any) int64 {
		s, ok := v.(string)
		if !ok {
			return 0
		}
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil {
			return 0
		}
		return n
	}
	return parse(vals[0]) >= l.dayCap, parse(vals[1]) >= l.weekCap, nil
}
