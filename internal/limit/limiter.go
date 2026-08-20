package limit

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter holds the control-plane rate/quota primitives. It carries the Valkey client, the
// per-tunnel/per-direction per-second byte cap (bwRate) and packet cap (pktCap), and the day/week
// traffic caps, with an injectable clock for tests. Each key gets a TTL alongside its mutation — set
// atomically in the same Lua script (or SET EX for the cooldown windows), or via a pipelined EXPIRE NX
// immediately after the INCR for the bw:/pkt: per-second bandwidth windows (self-healing on the next
// same-second write; see ChargeBandwidth).
type Limiter struct {
	rdb       redis.UniversalClient
	bwRate    int64 // per-second byte cap per tunnel per direction
	pktCap    int64 // per-second read (packet) cap per tunnel per direction; 0 = disabled
	dayCap    int64
	weekCap   int64
	streamTTL time.Duration // conc:{name} safety TTL (= 3 × --limit-conn-idle), refreshed per chunk
	now       func() time.Time
	logger    *slog.Logger
}

// Option configures a Limiter (functional-options pattern).
type Option func(*Limiter)

// WithLogger sets the Limiter's logger (used for the issuance-slot heartbeat failure surface).
func WithLogger(l *slog.Logger) Option { return func(lm *Limiter) { lm.logger = l } }

// WithPacketCap sets the per-tunnel/per-direction reads-per-second cap (0 = disabled, the default).
func WithPacketCap(n int64) Option { return func(l *Limiter) { l.pktCap = n } }

// NewLimiter builds the Limiter. bwRate is --limit-bandwidth in bytes/sec; dayCap/weekCap are the
// combined-direction traffic caps in bytes; streamTTL is the global stream-counter safety TTL,
// refreshed by every traffic chunk (derived = 3 × --limit-conn-idle).
func NewLimiter(rdb redis.UniversalClient, bwRate, dayCap, weekCap int64, streamTTL time.Duration, opts ...Option) *Limiter {
	l := &Limiter{rdb: rdb, bwRate: bwRate, dayCap: dayCap, weekCap: weekCap, streamTTL: streamTTL,
		now: time.Now, logger: slog.New(slog.DiscardHandler)}
	for _, o := range opts {
		o(l)
	}
	return l
}

// SetClock overrides the clock (tests only).
func (l *Limiter) SetClock(f func() time.Time) { l.now = f }

// bwWindowTTL outlives a 1-second window (set once via EXPIRE NX on the window's first write) so a write
// late in the window never expires the counter mid-window; the next second uses a fresh key.
const bwWindowTTL = 2 * time.Second

func bwWindowKeys(name, dir string, sec int64) (byteKey, pktKey string) {
	s := strconv.FormatInt(sec, 10)
	return "bw:" + name + ":" + dir + ":" + s, "pkt:" + name + ":" + dir + ":" + s
}

// ChargeBandwidth records nr bytes and one read against the current 1-second byte + packet windows for
// (name, dir) in a single pipelined round-trip (INCRBY + INCR + EXPIRE…NX ×2 — no Lua), and reports
// whether either per-second cap is now exceeded plus the time remaining in the current second (the caller
// waits that out before the next read). A plain Pipeline (not TxPipeline) is deliberate: these are
// per-second transient counters and EXPIRE NX self-heals a skipped TTL on the next same-second read, so
// strict atomicity is unwarranted here. The packet cap is skipped when pktCap == 0. A Valkey error returns
// over=false (fail-open: pacing never hard-depends on the control plane).
func (l *Limiter) ChargeBandwidth(ctx context.Context, name, dir string, nr int64) (over bool, retryAfter time.Duration, err error) {
	now := l.now()
	sec := now.Unix()
	byteKey, pktKey := bwWindowKeys(name, dir, sec)
	pipe := l.rdb.Pipeline() // one round-trip; EXPIRE NX sets the TTL, self-healing on the next same-second read
	bCmd := pipe.IncrBy(ctx, byteKey, nr)
	pCmd := pipe.Incr(ctx, pktKey)
	pipe.ExpireNX(ctx, byteKey, bwWindowTTL)
	pipe.ExpireNX(ctx, pktKey, bwWindowTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}
	over = bCmd.Val() > l.bwRate || (l.pktCap > 0 && pCmd.Val() > l.pktCap)
	if over {
		retryAfter = time.Unix(sec+1, 0).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
	}
	return over, retryAfter, nil
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
-- Refresh the global stream counter's TTL from the active data path. PEXPIRE on a missing key is a
-- no-op (returns 0, never creates the key), so a torn-down tunnel's counter is never resurrected.
redis.call('PEXPIRE', KEYS[3], ARGV[6])
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
	res, err := claimTrafficScript.Run(ctx, l.rdb, []string{dayKey, weekKey, "conc:" + name},
		n, l.dayCap, l.weekCap, (24 * time.Hour).Milliseconds(), (7 * 24 * time.Hour).Milliseconds(),
		l.streamTTL.Milliseconds()).Slice()
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
