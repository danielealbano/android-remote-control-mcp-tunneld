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
// immediately after the INCR for the bw:/pkt: per-second and traf: day/week windows (self-healing on the
// next same-window write; see Charge).
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
// per-direction traffic caps in bytes; streamTTL is the global stream-counter safety TTL,
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

// ChargeAction is the caller's instruction after charging a read against every per-window counter.
type ChargeAction int

const (
	ChargeProceed ChargeAction = iota // under all caps (or a fail-open Valkey error) → forward now
	ChargeWait                        // over a cap whose window resets within maxPacingWait → wait, then forward
	ChargeKill                        // over a cap whose window resets beyond maxPacingWait → end the stream
)

const (
	bwWindowTTL   = 2 * time.Second            // per-second byte/packet windows (2× the 1s window)
	trafDayTTL    = 25 * time.Hour             // 24h window + 1h margin so a write never expires the counter mid-window
	trafWeekTTL   = 7*24*time.Hour + time.Hour // 7d window + 1h margin (a small fixed margin, NOT 2× — the key is dead weight after its window)
	maxPacingWait = 5 * time.Second            // over a cap resetting within this → wait; else kill
)

// chargeKeys builds the four per-window keys for (name, dir) at unix second `sec`. Day/week are
// clock-aligned: unix_day = sec/86400 (UTC-midnight days), unix_week = unix_day/7 (epoch-aligned 7-day
// blocks) — so the window reset is computed from the clock, no PTTL read, and old windows roll off.
func chargeKeys(name, dir string, sec int64) (bwKey, pktKey, dayKey, weekKey string) {
	s := strconv.FormatInt(sec, 10)
	d := strconv.FormatInt(sec/86400, 10)
	w := strconv.FormatInt(sec/86400/7, 10)
	base := name + ":" + dir
	return "bw:" + base + ":" + s, "pkt:" + base + ":" + s,
		"traf:" + base + ":day:" + d, "traf:" + base + ":week:" + w
}

// Charge records nr bytes + one read against the per-second byte/packet windows AND the per-day/week
// traffic windows for (name, dir) in a single plain pipelined round-trip (INCRBY/INCR + EXPIRE…NX — no
// Lua, no TxPipeline; EXPIRE NX self-heals a skipped TTL on the next same-window write), refreshes the
// conc:{name} TTL, and returns the enforcement action. Kill takes precedence over Wait (an exhausted far
// window can't be waited out); the returned window ("day"/"week") labels a Kill for the metric. The
// packet cap is skipped when pktCap==0. A Valkey error returns ChargeProceed (fail-open).
func (l *Limiter) Charge(ctx context.Context, name, dir string, nr int64) (ChargeAction, time.Duration, string, error) {
	now := l.now()
	sec := now.Unix()
	bwKey, pktKey, dayKey, weekKey := chargeKeys(name, dir, sec)
	pipe := l.rdb.Pipeline() // plain pipeline, one round-trip; EXPIRE NX self-heals TTLs on the next same-window write
	bCmd := pipe.IncrBy(ctx, bwKey, nr)
	pCmd := pipe.Incr(ctx, pktKey)
	dCmd := pipe.IncrBy(ctx, dayKey, nr)
	wCmd := pipe.IncrBy(ctx, weekKey, nr)
	pipe.ExpireNX(ctx, bwKey, bwWindowTTL)
	pipe.ExpireNX(ctx, pktKey, bwWindowTTL)
	pipe.ExpireNX(ctx, dayKey, trafDayTTL)
	pipe.ExpireNX(ctx, weekKey, trafWeekTTL)
	pipe.PExpire(ctx, "conc:"+name, l.streamTTL) // refresh the live-stream counter TTL (no-op on a missing key)
	if _, err := pipe.Exec(ctx); err != nil {
		return ChargeProceed, 0, "", err // fail-open
	}

	secReset := time.Unix(sec+1, 0).Sub(now)
	dayReset := time.Unix((sec/86400+1)*86400, 0).Sub(now)
	weekReset := time.Unix((sec/86400/7+1)*7*86400, 0).Sub(now)

	overSec := bCmd.Val() > l.bwRate || (l.pktCap > 0 && pCmd.Val() > l.pktCap)
	dayOver := dCmd.Val() > l.dayCap
	weekOver := wCmd.Val() > l.weekCap

	// Kill precedence: a volume window over its cap that resets beyond maxPacingWait cannot be waited out.
	if weekOver && weekReset > maxPacingWait {
		return ChargeKill, 0, "week", nil
	}
	if dayOver && dayReset > maxPacingWait {
		return ChargeKill, 0, "day", nil
	}
	// Otherwise wait for the furthest over-window that resets within maxPacingWait.
	wait := time.Duration(0)
	if overSec && secReset > wait {
		wait = secReset
	}
	if dayOver && dayReset > wait {
		wait = dayReset
	}
	if weekOver && weekReset > wait {
		wait = weekReset
	}
	if wait > 0 {
		return ChargeWait, wait, "", nil
	}
	return ChargeProceed, 0, "", nil
}

// atoiCap parses a Valkey MGET result element (string | nil) to an int64, treating a missing/unparseable
// value as 0 — the shared parse helper for TrafficExhausted's four per-direction lookups.
func atoiCap(v any) int64 {
	s, ok := v.(string)
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// TrafficExhausted reports whether the tunnel's current day/week window is at/over its cap in EITHER
// direction — the admission-time gate (no mutation): a new stream is refused when no further byte could
// be accepted. Clock-aligned to the same windows Charge writes.
func (l *Limiter) TrafficExhausted(ctx context.Context, name string) (dayOver, weekOver bool, err error) {
	sec := l.now().Unix()
	d := strconv.FormatInt(sec/86400, 10)
	w := strconv.FormatInt(sec/86400/7, 10)
	keys := []string{
		"traf:" + name + ":in:day:" + d, "traf:" + name + ":out:day:" + d,
		"traf:" + name + ":in:week:" + w, "traf:" + name + ":out:week:" + w,
	}
	vals, err := l.rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return false, false, err
	}
	dayOver = atoiCap(vals[0]) >= l.dayCap || atoiCap(vals[1]) >= l.dayCap
	weekOver = atoiCap(vals[2]) >= l.weekCap || atoiCap(vals[3]) >= l.weekCap
	return dayOver, weekOver, nil
}

// ResetStreams clears the live concurrent-stream counter for name (conc:{name}) — called when the phone
// (re)binds, because a fresh phone connection means all prior streams are dead. It NEVER touches the
// identity-scoped traf: day/week quotas (those must persist across reconnects).
func (l *Limiter) ResetStreams(ctx context.Context, name string) error {
	return l.rdb.Del(ctx, "conc:"+name).Err()
}
