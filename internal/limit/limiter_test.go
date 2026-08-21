package limit

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newLimiter(t *testing.T, bw, day, week int64) *Limiter {
	t.Helper()
	rdb, _ := newTestRedis(t)
	return NewLimiter(rdb, bw, day, week, time.Hour)
}

// newChargeLimiter builds a Limiter for the unified Charge tests with a SETTABLE clock (mutate via the
// returned *time.Time so a test can roll the second or position mid-/near a day/week boundary) and
// explicit byte/packet + day/week caps.
func newChargeLimiter(t *testing.T, bwRate, pktCap, dayCap, weekCap int64) (*Limiter, *miniredis.Miniredis, *time.Time) {
	t.Helper()
	rdb, mr := newTestRedis(t)
	clk := time.Unix(1_700_000_000, 0)
	l := NewLimiter(rdb, bwRate, dayCap, weekCap, time.Hour, WithPacketCap(pktCap))
	l.SetClock(func() time.Time { return clk })
	return l, mr, &clk
}

// TestCharge_ByteWindowWaits: at the real 1mbit byte cap, legit ~4 KB reads are byte-capped at ~30
// reads/sec — reads 1..30 (≤122880 B) Proceed, read 31 (126976 B) trips → ChargeWait with a sub-second
// wait (the per-second window resets in ≤ 1 s ≤ maxPacingWait).
func TestCharge_ByteWindowWaits(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 125000, 0, 1<<40, 1<<40) // 1mbit; packet cap disabled; huge day/week
	for i := 1; i <= 30; i++ {
		action, _, _, err := l.Charge(ctx, "t", "in", 4096)
		if err != nil || action != ChargeProceed {
			t.Fatalf("read %d: action=%v err=%v, want Proceed", i, action, err)
		}
	}
	action, wait, _, err := l.Charge(ctx, "t", "in", 4096)
	if err != nil || action != ChargeWait || wait <= 0 || wait > time.Second {
		t.Fatalf("read 31: action=%v wait=%v err=%v, want Wait 0<wait≤1s", action, wait, err)
	}
}

// TestCharge_PacketWindowWaits: at the default --limit-packets (100), a 1-byte-read flood trips the
// PACKET window at read 101 (bytes stay far under the cap) → ChargeWait.
func TestCharge_PacketWindowWaits(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 1<<30, 100, 1<<40, 1<<40) // huge byte + day/week caps; only packets can trip
	for i := 1; i <= 100; i++ {
		action, _, _, err := l.Charge(ctx, "t", "in", 1)
		if err != nil || action != ChargeProceed {
			t.Fatalf("read %d: action=%v err=%v, want Proceed", i, action, err)
		}
	}
	action, wait, _, err := l.Charge(ctx, "t", "in", 1)
	if err != nil || action != ChargeWait || wait <= 0 {
		t.Fatalf("read 101: action=%v wait=%v err=%v, want Wait", action, wait, err)
	}
}

// TestCharge_DayCapKillsWhenResetFar: a day window over its cap whose reset is ≫ maxPacingWait (the
// clock sits mid-day) → ChargeKill with window "day".
func TestCharge_DayCapKillsWhenResetFar(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 1<<30, 0, 4, 1<<40) // 4-byte day cap; huge byte/week caps
	action, wait, win, err := l.Charge(ctx, "t", "in", 10)
	if err != nil || action != ChargeKill || win != "day" || wait != 0 {
		t.Fatalf("action=%v wait=%v win=%q err=%v, want Kill win=day wait=0", action, wait, win, err)
	}
}

// TestCharge_WeekCapKillsAndPrecedesDay: when BOTH the week and day windows are over (both reset far),
// the week kill takes precedence → ChargeKill with window "week".
func TestCharge_WeekCapKillsAndPrecedesDay(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 1<<30, 0, 4, 4) // both day + week caps tiny
	action, _, win, err := l.Charge(ctx, "t", "in", 10)
	if err != nil || action != ChargeKill || win != "week" {
		t.Fatalf("action=%v win=%q err=%v, want Kill win=week (week precedes day)", action, win, err)
	}
}

// TestCharge_DayCapWaitsNearBoundary: a day window over its cap but resetting within maxPacingWait (the
// clock sits 3 s before the UTC-day boundary) → ChargeWait, not Kill.
func TestCharge_DayCapWaitsNearBoundary(t *testing.T) {
	ctx := ctxT(t)
	l, _, clk := newChargeLimiter(t, 1<<30, 0, 4, 1<<40)
	sec := clk.Unix()
	dayEnd := (sec/86400 + 1) * 86400
	*clk = time.Unix(dayEnd-3, 0) // 3s before the day boundary → dayReset ≤ maxPacingWait
	action, wait, _, err := l.Charge(ctx, "t", "in", 10)
	if err != nil || action != ChargeWait || wait <= 0 || wait > maxPacingWait {
		t.Fatalf("action=%v wait=%v err=%v, want Wait 0<wait≤%s", action, wait, err, maxPacingWait)
	}
}

// TestCharge_PerDirectionIsolated: charging "in" past the day cap kills "in", but "out" still Proceeds —
// the day counters are per-direction.
func TestCharge_PerDirectionIsolated(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 1<<30, 0, 4, 1<<40) // 4-byte day cap; clock mid-day (reset far)
	if action, _, win, _ := l.Charge(ctx, "t", "in", 10); action != ChargeKill || win != "day" {
		t.Fatalf("in charge: action=%v win=%q, want Kill day", action, win)
	}
	if action, _, _, _ := l.Charge(ctx, "t", "out", 1); action != ChargeProceed {
		t.Fatalf("out charge: action=%v, want Proceed (in's bytes must not trip out's day counter)", action)
	}
}

// TestCharge_ExpireNXHealsMissingTTL: a traf: day key left WITHOUT a TTL (a simulated orphan bare INCR)
// gets one from the NEXT same-window Charge — the self-healing the plain-pipeline choice relies on.
func TestCharge_ExpireNXHealsMissingTTL(t *testing.T) {
	ctx := ctxT(t)
	l, mr, clk := newChargeLimiter(t, 1<<30, 0, 1<<40, 1<<40)
	_, _, dayKey, _ := chargeKeys("t", "in", clk.Unix())
	if err := l.rdb.Incr(ctx, dayKey).Err(); err != nil { // orphan: key exists with NO TTL (white-box)
		t.Fatal(err)
	}
	if ttl := mr.TTL(dayKey); ttl != 0 {
		t.Fatalf("precondition: orphan key must have no TTL, got %v", ttl)
	}
	if _, _, _, err := l.Charge(ctx, "t", "in", 1); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(dayKey); ttl <= 0 {
		t.Fatalf("EXPIRE NX must heal the missing TTL, got %v", ttl)
	}
}

// TestCharge_FailOpenOnValkeyError: a closed Valkey fails open (ChargeProceed) with the error.
func TestCharge_FailOpenOnValkeyError(t *testing.T) {
	ctx := ctxT(t)
	l, mr, _ := newChargeLimiter(t, 125000, 100, 1<<40, 1<<40)
	mr.Close() // every Valkey call now errors
	action, wait, _, err := l.Charge(ctx, "t", "in", 4096)
	if err == nil {
		t.Fatal("a closed Valkey must return an error")
	}
	if action != ChargeProceed || wait != 0 {
		t.Fatalf("fail-open: action=%v wait=%v, want Proceed wait=0", action, wait)
	}
}

func TestIssuanceRecordCountsSuccesses(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1, 1, 1)
	for range 3 {
		if err := l.IssuanceRecord(ctx, "t"); err != nil {
			t.Fatal(err)
		}
	}
	// Three committed successes fill cap 3: a fresh Begin (no in-flight order) is refused.
	if ok, _, _ := l.IssuanceBegin(ctx, "t", 3); ok {
		t.Error("after 3 committed successes, cap 3 must deny a new begin")
	}
	// A higher cap still admits with 3 committed.
	if ok, _, err := l.IssuanceBegin(ctx, "t", 4); err != nil || !ok {
		t.Fatalf("cap 4 must admit with 3 committed: ok=%v err=%v", ok, err)
	}
}

func TestCACooldownAndFailures(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1, 1, 1)
	if d, _ := l.CACooldown(ctx, "letsencrypt"); d != 0 {
		t.Errorf("no cooldown expected, got %s", d)
	}
	if err := l.SetCACooldown(ctx, "letsencrypt", time.Hour); err != nil {
		t.Fatal(err)
	}
	if d, _ := l.CACooldown(ctx, "letsencrypt"); d <= 0 {
		t.Error("cooldown should be readable")
	}
	c1, _ := l.BumpCAFailures(ctx, "gts", 6*time.Hour)
	c2, _ := l.BumpCAFailures(ctx, "gts", 6*time.Hour)
	if c1 != 1 || c2 != 2 {
		t.Errorf("failure streak = %d,%d", c1, c2)
	}
	_ = l.ResetCAFailures(ctx, "gts")
	c3, _ := l.BumpCAFailures(ctx, "gts", 6*time.Hour)
	if c3 != 1 {
		t.Errorf("after reset streak = %d, want 1", c3)
	}
}

func TestAcquireReleaseStreamGlobalCap(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1, 1, 1)
	for range 4 {
		ok, err := l.AcquireStream(ctx, "t", "conn1", 4)
		if err != nil || !ok {
			t.Fatalf("acquire: ok=%v err=%v", ok, err)
		}
	}
	if ok, _ := l.AcquireStream(ctx, "t", "conn1", 4); ok {
		t.Error("5th acquire past cap 4 should fail")
	}
	if err := l.ReleaseStream(ctx, "t", "conn1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := l.AcquireStream(ctx, "t", "conn1", 4); !ok {
		t.Error("after release, a slot should be free")
	}
}

// TestTrafficExhausted_PerDirection: the admission gate reports over when EITHER direction's day/week
// window is at/over its cap, and is read-only (no mutation of the seeded counters).
func TestTrafficExhausted_PerDirection(t *testing.T) {
	ctx := ctxT(t)
	l, _, clk := newChargeLimiter(t, 1, 0, 10, 20) // day cap 10, week cap 20 (bwRate/pktCap unused here)

	day, week, err := l.TrafficExhausted(ctx, "t")
	if err != nil || day || week {
		t.Fatalf("fresh tunnel must not be exhausted: %v %v %v", day, week, err)
	}
	// Seed ONLY the "out" day window at its cap; the "in" direction stays empty.
	_, _, outDay, _ := chargeKeys("t", "out", clk.Unix())
	if err := l.rdb.Set(ctx, outDay, "10", 0).Err(); err != nil {
		t.Fatal(err)
	}
	day, week, err = l.TrafficExhausted(ctx, "t")
	if err != nil || !day || week {
		t.Fatalf("at-cap out-day window must report exhausted (day=%v week=%v err=%v)", day, week, err)
	}
	// Seed the "in" week window at its cap → week over via the other direction.
	_, _, _, inWeek := chargeKeys("t", "in", clk.Unix())
	if err := l.rdb.Set(ctx, inWeek, "20", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if _, week, _ := l.TrafficExhausted(ctx, "t"); !week {
		t.Fatal("at-cap in-week window must report week exhausted (either direction)")
	}
	// Read-only: the seeded counter is unchanged after the checks.
	if got, _ := l.rdb.Get(ctx, outDay).Int64(); got != 10 {
		t.Fatalf("TrafficExhausted must be read-only, out-day counter moved to %d", got)
	}
}

// TestCharge_RefreshesConcTTLOnlyIfExists: the Charge pipeline's PEXPIRE conc:{name} refreshes an
// EXISTING conc TTL to streamTTL but is a NO-OP on a missing key (a torn-down counter is never
// resurrected).
func TestCharge_RefreshesConcTTLOnlyIfExists(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 1<<30, 1<<40, 1<<40, 45*time.Minute)
	const name = "t"

	// No conc key yet: Charge must NOT create it (PEXPIRE on a missing key is a no-op).
	if _, _, _, err := l.Charge(ctx, name, "in", 100); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("conc:" + name) {
		t.Fatal("Charge must not create the conc counter")
	}

	// With an existing conc key whose TTL has been shrunk, Charge refreshes it to streamTTL.
	if ok, err := l.AcquireStream(ctx, name, "conn1", 4); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	mr.SetTTL("conc:"+name, time.Minute)
	if _, _, _, err := l.Charge(ctx, name, "in", 100); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL("conc:" + name); ttl <= time.Minute {
		t.Fatalf("conc TTL must be refreshed to streamTTL, got %s", ttl)
	}
}

// TestAcquireStream_UsesDerivedTTL: the conc counter's safety TTL is the configured streamTTL.
func TestAcquireStream_UsesDerivedTTL(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	const ttl = 45 * time.Minute
	l := NewLimiter(rdb, 0, 0, 0, ttl)
	if ok, err := l.AcquireStream(ctx, "t", "conn1", 4); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if got := mr.TTL("conc:t"); got != ttl {
		t.Fatalf("conc TTL = %s, want the configured streamTTL %s", got, ttl)
	}
}
