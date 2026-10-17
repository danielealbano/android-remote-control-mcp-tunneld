package limit

import (
	"bytes"
	"log/slog"
	"strings"
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
		action, _, _, err := l.Charge(ctx, "t", "m1", "in", 4096)
		if err != nil || action != ChargeProceed {
			t.Fatalf("read %d: action=%v err=%v, want Proceed", i, action, err)
		}
	}
	action, wait, _, err := l.Charge(ctx, "t", "m1", "in", 4096)
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
		action, _, _, err := l.Charge(ctx, "t", "m1", "in", 1)
		if err != nil || action != ChargeProceed {
			t.Fatalf("read %d: action=%v err=%v, want Proceed", i, action, err)
		}
	}
	action, wait, _, err := l.Charge(ctx, "t", "m1", "in", 1)
	if err != nil || action != ChargeWait || wait <= 0 {
		t.Fatalf("read 101: action=%v wait=%v err=%v, want Wait", action, wait, err)
	}
}

// TestCharge_DayCapKillsWhenResetFar: a day window over its cap whose reset is ≫ maxPacingWait (the
// clock sits mid-day) → ChargeKill with window "day".
func TestCharge_DayCapKillsWhenResetFar(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 1<<30, 0, 4, 1<<40) // 4-byte day cap; huge byte/week caps
	action, wait, win, err := l.Charge(ctx, "t", "m1", "in", 10)
	if err != nil || action != ChargeKill || win != "day" || wait != 0 {
		t.Fatalf("action=%v wait=%v win=%q err=%v, want Kill win=day wait=0", action, wait, win, err)
	}
}

// TestCharge_WeekCapKillsAndPrecedesDay: when BOTH the week and day windows are over (both reset far),
// the week kill takes precedence → ChargeKill with window "week".
func TestCharge_WeekCapKillsAndPrecedesDay(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 1<<30, 0, 4, 4) // both day + week caps tiny
	action, _, win, err := l.Charge(ctx, "t", "m1", "in", 10)
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
	action, wait, _, err := l.Charge(ctx, "t", "m1", "in", 10)
	if err != nil || action != ChargeWait || wait <= 0 || wait > maxPacingWait {
		t.Fatalf("action=%v wait=%v err=%v, want Wait 0<wait≤%s", action, wait, err, maxPacingWait)
	}
}

// TestCharge_PerDirectionIsolated: charging "in" past the day cap kills "in", but "out" still Proceeds —
// the day counters are per-direction.
func TestCharge_PerDirectionIsolated(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newChargeLimiter(t, 1<<30, 0, 4, 1<<40) // 4-byte day cap; clock mid-day (reset far)
	if action, _, win, err := l.Charge(ctx, "t", "m1", "in", 10); err != nil {
		t.Fatal(err)
	} else if action != ChargeKill || win != "day" {
		t.Fatalf("in charge: action=%v win=%q, want Kill day", action, win)
	}
	if action, _, _, err := l.Charge(ctx, "t", "m1", "out", 1); err != nil {
		t.Fatal(err)
	} else if action != ChargeProceed {
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
	if _, _, _, err := l.Charge(ctx, "t", "m1", "in", 1); err != nil {
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
	action, wait, _, err := l.Charge(ctx, "t", "m1", "in", 4096)
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
	if ok, _, err := l.IssuanceBegin(ctx, "t", 3); err != nil {
		t.Fatal(err)
	} else if ok {
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
	if d, err := l.CACooldown(ctx, "letsencrypt"); err != nil {
		t.Fatal(err)
	} else if d != 0 {
		t.Errorf("no cooldown expected, got %s", d)
	}
	if err := l.SetCACooldown(ctx, "letsencrypt", time.Hour); err != nil {
		t.Fatal(err)
	}
	if d, err := l.CACooldown(ctx, "letsencrypt"); err != nil {
		t.Fatal(err)
	} else if d <= 0 {
		t.Error("cooldown should be readable")
	}
	c1, err := l.BumpCAFailures(ctx, "gts", 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := l.BumpCAFailures(ctx, "gts", 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != 1 || c2 != 2 {
		t.Errorf("failure streak = %d,%d", c1, c2)
	}
	if err := l.ResetCAFailures(ctx, "gts"); err != nil {
		t.Fatal(err)
	}
	c3, err := l.BumpCAFailures(ctx, "gts", 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if c3 != 1 {
		t.Errorf("after reset streak = %d, want 1", c3)
	}
}

func TestCAWaitState_ReadsTheWaitUntilAndThe429Mark(t *testing.T) {
	t.Parallel()
	ctx := ctxT(t)
	rdb, mr := newTestRedis(t)
	l := NewLimiter(rdb, 1, 1, 1, time.Hour)
	if cool, mark, err := l.CAWaitState(ctx, "gts-1"); err != nil || cool != 0 || mark != "" {
		t.Fatalf("CAWaitState = %s, %q, %v; want no wait and no mark", cool, mark, err)
	}
	if err := l.SetCACooldown(ctx, "gts-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := l.MarkCALimited(ctx, "gts-1", 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	cool, first, err := l.CAWaitState(ctx, "gts-1")
	if err != nil || cool != time.Minute || first == "" {
		t.Fatalf("CAWaitState = %s, %q, %v; want the 1 m wait and a mark", cool, first, err)
	}
	if ttl := mr.TTL(limitedKey("gts-1")); ttl != 3*time.Minute {
		t.Fatalf("429 mark TTL = %s, want 3 m", ttl)
	}
	if err := l.MarkCALimited(ctx, "gts-1", 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, second, err := l.CAWaitState(ctx, "gts-1"); err != nil || second == "" || second == first {
		t.Fatalf("a second 429 must leave a new mark: first %q, second %q (%v)", first, second, err)
	}
	if _, mark, err := l.CAWaitState(ctx, "gts-2"); err != nil || mark != "" {
		t.Fatalf("another account's mark = %q (%v), want none", mark, err)
	}
	if err := l.MarkCALimited(ctx, "gts-1", 0); err == nil {
		t.Fatal("a mark without a TTL must be refused")
	}
	mr.Close()
	if _, _, err := l.CAWaitState(ctx, "gts-1"); err == nil {
		t.Fatal("a failed read must return an error")
	}
	if err := l.MarkCALimited(ctx, "gts-1", time.Minute); err == nil {
		t.Fatal("a failed write must return an error")
	}
}

func TestAcquireReleaseStreamGlobalCap(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1, 1, 1)
	for _, m := range []string{"a", "b", "c", "d"} {
		ok, err := l.AcquireStream(ctx, "t", m, 4)
		if err != nil || !ok {
			t.Fatalf("acquire %s: ok=%v err=%v", m, ok, err)
		}
	}
	if ok, err := l.AcquireStream(ctx, "t", "e", 4); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Error("a 5th distinct member past cap 4 should fail")
	}
	if err := l.ReleaseStream(ctx, "t", "a"); err != nil {
		t.Fatal(err)
	}
	if ok, err := l.AcquireStream(ctx, "t", "f", 4); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Error("after release, a slot should be free for a new member")
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
	if _, week, err := l.TrafficExhausted(ctx, "t"); err != nil {
		t.Fatal(err)
	} else if !week {
		t.Fatal("at-cap in-week window must report week exhausted (either direction)")
	}
	// Read-only: the seeded counter is unchanged after the checks.
	if got, err := l.rdb.Get(ctx, outDay).Int64(); err != nil {
		t.Fatal(err)
	} else if got != 10 {
		t.Fatalf("TrafficExhausted must be read-only, out-day counter moved to %d", got)
	}
}

func TestCharge_RefreshesOnlyExistingMember(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	clk := time.Unix(1_700_000_000, 0)
	const ttl = 45 * time.Minute
	l := NewLimiter(rdb, 1<<30, 1<<40, 1<<40, ttl)
	l.SetClock(func() time.Time { return clk })
	const name = "t"

	if _, _, _, err := l.Charge(ctx, name, "m1", "in", 100); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("conc:" + name) {
		t.Fatal("Charge must not create the stream set")
	}

	for _, m := range []string{"m1", "m2"} {
		if ok, err := l.AcquireStream(ctx, name, m, 4); err != nil || !ok {
			t.Fatalf("acquire %s: ok=%v err=%v", m, ok, err)
		}
	}
	if err := l.ReleaseStream(ctx, name, "m2"); err != nil {
		t.Fatal(err)
	}
	mr.SetTTL("conc:"+name, time.Minute)
	clk = clk.Add(10 * time.Second)
	if _, _, _, err := l.Charge(ctx, name, "m1", "in", 100); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := l.Charge(ctx, name, "m2", "in", 100); err != nil {
		t.Fatal(err)
	}
	if got := mr.TTL("conc:" + name); got != ttl {
		t.Fatalf("set TTL = %s, want refreshed to streamTTL %s", got, ttl)
	}
	score, err := mr.ZScore("conc:"+name, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if want := float64(clk.Add(ttl).UnixMilli()); score != want {
		t.Errorf("m1 score = %v, want bumped to %v", score, want)
	}
	members, err := mr.ZMembers("conc:" + name)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0] != "m1" {
		t.Fatalf("set = %v, a released member must not be re-added", members)
	}
}

// TestAcquireStream_UsesDerivedTTL: the conc counter's safety TTL is the configured streamTTL.
func TestAcquireStream_UsesDerivedTTL(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	const ttl = 45 * time.Minute
	l := NewLimiter(rdb, 0, 0, 0, ttl)
	if ok, err := l.AcquireStream(ctx, "t", "m1", 4); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if got := mr.TTL("conc:t"); got != ttl {
		t.Fatalf("conc TTL = %s, want the configured streamTTL %s", got, ttl)
	}
}

func TestTrafficExhausted_UnparseableCounterLogged(t *testing.T) {
	ctx := ctxT(t)
	l, _, clk := newChargeLimiter(t, 1, 0, 10, 20)
	var buf bytes.Buffer
	l.logger = slog.New(slog.NewTextHandler(&buf, nil))
	_, _, outDay, _ := chargeKeys("t", "out", clk.Unix())
	if err := l.rdb.Set(ctx, outDay, "not-a-number", 0).Err(); err != nil {
		t.Fatal(err)
	}
	day, week, err := l.TrafficExhausted(ctx, "t")
	if err != nil || day || week {
		t.Fatalf("an unparseable counter counts as 0 (day=%v week=%v err=%v)", day, week, err)
	}
	if !strings.Contains(buf.String(), "unparseable Valkey counter") {
		t.Fatalf("the unparseable counter must be logged; log = %q", buf.String())
	}
}
