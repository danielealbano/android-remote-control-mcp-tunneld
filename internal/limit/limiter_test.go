package limit

import (
	"testing"
	"time"
)

func newLimiter(t *testing.T, bw, day, week int64) *Limiter {
	t.Helper()
	rdb, _ := newTestRedis(t)
	return NewLimiter(rdb, bw, day, week)
}

func TestClaimBandwidthPartialGrantAndRefill(t *testing.T) {
	ctx := ctxT(t)
	base := time.Unix(1_700_000_000, 0)
	clk := base
	l := newLimiter(t, 1000, 1<<40, 1<<40) // 1000 B/s → burst 1000
	l.SetClock(func() time.Time { return clk })

	// First claim gets the full burst.
	g, err := l.ClaimBandwidth(ctx, "t", "out", 800)
	if err != nil || g != 800 {
		t.Fatalf("first claim = %d err=%v", g, err)
	}
	// Bucket has ~200 left; asking 500 grants 200.
	g, _ = l.ClaimBandwidth(ctx, "t", "out", 500)
	if g != 200 {
		t.Errorf("drained claim = %d, want 200", g)
	}
	// Zero tokens now.
	g, _ = l.ClaimBandwidth(ctx, "t", "out", 100)
	if g != 0 {
		t.Errorf("empty bucket claim = %d, want 0", g)
	}
	// Advance 1s → refills 1000 (capped at burst).
	clk = base.Add(time.Second)
	g, _ = l.ClaimBandwidth(ctx, "t", "out", 1000)
	if g != 1000 {
		t.Errorf("refilled claim = %d, want 1000", g)
	}
}

func TestClaimTrafficDayWeek(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1000, 1000, 5000) // day cap 1000, week cap 5000
	l.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })

	dayOK, weekOK, err := l.ClaimTraffic(ctx, "t", 600)
	if err != nil || !dayOK || !weekOK {
		t.Fatalf("under both: day=%v week=%v err=%v", dayOK, weekOK, err)
	}
	// 600+600 = 1200 > day 1000 → dayOK false, week still ok (1200 < 5000).
	dayOK, weekOK, _ = l.ClaimTraffic(ctx, "t", 600)
	if dayOK {
		t.Error("day should be exhausted")
	}
	if !weekOK {
		t.Error("week should still be ok")
	}
}

func TestIssuanceReadOnlyAndRecord(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1, 1, 1)
	ok, err := l.IssuanceAllowed(ctx, "t", 3)
	if err != nil || !ok {
		t.Fatalf("initial allowed: %v %v", ok, err)
	}
	// Read-only check does not mutate: still allowed after repeated checks.
	_, _ = l.IssuanceAllowed(ctx, "t", 3)
	if v := l.rdb.Get(ctx, issuanceKey("t")).Val(); v != "" {
		t.Errorf("IssuanceAllowed must not create the counter, got %q", v)
	}
	for range 3 {
		if err := l.IssuanceRecord(ctx, "t"); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := l.IssuanceAllowed(ctx, "t", 3); ok {
		t.Error("after 3 records, cap 3 should deny")
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
		ok, err := l.AcquireStream(ctx, "t", 4)
		if err != nil || !ok {
			t.Fatalf("acquire: ok=%v err=%v", ok, err)
		}
	}
	if ok, _ := l.AcquireStream(ctx, "t", 4); ok {
		t.Error("5th acquire past cap 4 should fail")
	}
	if err := l.ReleaseStream(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := l.AcquireStream(ctx, "t", 4); !ok {
		t.Error("after release, a slot should be free")
	}
}

func TestTrafficExhaustedReadOnly(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1, 10, 20) // day cap 10, week cap 20

	day, week, err := l.TrafficExhausted(ctx, "t")
	if err != nil || day || week {
		t.Fatalf("fresh tunnel must not be exhausted: %v %v %v", day, week, err)
	}
	if _, _, err := l.ClaimTraffic(ctx, "t", 10); err != nil { // exactly at the day cap
		t.Fatal(err)
	}
	day, week, err = l.TrafficExhausted(ctx, "t")
	if err != nil || !day || week {
		t.Fatalf("at-cap day window must report exhausted (day=%v week=%v err=%v)", day, week, err)
	}
	// Read-only: the check itself must not move the counters.
	day2, _, _ := l.TrafficExhausted(ctx, "t")
	if day2 != day {
		t.Fatal("TrafficExhausted must be read-only")
	}
}
