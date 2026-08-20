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

// newWindowLimiter builds a Limiter for the per-second byte/packet window tests with a SETTABLE clock
// (advance via the returned *time.Time so a test can roll the second) and an explicit packet cap.
func newWindowLimiter(t *testing.T, bwRate, pktCap int64) (*Limiter, *miniredis.Miniredis, *time.Time) {
	t.Helper()
	rdb, mr := newTestRedis(t)
	clk := time.Unix(1_700_000_000, 0)
	l := NewLimiter(rdb, bwRate, 1<<40, 1<<40, time.Hour, WithPacketCap(pktCap))
	l.SetClock(func() time.Time { return clk })
	return l, mr, &clk
}

// TestChargeBandwidth_ByteWindowOver: at the real 1mbit byte cap, legit ~4 KB reads are byte-capped at
// ~30 reads/sec — read 30 (122880 B) is under, read 31 (126976 B) trips.
func TestChargeBandwidth_ByteWindowOver(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newWindowLimiter(t, 125000, 0) // 1mbit; packet cap disabled so the byte window is what trips
	for i := 1; i <= 30; i++ {
		over, _, err := l.ChargeBandwidth(ctx, "t", "in", 4096)
		if err != nil || over {
			t.Fatalf("read %d: over=%v err=%v, want over=false", i, over, err)
		}
	}
	over, retry, err := l.ChargeBandwidth(ctx, "t", "in", 4096)
	if err != nil || !over || retry <= 0 {
		t.Fatalf("read 31: over=%v retry=%v err=%v, want over=true retry>0", over, retry, err)
	}
}

// TestChargeBandwidth_PacketWindowOver: at the real default --limit-packets (100), a 1-byte-read flood
// trips the PACKET window at read 101 (bytes stay far under the cap).
func TestChargeBandwidth_PacketWindowOver(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newWindowLimiter(t, 1<<30, 100) // huge byte cap so only the packet window can trip
	for i := 1; i <= 100; i++ {
		over, _, err := l.ChargeBandwidth(ctx, "t", "in", 1)
		if err != nil || over {
			t.Fatalf("read %d: over=%v err=%v, want over=false", i, over, err)
		}
	}
	over, _, err := l.ChargeBandwidth(ctx, "t", "in", 1)
	if err != nil || !over {
		t.Fatalf("read 101: over=%v err=%v, want over=true", over, err)
	}
}

// TestChargeBandwidth_PacketCapDisabled: with pktCap==0 a tiny-read burst never trips on packets.
func TestChargeBandwidth_PacketCapDisabled(t *testing.T) {
	ctx := ctxT(t)
	l, _, _ := newWindowLimiter(t, 1<<30, 0) // packet cap disabled, byte cap huge
	for i := 1; i <= 500; i++ {
		if over, _, err := l.ChargeBandwidth(ctx, "t", "in", 1); err != nil || over {
			t.Fatalf("read %d: over=%v err=%v, want over=false (packet cap disabled)", i, over, err)
		}
	}
}

// TestChargeBandwidth_WindowResetsNextSecond: advancing the clock one second moves to a fresh key, so the
// counts reset and a read that was over is under again.
func TestChargeBandwidth_WindowResetsNextSecond(t *testing.T) {
	ctx := ctxT(t)
	l, _, clk := newWindowLimiter(t, 4096, 0) // byte cap = one read; the 2nd read in a second trips
	if over, _, _ := l.ChargeBandwidth(ctx, "t", "in", 4096); over {
		t.Fatal("read 1 must be under the cap")
	}
	if over, _, _ := l.ChargeBandwidth(ctx, "t", "in", 4096); !over {
		t.Fatal("read 2 in the same second must be over the cap")
	}
	*clk = clk.Add(time.Second) // next second → fresh window key
	if over, _, _ := l.ChargeBandwidth(ctx, "t", "in", 4096); over {
		t.Fatal("first read of the next second must be under the cap (window reset)")
	}
}

// TestChargeBandwidth_ExpireNXSetsTTLOnce: the window key's TTL is set on creation and NOT reset by a
// later same-second write (EXPIRE NX is a no-op once a TTL exists).
func TestChargeBandwidth_ExpireNXSetsTTLOnce(t *testing.T) {
	ctx := ctxT(t)
	l, mr, clk := newWindowLimiter(t, 1<<30, 0)
	byteKey, _ := bwWindowKeys("t", "in", clk.Unix())
	if _, _, err := l.ChargeBandwidth(ctx, "t", "in", 1); err != nil { // creates the key, TTL = bwWindowTTL
		t.Fatal(err)
	}
	mr.FastForward(500 * time.Millisecond)                             // TTL now ~1.5s (miniredis clock only; the window key is unchanged)
	if _, _, err := l.ChargeBandwidth(ctx, "t", "in", 1); err != nil { // same-second write: EXPIRE NX no-op
		t.Fatal(err)
	}
	if ttl := mr.TTL(byteKey); ttl <= 0 || ttl >= bwWindowTTL {
		t.Fatalf("TTL = %v, want 0 < ttl < %v (NX must not re-stamp it back to full)", ttl, bwWindowTTL)
	}
}

// TestChargeBandwidth_ExpireNXHealsMissingTTL: a window key left WITHOUT a TTL (a simulated orphan) gets
// one from the NEXT same-second ChargeBandwidth — the self-healing the plain-pipeline choice relies on.
func TestChargeBandwidth_ExpireNXHealsMissingTTL(t *testing.T) {
	ctx := ctxT(t)
	l, mr, clk := newWindowLimiter(t, 1<<30, 0)
	byteKey, _ := bwWindowKeys("t", "in", clk.Unix())
	if err := l.rdb.Incr(ctx, byteKey).Err(); err != nil { // orphan: key exists with NO TTL (white-box)
		t.Fatal(err)
	}
	if ttl := mr.TTL(byteKey); ttl != 0 {
		t.Fatalf("precondition: orphan key must have no TTL, got %v", ttl)
	}
	if _, _, err := l.ChargeBandwidth(ctx, "t", "in", 1); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(byteKey); ttl <= 0 {
		t.Fatalf("EXPIRE NX must heal the missing TTL, got %v", ttl)
	}
}

// TestChargeBandwidth_FailOpenOnValkeyError: a closed Valkey fails open (over=false) with the error.
func TestChargeBandwidth_FailOpenOnValkeyError(t *testing.T) {
	ctx := ctxT(t)
	l, mr, _ := newWindowLimiter(t, 125000, 100)
	mr.Close() // every Valkey call now errors
	over, retry, err := l.ChargeBandwidth(ctx, "t", "in", 4096)
	if err == nil {
		t.Fatal("a closed Valkey must return an error")
	}
	if over || retry != 0 {
		t.Fatalf("fail-open: over=%v retry=%v, want over=false retry=0", over, retry)
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

func TestIssuanceRecordCountsSuccesses(t *testing.T) {
	ctx := ctxT(t)
	l := newLimiter(t, 1, 1, 1)
	for range 3 {
		if err := l.IssuanceRecord(ctx, "t"); err != nil {
			t.Fatal(err)
		}
	}
	// Three committed successes fill cap 3: a fresh Begin (no in-flight slots) is refused.
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

// TestClaimTraffic_RefreshesConcTTLOnlyIfExists: the per-chunk claim refreshes an existing conc counter
// TTL but never creates a missing one.
func TestClaimTraffic_RefreshesConcTTLOnlyIfExists(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 1<<40, 1<<40, 45*time.Minute)
	const name = "t"

	// No conc key yet: ClaimTraffic must NOT create it (PEXPIRE on a missing key is a no-op).
	if _, _, err := l.ClaimTraffic(ctx, name, 100); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("conc:" + name) {
		t.Fatal("ClaimTraffic must not create the conc counter")
	}

	// With an existing conc key whose TTL has been shrunk, ClaimTraffic refreshes it to streamTTL.
	if ok, err := l.AcquireStream(ctx, name, 4); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	mr.SetTTL("conc:"+name, time.Minute)
	if _, _, err := l.ClaimTraffic(ctx, name, 100); err != nil {
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
	if ok, err := l.AcquireStream(ctx, "t", 4); err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	if got := mr.TTL("conc:t"); got != ttl {
		t.Fatalf("conc TTL = %s, want the configured streamTTL %s", got, ttl)
	}
}
