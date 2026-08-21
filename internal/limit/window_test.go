package limit

import (
	"net/netip"
	"testing"
	"time"
)

var testIP = netip.MustParseAddr("203.0.113.7")

func TestRPSAllowsUpToLimitThenDenies(t *testing.T) {
	l, _ := newFrozenLimiter(t)
	ctx := ctxT(t)
	for range 10 {
		ok, _, err := l.Allow(ctx, "rps", testIP, 10, time.Second)
		if err != nil || !ok {
			t.Fatalf("call: ok=%v err=%v (want allowed)", ok, err)
		}
	}
	ok, retry, err := l.Allow(ctx, "rps", testIP, 10, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("11th call must be denied")
	}
	if retry <= 0 || retry > time.Second {
		t.Errorf("retry-after = %s, want (0, 1s]", retry)
	}
}

func TestRPMAllowsUpToLimitThenDenies(t *testing.T) {
	l, _ := newFrozenLimiter(t)
	ctx := ctxT(t)
	for range 100 {
		ok, _, err := l.Allow(ctx, "rpm", testIP, 100, time.Minute)
		if err != nil || !ok {
			t.Fatalf("call denied: ok=%v err=%v", ok, err)
		}
	}
	ok, retry, err := l.Allow(ctx, "rpm", testIP, 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("101st call must be denied")
	}
	if retry <= 0 || retry > time.Minute {
		t.Errorf("retry-after = %s, want (0, 1m]", retry)
	}
}

func TestWindowResetsOnBoundary(t *testing.T) {
	l, mr := newFrozenLimiter(t)
	ctx := ctxT(t)
	for i := range 2 {
		if ok, _, _ := l.Allow(ctx, "rps", testIP, 2, time.Second); !ok {
			t.Fatalf("call %d must be allowed", i+1)
		}
	}
	if ok, _, _ := l.Allow(ctx, "rps", testIP, 2, time.Second); ok {
		t.Fatal("3rd call must be denied within the window")
	}
	// Advance miniredis past the window*2 TTL so the window key expires.
	mr.FastForward(3 * time.Second)
	if ok, _, err := l.Allow(ctx, "rps", testIP, 2, time.Second); err != nil || !ok {
		t.Errorf("after window expiry the count must reset (ok=%v err=%v)", ok, err)
	}
}

// TestEveryKeyHasTTLAfterFirstOp pins the SACRED "no permanent Valkey state" invariant across ALL key
// families: after one op on each, every resulting key must carry a TTL.
func TestEveryKeyHasTTLAfterFirstOp(t *testing.T) {
	l, mr := newFrozenLimiter(t)
	ctx := ctxT(t)
	if _, _, err := l.Allow(ctx, "rps", testIP, 10, time.Second); err != nil { // rl:
		t.Fatal(err)
	}
	if _, err := l.AcquireStream(ctx, "tunnel-x", "conn1", 4); err != nil { // conc:
		t.Fatal(err)
	}
	if _, _, _, err := l.Charge(ctx, "tunnel-x", "in", 1024); err != nil { // bw: + pkt: + traf:day + traf:week
		t.Fatal(err)
	}
	if _, _, err := l.IssuanceBegin(ctx, "tunnel-x", 3); err != nil { // iss_lock:
		t.Fatal(err)
	}
	if err := l.IssuanceRecord(ctx, "tunnel-x"); err != nil { // iss:
		t.Fatal(err)
	}
	if _, err := l.BumpCAFailures(ctx, "letsencrypt", time.Hour); err != nil { // acme-fail:
		t.Fatal(err)
	}
	keys := mr.Keys()
	if len(keys) == 0 {
		t.Fatal("expected keys after limiter ops")
	}
	for _, k := range keys {
		if ttl := mr.TTL(k); ttl <= 0 {
			t.Errorf("key %q has no TTL (%s) — un-TTL'd Redis state", k, ttl)
		}
	}
}

// TestOverReadOnlyPreGate: Over reports an at-limit window WITHOUT consuming a slot.
func TestOverReadOnlyPreGate(t *testing.T) {
	l, _ := newFrozenLimiter(t)
	ctx := ctxT(t)
	ip := netip.MustParseAddr("203.0.113.30")

	over, _, err := l.Over(ctx, "enroll-min", ip, 2, time.Minute)
	if err != nil || over {
		t.Fatalf("fresh window must not be over (over=%v err=%v)", over, err)
	}
	for range 2 {
		if ok, _, err := l.Allow(ctx, "enroll-min", ip, 2, time.Minute); err != nil || !ok {
			t.Fatalf("allow within limit failed: %v %v", ok, err)
		}
	}
	over, ra, err := l.Over(ctx, "enroll-min", ip, 2, time.Minute)
	if err != nil || !over || ra <= 0 {
		t.Fatalf("at-limit window must report over with a retry-after (over=%v ra=%v err=%v)", over, ra, err)
	}
	// Read-only: Over itself must not have consumed anything — the counter is still exactly 2.
	over2, _, _ := l.Over(ctx, "enroll-min", ip, 3, time.Minute)
	if over2 {
		t.Fatal("Over must not increment the window counter")
	}
}
