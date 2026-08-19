package limit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIssuanceBegin_ConcurrentGate: with 2 committed successes and cap 3, exactly one of many
// concurrent Begins may reserve the last in-flight slot.
func TestIssuanceBegin_ConcurrentGate(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"
	for range 2 { // committed = 2
		if err := l.IssuanceRecord(ctx, name); err != nil {
			t.Fatal(err)
		}
	}

	const goroutines = 8
	var wins atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if ok, _, err := l.IssuanceBegin(ctx, name, 3); err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("committed=2 cap=3: exactly one concurrent Begin must win, got %d", wins.Load())
	}
}

// TestIssuanceBegin_PurgesExpiredSlots: an expired in-flight slot is purged by the next Begin, freeing
// the cap for a new order.
func TestIssuanceBegin_PurgesExpiredSlots(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	base := time.Unix(1_700_000_000, 0)
	clk := base
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	l.SetClock(func() time.Time { return clk })
	const name = "t"

	// The first Begin fills the single slot (cap 1).
	if ok, _, err := l.IssuanceBegin(ctx, name, 1); err != nil || !ok {
		t.Fatalf("first begin: ok=%v err=%v", ok, err)
	}
	// A second Begin at the same instant is refused (the slot is live).
	if ok, _, _ := l.IssuanceBegin(ctx, name, 1); ok {
		t.Fatal("a live in-flight slot must block a second begin at cap 1")
	}
	// Advance past the slot deadline: the stale slot is purged and a new order is admitted.
	clk = base.Add(issuanceSlotTTL + time.Second)
	if ok, _, err := l.IssuanceBegin(ctx, name, 1); err != nil || !ok {
		t.Fatal("an expired in-flight slot must be purged and the new order admitted")
	}
}

// TestIssuanceHeartbeat_RefreshesOnlyPresent: a heartbeat for an already-purged slot must not
// resurrect it.
func TestIssuanceHeartbeat_RefreshesOnlyPresent(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"

	ok, orderID, err := l.IssuanceBegin(ctx, name, 1)
	if err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	// The slot is purged (an expiry / completion).
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	// A late heartbeat for the purged slot must be a no-op (HEXISTS guard), never re-creating the field.
	now := l.now().UnixMilli()
	if err := issuanceHeartbeatScript.Run(ctx, l.rdb, []string{inflightKey(name)},
		orderID, now, issuanceSlotTTL.Milliseconds(),
		(issuanceSlotTTL + issuanceKeyTTLMargin).Milliseconds()).Err(); err != nil {
		t.Fatal(err)
	}
	if exists, _ := l.rdb.HExists(ctx, inflightKey(name), orderID).Result(); exists {
		t.Fatal("a heartbeat must not resurrect a purged in-flight slot")
	}
}

// TestIssuanceEnd_FreesSlotOnFailure: a Begin followed by End (no Record) frees the slot and leaves the
// committed weekly window unconsumed.
func TestIssuanceEnd_FreesSlotOnFailure(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"

	ok, orderID, err := l.IssuanceBegin(ctx, name, 1)
	if err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	// Failure path: free the slot WITHOUT recording a success.
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	// The committed counter was never incremented, so a fresh Begin at cap 1 still admits.
	if ok, _, err := l.IssuanceBegin(ctx, name, 1); err != nil || !ok {
		t.Fatal("a failed order must free its slot and leave the weekly window unconsumed")
	}
}
