package limit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLimiter_Issuance_SerializesOnePerTunnel: while one order holds the lock, a second Begin is refused;
// after the holder Ends, a new Begin succeeds.
func TestLimiter_Issuance_SerializesOnePerTunnel(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"
	ok, orderID, err := l.IssuanceBegin(ctx, name, 3)
	if err != nil || !ok {
		t.Fatalf("first begin: ok=%v err=%v", ok, err)
	}
	if ok, _, _ := l.IssuanceBegin(ctx, name, 3); ok {
		t.Fatal("a second begin while one order holds the lock must be refused")
	}
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := l.IssuanceBegin(ctx, name, 3); err != nil || !ok {
		t.Fatal("after End, a new begin must succeed")
	}
}

// TestLimiter_Issuance_ConcurrentGate: with many concurrent Begins, exactly one wins the lock.
func TestLimiter_Issuance_ConcurrentGate(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"
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
		t.Fatalf("exactly one concurrent Begin must win the lock, got %d", wins.Load())
	}
}

// TestLimiter_Issuance_CapCountsSuccessesOnly: the weekly cap counts only Recorded successes; a failed
// order (End without Record) does not burn the window.
func TestLimiter_Issuance_CapCountsSuccessesOnly(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"
	// A failed order: Begin → End (no Record). It must NOT burn the window.
	ok, orderID, err := l.IssuanceBegin(ctx, name, 1)
	if err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	// Window still empty: a fresh order Begins, Records a success, then Ends.
	ok, orderID, err = l.IssuanceBegin(ctx, name, 1)
	if err != nil || !ok {
		t.Fatal("a failed order must leave the window unconsumed (fresh begin must admit)")
	}
	if err := l.IssuanceRecord(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	// Now 1 committed success at cap 1: a new Begin is refused BY THE CAP (the lock is free).
	if ok, _, _ := l.IssuanceBegin(ctx, name, 1); ok {
		t.Fatal("after 1 committed success at cap 1, a new begin must be refused")
	}
}

// TestLimiter_Issuance_LockSelfExpires: with no heartbeat (a crash), the lock self-expires after issLockTTL
// and a new begin then succeeds.
func TestLimiter_Issuance_LockSelfExpires(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"
	if ok, _, err := l.IssuanceBegin(ctx, name, 3); err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	// A crash: no End, no heartbeat. Advance past the lock TTL → it self-expires.
	mr.FastForward(issLockTTL + time.Second)
	if ok, _, err := l.IssuanceBegin(ctx, name, 3); err != nil || !ok {
		t.Fatal("after the lock self-expires, a new begin must succeed")
	}
}
