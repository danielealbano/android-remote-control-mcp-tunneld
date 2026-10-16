package limit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
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
	if ok, _, err := l.IssuanceBegin(ctx, name, 3); !errors.Is(err, ErrIssuanceInFlight) || ok {
		t.Fatalf("a second begin while one order holds the lock must be refused as in flight: ok=%v err=%v", ok, err)
	}
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := l.IssuanceBegin(ctx, name, 3); err != nil || !ok {
		t.Fatalf("after End, a new begin must succeed (ok=%v err=%v)", ok, err)
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
	errs := make(chan error, goroutines)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			ok, _, err := l.IssuanceBegin(ctx, name, 3)
			if !errors.Is(err, ErrIssuanceInFlight) {
				errs <- err
			}
			if err == nil && ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("IssuanceBegin: %v", err)
		}
	}
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
		t.Fatalf("a failed order must leave the window unconsumed (fresh begin must admit; ok=%v err=%v)", ok, err)
	}
	if err := l.IssuanceRecord(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	// Now 1 committed success at cap 1: a new Begin is refused BY THE CAP (the lock is free).
	if ok, _, err := l.IssuanceBegin(ctx, name, 1); err != nil {
		t.Fatal(err)
	} else if ok {
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
		t.Fatalf("after the lock self-expires, a new begin must succeed (ok=%v err=%v)", ok, err)
	}
}

func TestLimiter_IssuanceEnd_ReturnsReleaseError(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	ok, orderID, err := l.IssuanceBegin(ctx, "t", 3)
	if err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	mr.Close()
	if err := l.IssuanceEnd(ctx, "t", orderID); err == nil {
		t.Fatal("a failed lock release must be returned to the caller")
	}
}

func TestLimiter_IssuanceBegin_CountReadErrorJoinsRelease(t *testing.T) {
	l, _, rdb, _ := newLoggedLimiter(t)
	rdb.AddHook(tunneltest.FailCommands(errInjected, "get"))
	ok, orderID, err := l.IssuanceBegin(ctxT(t), "t", 3)
	if ok || orderID != "" || !errors.Is(err, errInjected) {
		t.Fatalf("IssuanceBegin = (%v, %q, %v), want a refusal carrying the read error", ok, orderID, err)
	}
	if !strings.Contains(err.Error(), "issuance count read") || !strings.Contains(err.Error(), "issuance lock release check") {
		t.Fatalf("the count-read and release errors must both be reported, got %v", err)
	}
}

func TestLimiter_IssuanceBegin_OverCapReleaseFailureLogged(t *testing.T) {
	l, mr, rdb, buf := newLoggedLimiter(t)
	if err := mr.Set(issuanceKey("t"), "3"); err != nil {
		t.Fatal(err)
	}
	rdb.AddHook(tunneltest.FailCommands(errInjected, "del"))
	ok, _, err := l.IssuanceBegin(ctxT(t), "t", 3)
	if ok || err != nil {
		t.Fatalf("IssuanceBegin over the cap = (%v, %v), want a plain refusal", ok, err)
	}
	if !strings.Contains(buf.String(), `msg="issuance lock release failed (lock expires by TTL)" tunnel=t`) {
		t.Fatalf("the failed release must be logged; log = %q", buf.String())
	}
}

func TestLimiter_RefreshIssLock_LogsFailures(t *testing.T) {
	tests := []struct {
		name string
		fail string
		want string
	}{
		{name: "ownership check fails", fail: "get", want: `msg="issuance lock refresh check failed (lock may expire; a retry could then start)" tunnel=t`},
		{name: "ttl refresh fails", fail: "pexpire", want: `msg="issuance lock refresh failed (lock may expire; a retry could then start)" tunnel=t`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, mr, rdb, buf := newLoggedLimiter(t)
			if err := mr.Set(issLockKey("t"), "order"); err != nil {
				t.Fatal(err)
			}
			rdb.AddHook(tunneltest.FailCommands(errInjected, tc.fail))
			l.refreshIssLock(ctxT(t), "t", "order")
			if !strings.Contains(buf.String(), tc.want) || !strings.Contains(buf.String(), errInjected.Error()) {
				t.Fatalf("the refresh failure must be logged with its cause; log = %q", buf.String())
			}
		})
	}
}

func TestLimiter_RefreshIssLock_ExtendsHeldLock(t *testing.T) {
	l, mr, _, buf := newLoggedLimiter(t)
	if err := mr.Set(issLockKey("t"), "order"); err != nil {
		t.Fatal(err)
	}
	l.refreshIssLock(ctxT(t), "t", "order")
	if ttl := mr.TTL(issLockKey("t")); ttl != issLockTTL {
		t.Fatalf("a held lock must be refreshed to issLockTTL, got %v", ttl)
	}
	if buf.Len() != 0 {
		t.Fatalf("a successful refresh must not log; log = %q", buf.String())
	}
}

func TestLimiter_IssuanceLock_CancelledCallerIsSilent(t *testing.T) {
	tests := []struct {
		name string
		fail string
		lock bool
		run  func(ctx context.Context, l *Limiter)
	}{
		{name: "over-cap release", fail: "del", run: func(ctx context.Context, l *Limiter) {
			if ok, _, err := l.IssuanceBegin(ctx, "t", 3); ok || err != nil {
				t.Errorf("IssuanceBegin over the cap = (%v, %v), want a plain refusal", ok, err)
			}
		}},
		{name: "ttl refresh", fail: "pexpire", lock: true, run: func(ctx context.Context, l *Limiter) {
			l.refreshIssLock(ctx, "t", "order")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, mr, rdb, buf := newLoggedLimiter(t)
			if err := mr.Set(issuanceKey("t"), "3"); err != nil {
				t.Fatal(err)
			}
			if tc.lock {
				if err := mr.Set(issLockKey("t"), "order"); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rdb.AddHook(tunneltest.CancelAfter("get", cancel))
			rdb.AddHook(tunneltest.FailCommands(errInjected, tc.fail))
			tc.run(ctx, l)
			if buf.Len() != 0 {
				t.Fatalf("a lock failure caused by the caller's cancellation must not be logged; log = %q", buf.String())
			}
		})
	}
}
