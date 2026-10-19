package limit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// TestLimiter_Issuance_SerializesOnePerTunnel: while one order holds the lock, a second Begin is refused;
// after the holder Ends, a new Begin succeeds.
func TestLimiter_Issuance_SerializesOnePerTunnel(t *testing.T) {
	rdb, _ := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	const name = "t"
	ok, orderID, _, err := l.IssuanceBegin(ctx, name, 3)
	if err != nil || !ok {
		t.Fatalf("first begin: ok=%v err=%v", ok, err)
	}
	if ok, _, _, err := l.IssuanceBegin(ctx, name, 3); !errors.Is(err, ErrIssuanceInFlight) || ok {
		t.Fatalf("a second begin while one order holds the lock must be refused as in flight: ok=%v err=%v", ok, err)
	}
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	if ok, _, _, err := l.IssuanceBegin(ctx, name, 3); err != nil || !ok {
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
			ok, _, _, err := l.IssuanceBegin(ctx, name, 3)
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
	ok, orderID, _, err := l.IssuanceBegin(ctx, name, 1)
	if err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	if err := l.IssuanceEnd(ctx, name, orderID); err != nil {
		t.Fatal(err)
	}
	// Window still empty: a fresh order Begins, Records a success, then Ends.
	ok, orderID, _, err = l.IssuanceBegin(ctx, name, 1)
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
	if ok, _, _, err := l.IssuanceBegin(ctx, name, 1); err != nil {
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
	if ok, _, _, err := l.IssuanceBegin(ctx, name, 3); err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	// A crash: no End, no heartbeat. Advance past the lock TTL → it self-expires.
	mr.FastForward(issLockTTL + time.Second)
	if ok, _, _, err := l.IssuanceBegin(ctx, name, 3); err != nil || !ok {
		t.Fatalf("after the lock self-expires, a new begin must succeed (ok=%v err=%v)", ok, err)
	}
}

func TestLimiter_IssuanceEnd_ReturnsReleaseError(t *testing.T) {
	rdb, mr := newTestRedis(t)
	ctx := ctxT(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	ok, orderID, _, err := l.IssuanceBegin(ctx, "t", 3)
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
	ok, orderID, _, err := l.IssuanceBegin(ctxT(t), "t", 3)
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
	ok, _, _, err := l.IssuanceBegin(ctxT(t), "t", 3)
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
			if ok, _, _, err := l.IssuanceBegin(ctx, "t", 3); ok || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "issuance window read") {
				t.Errorf("IssuanceBegin over the cap with a cancelled caller = (%v, %v), want a refusal carrying the cancelled window read", ok, err)
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

func TestLimiter_IssuanceBegin_CappedReturnsWindowLeft(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, l *Limiter, mr *miniredis.Miniredis)
		ok    bool
		want  time.Duration
	}{
		{name: "an hour into the window", setup: func(t *testing.T, l *Limiter, mr *miniredis.Miniredis) {
			if err := l.IssuanceRecord(ctxT(t), "t"); err != nil {
				t.Fatal(err)
			}
			mr.FastForward(time.Hour)
		}, want: issWindowTTL - time.Hour},
		{name: "a sub-second remainder rounds up", setup: func(t *testing.T, _ *Limiter, mr *miniredis.Miniredis) {
			if err := mr.Set(issuanceKey("t"), "1"); err != nil {
				t.Fatal(err)
			}
			mr.SetTTL(issuanceKey("t"), 1500*time.Millisecond)
		}, want: 2 * time.Second},
		{name: "under the cap", setup: func(*testing.T, *Limiter, *miniredis.Miniredis) {}, ok: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rdb, mr := newTestRedis(t)
			l := NewLimiter(rdb, 0, 0, 0, time.Hour)
			tc.setup(t, l, mr)
			ok, _, left, err := l.IssuanceBegin(ctxT(t), "t", 1)
			if err != nil || ok != tc.ok || left != tc.want {
				t.Fatalf("IssuanceBegin = (ok %v, retryAfter %v, err %v), want (ok %v, retryAfter %v)", ok, left, err, tc.ok, tc.want)
			}
			if !tc.ok && mr.Exists(issLockKey("t")) {
				t.Fatal("a capped begin must release the issuance lock")
			}
		})
	}
}

func TestLimiter_IssuanceBegin_CappedWithoutTTLRestoresWindow(t *testing.T) {
	rdb, mr := newTestRedis(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	if err := mr.Set(issuanceKey("t"), "3"); err != nil {
		t.Fatal(err)
	}
	ok, _, left, err := l.IssuanceBegin(ctxT(t), "t", 3)
	if ok || err != nil || left != issWindowTTL {
		t.Fatalf("IssuanceBegin = (ok %v, retryAfter %v, err %v), want a refusal with the full window", ok, left, err)
	}
	if ttl := mr.TTL(issuanceKey("t")); ttl != issWindowTTL {
		t.Fatalf("a capped counter without a TTL must get the 7-day window back, TTL = %v", ttl)
	}
}

func TestLimiter_IssuanceWindowLeft_MissingKeyIsOneSecond(t *testing.T) {
	rdb, _ := newTestRedis(t)
	l := NewLimiter(rdb, 0, 0, 0, time.Hour)
	left, err := l.issuanceWindowLeft(ctxT(t), "missing")
	if err != nil || left != time.Second {
		t.Fatalf("issuanceWindowLeft(missing) = (%v, %v), want (1s, nil)", left, err)
	}
}

func TestLimiter_IssuanceBegin_WindowErrorsReturned(t *testing.T) {
	tests := []struct {
		name, fail, want string
	}{
		{name: "window read", fail: "pttl", want: "issuance window read"},
		{name: "window restore", fail: "expire", want: "issuance window restore"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, mr, rdb, _ := newLoggedLimiter(t)
			if err := mr.Set(issuanceKey("t"), "3"); err != nil {
				t.Fatal(err)
			}
			rdb.AddHook(tunneltest.FailCommands(errInjected, tc.fail))
			ok, _, _, err := l.IssuanceBegin(ctxT(t), "t", 3)
			if ok || !errors.Is(err, errInjected) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("IssuanceBegin = (%v, %v), want a refusal carrying %q", ok, err, tc.want)
			}
		})
	}
}
