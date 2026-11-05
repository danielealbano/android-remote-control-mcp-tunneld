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
	"github.com/redis/go-redis/v9"

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
	mr.SetError("ERR valkey is down")
	if err := l.IssuanceEnd(ctx, "t", orderID); err == nil {
		t.Fatal("a failed lock release must be returned to the caller")
	}
}

func TestLimiter_IssuanceBegin_CountReadErrorLogsRelease(t *testing.T) {
	t.Parallel()
	l, _, rdb, buf := newLoggedLimiter(t)
	rdb.AddHook(tunneltest.FailCommands(errInjected, "get"))
	ok, orderID, _, err := l.IssuanceBegin(ctxT(t), "t", 3)
	if ok || orderID != "" || !errors.Is(err, errInjected) || !strings.Contains(err.Error(), "issuance count read") {
		t.Fatalf("IssuanceBegin = (%v, %q, %v), want a refusal carrying the read error", ok, orderID, err)
	}
	if !strings.Contains(buf.String(), `msg="could not release the tunnel's issuance lock; it expires on its own" tunnel=t`) || !strings.Contains(buf.String(), "issuance lock release check") {
		t.Fatalf("the failed release must be logged; log = %q", buf.String())
	}
}

type deadlineRecorder struct {
	mu   sync.Mutex
	left map[string]time.Duration
}

func (h *deadlineRecorder) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *deadlineRecorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if d, ok := ctx.Deadline(); ok {
			h.mu.Lock()
			h.left[cmd.Name()] = time.Until(d)
			h.mu.Unlock()
		}
		return next(ctx, cmd)
	}
}

func (h *deadlineRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestLimiter_IssuanceEnd_ReleaseOwnsItsBound(t *testing.T) {
	t.Parallel()
	l, mr, rdb, buf := newLoggedLimiter(t)
	ok, orderID, _, err := l.IssuanceBegin(ctxT(t), "t", 3)
	if err != nil || !ok {
		t.Fatalf("begin: ok=%v err=%v", ok, err)
	}
	rec := &deadlineRecorder{left: map[string]time.Duration{}}
	rdb.AddHook(rec)
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	cancel()
	if err := l.IssuanceEnd(ctx, "t", orderID); err != nil {
		t.Fatalf("a cancelled caller must still release the lock: %v", err)
	}
	if mr.Exists(issLockKey("t")) {
		t.Fatal("the lock must be released")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, name := range []string{"get", "del"} {
		if left, ok := rec.left[name]; !ok || left <= 0 || left > issLockReleaseTimeout {
			t.Fatalf("%s ran with %s left (deadline set: %v), want the release's own (0, %s] bound", name, left, ok, issLockReleaseTimeout)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("a clean release must not log; log = %q", buf.String())
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
	if !strings.Contains(buf.String(), `msg="could not release the tunnel's issuance lock; it expires on its own" tunnel=t`) {
		t.Fatalf("the failed release must be logged; log = %q", buf.String())
	}
}

func TestLimiter_RefreshIssLock_LogsFailures(t *testing.T) {
	tests := []struct {
		name string
		fail string
		want string
	}{
		{name: "ownership check fails", fail: "get", want: `msg="could not check the tunnel's issuance lock before refreshing it; if it expires, a retried request could start a second issuance" tunnel=t`},
		{name: "ttl refresh fails", fail: "pexpire", want: `msg="could not refresh the tunnel's issuance lock; if it expires, a retried request could start a second issuance" tunnel=t`},
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

func TestLimiter_RefreshIssLock_CancelledCallerIsSilent(t *testing.T) {
	t.Parallel()
	l, mr, rdb, buf := newLoggedLimiter(t)
	if err := mr.Set(issLockKey("t"), "order"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rdb.AddHook(tunneltest.CancelAfter("get", cancel))
	rdb.AddHook(tunneltest.FailCommands(errInjected, "pexpire"))
	l.refreshIssLock(ctx, "t", "order")
	if buf.Len() != 0 {
		t.Fatalf("a refresh failure caused by the caller's cancellation must not be logged; log = %q", buf.String())
	}
}

func TestLimiter_IssuanceBegin_CancelledCallerStillReleases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		count     string
		cancelOn  string
		fail      string
		replace   func(mr *miniredis.Miniredis) error
		wantErr   string
		wantHeld  bool
		wantValue string
		wantLog   string
	}{
		{name: "count read cancelled", cancelOn: "set", wantErr: "issuance count read"},
		{name: "count read cancelled, release fails", cancelOn: "set", fail: "del", wantErr: "issuance count read", wantHeld: true, wantLog: `msg="could not release the tunnel's issuance lock; it expires on its own" tunnel=t`},
		{name: "over the cap", count: "3", cancelOn: "get", wantErr: "issuance window read"},
		{name: "over the cap, release fails", count: "3", cancelOn: "get", fail: "del", wantErr: "issuance window read", wantHeld: true, wantLog: `msg="could not release the tunnel's issuance lock; it expires on its own" tunnel=t`},
		{
			name: "over the cap, lock already expired", count: "3", cancelOn: "get", wantErr: "issuance window read",
			replace: func(mr *miniredis.Miniredis) error { mr.Del(issLockKey("t")); return nil },
		},
		{
			name: "over the cap, another holder took the lock", count: "3", cancelOn: "get", wantErr: "issuance window read", wantHeld: true, wantValue: "someone-else",
			replace: func(mr *miniredis.Miniredis) error { return mr.Set(issLockKey("t"), "someone-else") },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, mr, rdb, buf := newLoggedLimiter(t)
			if tc.count != "" {
				if err := mr.Set(issuanceKey("t"), tc.count); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rdb.AddHook(tunneltest.CancelAfter(tc.cancelOn, func() {
				if ctx.Err() == nil && tc.replace != nil {
					if err := tc.replace(mr); err != nil {
						t.Error(err)
					}
				}
				cancel()
			}))
			if tc.fail != "" {
				rdb.AddHook(tunneltest.FailCommands(errInjected, tc.fail))
			}
			ok, _, _, err := l.IssuanceBegin(ctx, "t", 3)
			if ok || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("IssuanceBegin = (%v, %v), want a refusal carrying the cancelled %q", ok, err, tc.wantErr)
			}
			if held := mr.Exists(issLockKey("t")); held != tc.wantHeld {
				t.Fatalf("issuance lock held after the cancelled begin = %v, want %v", held, tc.wantHeld)
			}
			if tc.wantValue != "" {
				if v, err := mr.Get(issLockKey("t")); err != nil || v != tc.wantValue {
					t.Fatalf("another holder's lock must be left alone: %q %v", v, err)
				}
			}
			switch {
			case tc.wantLog == "" && buf.Len() != 0:
				t.Fatalf("a clean release must not log; log = %q", buf.String())
			case tc.wantLog != "" && !strings.Contains(buf.String(), tc.wantLog):
				t.Fatalf("the failed release must be logged even after the caller was cancelled; log = %q", buf.String())
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
