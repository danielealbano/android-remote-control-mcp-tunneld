package acme

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var (
	_ TLSALPNChallenges = (*ChallengeStore)(nil)
	_ HTTPChallenges    = (*ChallengeStore)(nil)
)

func newTestChallengeStore(t *testing.T) (*ChallengeStore, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { closeOrLog(t, rdb) })
	return NewChallengeStore(rdb, ChallengeTTL), mr, rdb
}

func TestChallengeStore_TLSALPNPutGetDelete(t *testing.T) {
	t.Parallel()
	s, _, _ := newTestChallengeStore(t)
	ctx := context.Background()
	if err := s.PutTLSALPN(ctx, "A.Example.TEST", "tok.thumb"); err != nil {
		t.Fatal(err)
	}
	cert, ok, err := s.TLSALPNCertificate(ctx, "a.example.test")
	if err != nil || !ok {
		t.Fatalf("certificate: ok=%v err=%v", ok, err)
	}
	if leaf := parseChallengeLeaf(t, cert); len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "a.example.test" {
		t.Fatalf("DNSNames = %v", leaf.DNSNames)
	}
	if err := s.DeleteTLSALPN(ctx, "a.example.test", "tok.thumb"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.TLSALPNCertificate(ctx, "a.example.test"); ok || err != nil {
		t.Fatalf("after delete: ok=%v err=%v", ok, err)
	}
}

func TestChallengeStore_TLSALPNPendingConflict(t *testing.T) {
	t.Parallel()
	s, _, _ := newTestChallengeStore(t)
	ctx := context.Background()
	if err := s.PutTLSALPN(ctx, "a.example.test", "first"); err != nil {
		t.Fatal(err)
	}
	err := s.PutTLSALPN(ctx, "a.example.test", "second")
	if !errors.Is(err, ErrChallengePending) || !errors.Is(err, ErrChallengeStore) {
		t.Fatalf("conflicting put = %v, want ErrChallengePending wrapping ErrChallengeStore", err)
	}
	if err := s.PutTLSALPN(ctx, "a.example.test", "first"); err != nil {
		t.Fatalf("same keyAuth must be idempotent, got %v", err)
	}
}

type deleteAfterRefusedSetNX struct {
	mr   *miniredis.Miniredis
	key  string
	once sync.Once
}

func (h *deleteAfterRefusedSetNX) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *deleteAfterRefusedSetNX) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h *deleteAfterRefusedSetNX) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if b, ok := cmd.(*redis.BoolCmd); ok && err == nil && !b.Val() {
			h.once.Do(func() { h.mr.Del(h.key) })
		}
		return err
	}
}

func TestChallengeStore_TLSALPNExpiredBetweenRetries(t *testing.T) {
	t.Parallel()
	s, mr, rdb := newTestChallengeStore(t)
	key := alpnChallengeKey("a.example.test")
	if err := mr.Set(key, "stale"); err != nil {
		t.Fatal(err)
	}
	rdb.AddHook(&deleteAfterRefusedSetNX{mr: mr, key: key})
	if err := s.PutTLSALPN(context.Background(), "a.example.test", "fresh"); err != nil {
		t.Fatalf("put after the pending key vanished: %v", err)
	}
	if got, err := mr.Get(key); err != nil || got != "fresh" {
		t.Fatalf("stored %q (err %v), want fresh", got, err)
	}
}

func TestChallengeStore_TLSALPNTTL(t *testing.T) {
	t.Parallel()
	s, mr, _ := newTestChallengeStore(t)
	if err := s.PutTLSALPN(context.Background(), "a.example.test", "k"); err != nil {
		t.Fatal(err)
	}
	if got := mr.TTL(alpnChallengeKey("a.example.test")); got != ChallengeTTL {
		t.Fatalf("TTL = %s, want %s", got, ChallengeTTL)
	}
}

func TestChallengeStore_DeleteIgnoresForeignValue(t *testing.T) {
	t.Parallel()
	s, mr, _ := newTestChallengeStore(t)
	ctx := context.Background()
	if err := s.PutTLSALPN(ctx, "a.example.test", "mine"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutHTTP(ctx, "a.example.test", "tok", "mine"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTLSALPN(ctx, "a.example.test", "other"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHTTP(ctx, "a.example.test", "tok", "other"); err != nil {
		t.Fatal(err)
	}
	if !mr.Exists(alpnChallengeKey("a.example.test")) || !mr.Exists(httpChallengeKey("a.example.test", "tok")) {
		t.Fatal("a delete with a foreign value removed the key")
	}
}

func TestChallengeStore_HTTPPutGetDelete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		putHost   string
		getHost   string
		putToken  string
		getToken  string
		wantFound bool
	}{
		{name: "exact", putHost: "a.example.test", getHost: "a.example.test", putToken: "tok", getToken: "tok", wantFound: true},
		{name: "host case-insensitive", putHost: "A.Example.Test", getHost: "a.example.test", putToken: "tok", getToken: "tok", wantFound: true},
		{name: "other token", putHost: "a.example.test", getHost: "a.example.test", putToken: "tok", getToken: "nope"},
		{name: "other host", putHost: "a.example.test", getHost: "b.example.test", putToken: "tok", getToken: "tok"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, mr, _ := newTestChallengeStore(t)
			ctx := context.Background()
			if err := s.PutHTTP(ctx, tc.putHost, tc.putToken, "key-auth"); err != nil {
				t.Fatal(err)
			}
			if got := mr.TTL(httpChallengeKey(tc.putHost, tc.putToken)); got != ChallengeTTL {
				t.Fatalf("TTL = %s, want %s", got, ChallengeTTL)
			}
			v, found, err := s.HTTPKeyAuth(ctx, tc.getHost, tc.getToken)
			if err != nil || found != tc.wantFound {
				t.Fatalf("lookup: found=%v err=%v, want found=%v", found, err, tc.wantFound)
			}
			if !tc.wantFound {
				return
			}
			if v != "key-auth" {
				t.Fatalf("keyAuth = %q", v)
			}
			if err := s.DeleteHTTP(ctx, tc.getHost, tc.getToken, "key-auth"); err != nil {
				t.Fatal(err)
			}
			if _, found, err := s.HTTPKeyAuth(ctx, tc.getHost, tc.getToken); err != nil || found {
				t.Fatalf("after delete: found=%v err=%v, want absent", found, err)
			}
		})
	}
}

func TestChallengeStore_ErrorsWrapChallengeStore(t *testing.T) {
	t.Parallel()
	s, mr, _ := newTestChallengeStore(t)
	mr.Close()
	ctx := context.Background()
	_, certOK, certErr := s.TLSALPNCertificate(ctx, "a.example.test")
	_, httpFound, httpErr := s.HTTPKeyAuth(ctx, "a.example.test", "tok")
	_, lockOK, lockErr := s.LockSelf(ctx, "enroll.example.test")
	if certOK || httpFound || lockOK {
		t.Fatalf("a failed store reported a hit: cert=%v http=%v lock=%v", certOK, httpFound, lockOK)
	}
	for name, err := range map[string]error{
		"PutTLSALPN":         s.PutTLSALPN(ctx, "a.example.test", "k"),
		"DeleteTLSALPN":      s.DeleteTLSALPN(ctx, "a.example.test", "k"),
		"TLSALPNCertificate": certErr,
		"PutHTTP":            s.PutHTTP(ctx, "a.example.test", "tok", "k"),
		"DeleteHTTP":         s.DeleteHTTP(ctx, "a.example.test", "tok", "k"),
		"HTTPKeyAuth":        httpErr,
		"LockSelf":           lockErr,
	} {
		if !errors.Is(err, ErrChallengeStore) {
			t.Errorf("%s error = %v, want it to wrap ErrChallengeStore", name, err)
		}
	}
}

type commandCtxRecorder struct {
	mu   sync.Mutex
	seen []commandCtx
}

type commandCtx struct {
	name      string
	remaining time.Duration
	deadline  bool
	cancelled bool
}

func (h *commandCtxRecorder) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *commandCtxRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (h *commandCtxRecorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		dl, ok := ctx.Deadline()
		h.mu.Lock()
		h.seen = append(h.seen, commandCtx{name: cmd.Name(), remaining: time.Until(dl), deadline: ok, cancelled: ctx.Err() != nil})
		h.mu.Unlock()
		return next(ctx, cmd)
	}
}

func (h *commandCtxRecorder) reset() {
	h.mu.Lock()
	h.seen = nil
	h.mu.Unlock()
}

func (h *commandCtxRecorder) commands() []commandCtx {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]commandCtx(nil), h.seen...)
}

func TestChallengeStore_LockSelf(t *testing.T) {
	t.Parallel()
	s, mr, rdb := newTestChallengeStore(t)
	hook := &commandCtxRecorder{}
	rdb.AddHook(hook)
	ctx, cancel := context.WithCancel(context.Background())
	unlock, ok, err := s.LockSelf(ctx, "enroll.example.test")
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	if got := mr.TTL(selfLockKey("enroll.example.test")); got != selfLockTTL {
		t.Fatalf("lock TTL = %s, want %s", got, selfLockTTL)
	}
	if _, ok, err := s.LockSelf(context.Background(), "enroll.example.test"); ok || err != nil {
		t.Fatalf("second lock: ok=%v err=%v, want busy", ok, err)
	}
	cancel()
	hook.reset()
	if err := unlock(); err != nil {
		t.Fatalf("unlock after the lock ctx was cancelled: %v", err)
	}
	unlockCmds := hook.commands()
	if len(unlockCmds) == 0 {
		t.Fatal("unlock issued no Valkey command")
	}
	for _, c := range unlockCmds {
		if !c.deadline || c.cancelled || c.remaining <= 0 || c.remaining > selfUnlockTimeout {
			t.Fatalf("unlock %s ran with deadline=%v cancelled=%v remaining=%s, want a live ctx bounded by %s",
				c.name, c.deadline, c.cancelled, c.remaining, selfUnlockTimeout)
		}
	}
	if mr.Exists(selfLockKey("enroll.example.test")) {
		t.Fatal("unlock did not release the lock")
	}

	staleUnlock, ok, err := s.LockSelf(context.Background(), "enroll.example.test")
	if err != nil || !ok {
		t.Fatalf("relock: ok=%v err=%v", ok, err)
	}
	if err := mr.Set(selfLockKey("enroll.example.test"), "new-holder"); err != nil {
		t.Fatal(err)
	}
	if err := staleUnlock(); err != nil {
		t.Fatal(err)
	}
	if got, err := mr.Get(selfLockKey("enroll.example.test")); err != nil || got != "new-holder" {
		t.Fatalf("a stale unlock removed the new holder's lock (now %q, err %v)", got, err)
	}

	unreachableUnlock, ok, err := s.LockSelf(context.Background(), "control.example.test")
	if err != nil || !ok {
		t.Fatalf("lock before closing Valkey: ok=%v err=%v", ok, err)
	}
	mr.Close()
	start := time.Now()
	if err := unreachableUnlock(); err == nil {
		t.Fatal("unlock against an unreachable Valkey must fail")
	}
	if elapsed := time.Since(start); elapsed > selfUnlockTimeout+time.Second {
		t.Fatalf("unlock took %s, want at most %s", elapsed, selfUnlockTimeout+time.Second)
	}
}
