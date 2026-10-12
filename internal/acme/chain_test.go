package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type fakeCA struct {
	caID  string
	err   error
	calls int
}

func (f *fakeCA) obtain(_ context.Context, _ *x509.CertificateRequest, _ string) ([]byte, store.CertInfo, error) {
	f.calls++
	if f.err != nil {
		return nil, store.CertInfo{}, f.err
	}
	return []byte("CERT"), store.CertInfo{CA: f.caID, Serial: "01", NotBefore: time.Unix(1_700_000_000, 0)}, nil
}
func (f *fakeCA) shouldRenew(_ context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error) {
	at := cur.NotBefore.Add(112 * time.Hour)
	return !now.Before(at), at, nil
}
func (f *fakeCA) id() string { return f.caID }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func newChain(t *testing.T, cfg ChainConfig, cas ...caIssuer) (*chainIssuer, *limit.Limiter) {
	t.Helper()
	mr := miniredis.RunT(t)
	return newChainOn(t, mr, cfg, cas...)
}

func newChainOn(t *testing.T, mr *miniredis.Miniredis, cfg ChainConfig, cas ...caIssuer) (*chainIssuer, *limit.Limiter) {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	lim := limit.NewLimiter(rdb, 1, 1, 1, time.Hour)
	lim.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	cfg.Limiter = lim
	if cfg.Logger == nil {
		cfg.Logger = testLogger()
	}
	if cfg.CooldownDefault == 0 {
		cfg.CooldownDefault = time.Hour
	}
	if cfg.BackoffInitial == 0 {
		cfg.BackoffInitial = time.Minute
	}
	if cfg.BackoffMax == 0 {
		cfg.BackoffMax = 6 * time.Hour
	}
	cfg.RenewMargin = 48 * time.Hour
	cfg.ShortlivedLifetime = 160 * time.Hour
	ch := NewChainIssuer(cfg, cas...)
	ch.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	return ch, lim
}

func TestSpilloverToZeroSSL(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: rateLimited(0, nil)}
	gts := &fakeCA{caID: CAGTS, err: transient(nil)}
	zs := &fakeCA{caID: CAZeroSSL}
	ch, _ := newChain(t, ChainConfig{}, le, gts, zs)
	_, info, err := ch.Obtain(context.Background(), nil, "t")
	if err != nil || info.CA != CAZeroSSL {
		t.Fatalf("expected zerossl, got info=%+v err=%v", info, err)
	}
}

func TestSpilloverStopsOnPermanent(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: permanent(nil)}
	gts := &fakeCA{caID: CAGTS}
	ch, _ := newChain(t, ChainConfig{}, le, gts)
	if _, _, err := ch.Obtain(context.Background(), nil, "t"); err == nil {
		t.Fatal("permanent should stop and return an error")
	}
	if gts.calls != 0 {
		t.Error("GTS must not be attempted after an LE permanent failure")
	}
}

func TestCooldownSkipsCA(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	if err := lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, info, err := ch.Obtain(context.Background(), nil, "t")
	if err != nil || info.CA != CAGTS {
		t.Fatalf("cooling LE should be skipped, got %+v %v", info, err)
	}
	if le.calls != 0 {
		t.Error("a cooling CA must not be attempted")
	}
}

func TestRateLimitedSetsCooldown(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: rateLimited(0, nil)}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	if _, _, err := ch.Obtain(context.Background(), nil, "t"); err != nil {
		t.Fatal(err)
	}
	if d, err := lim.CACooldown(context.Background(), CALetsEncrypt); err != nil {
		t.Fatal(err)
	} else if d <= 0 {
		t.Error("LE should be cooling after a rate-limited answer")
	}
}

func TestAllCoolingReturnsRetryable(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	if err := lim.SetCACooldown(context.Background(), CALetsEncrypt, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := lim.SetCACooldown(context.Background(), CAGTS, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	_, _, err := ch.Obtain(context.Background(), nil, "t")
	var ie *IssuerError
	if !asIssuerError(err, &ie) || ie.Class != ClassRateLimited {
		t.Fatalf("all cooling should be retryable rate-limited, got %v", err)
	}
	if ie.Retry != 30*time.Minute {
		t.Errorf("retry-after should be the shortest cooldown (30m), got %s", ie.Retry)
	}
}

func TestRenewTriesLEFirst(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, _ := newChain(t, ChainConfig{}, le, gts)
	// A name currently on GTS renews: LE is tried FIRST (opportunistic migration), no budget involved.
	_, info, err := ch.Renew(context.Background(), nil, "t", store.CertInfo{CA: CAGTS})
	if err != nil || info.CA != CALetsEncrypt {
		t.Fatalf("renewal should try LE first and migrate, got %+v %v", info, err)
	}
	if le.calls != 1 || gts.calls != 0 {
		t.Errorf("LE should be attempted once and GTS not at all, le=%d gts=%d", le.calls, gts.calls)
	}
}

func TestRenewSpillsWhenLECooling(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	if err := lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour); err != nil { // LE has an active retry-after
		t.Fatal(err)
	}
	_, info, err := ch.Renew(context.Background(), nil, "t", store.CertInfo{CA: CAGTS})
	if err != nil || info.CA != CAGTS {
		t.Fatalf("a cooling LE should be skipped and renewal spill to GTS, got %+v %v", info, err)
	}
	if le.calls != 0 {
		t.Error("a cooling LE must not be attempted on renewal")
	}
}

func TestRateLimitedSpillsAndSetsRetryAfter(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: rateLimited(30*time.Minute, nil)}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	// LE answers rate-limited → its retry-after is set (honoring Retry-After) and the order spills to GTS.
	_, info, err := ch.Obtain(context.Background(), nil, "t")
	if err != nil || info.CA != CAGTS {
		t.Fatalf("rate-limited LE should spill to GTS, got %+v %v", info, err)
	}
	if d, err := lim.CACooldown(context.Background(), CALetsEncrypt); err != nil {
		t.Fatal(err)
	} else if d < 29*time.Minute || d > 30*time.Minute {
		t.Errorf("LE cooldown must honor the 30m Retry-After AS-IS (not the 1h default), got %s", d)
	}
	if gts.calls != 1 {
		t.Errorf("GTS should have been attempted once, calls=%d", gts.calls)
	}
}

func TestAllCoolingMessageIsQuotaExhausted(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	ch, lim := newChain(t, ChainConfig{}, le)
	if err := lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, _, err := ch.Obtain(context.Background(), nil, "t")
	if err == nil || !strings.Contains(err.Error(), "quota exhausted, retry later") {
		t.Fatalf("all-cooling error should be the quota-exhausted message, got %v", err)
	}
}

func TestShouldRenewFixedCadence(t *testing.T) {
	gts := &fakeCA{caID: CAGTS}
	ch, _ := newChain(t, ChainConfig{}, gts)
	cur := store.CertInfo{CA: CAGTS, NotBefore: time.Unix(1_700_000_000, 0)}
	// now = NotBefore + 111h → not yet.
	ch.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0).Add(111 * time.Hour) })
	if due, _, err := ch.ShouldRenew(context.Background(), cur); err != nil {
		t.Fatal(err)
	} else if due {
		t.Error("should not renew before 112h")
	}
	ch.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0).Add(113 * time.Hour) })
	if due, _, err := ch.ShouldRenew(context.Background(), cur); err != nil {
		t.Fatal(err)
	} else if !due {
		t.Error("should renew after 112h")
	}
}

func TestBackoffDoubles(t *testing.T) {
	if backoff(time.Minute, 6*time.Hour, 1) != time.Minute {
		t.Error("streak 1 = initial")
	}
	if backoff(time.Minute, 6*time.Hour, 3) != 4*time.Minute {
		t.Error("streak 3 = 4×initial")
	}
	if backoff(time.Minute, 6*time.Hour, 20) != 6*time.Hour {
		t.Error("large streak caps at max")
	}
}

// TestObtainSelfSelfCert covers the plan's "ObtainSelf self-cert" row: a server-side key + cert for a
// reserved host, subject to the per-CA cooldowns, and never touching per-tunnel issuance state.
func TestObtainSelfSelfCert(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	if err := lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour); err != nil { // LE cooling → GTS
		t.Fatal(err)
	}

	certPEM, keyPEM, info, err := ch.ObtainSelf(context.Background(), "enroll.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("ObtainSelf must return a cert AND a server-side key")
	}
	if info.CA != CAGTS || le.calls != 0 {
		t.Fatalf("a cooling LE must be skipped for the self cert, got CA=%s leCalls=%d", info.CA, le.calls)
	}
	// The per-tunnel issuance counter is untouched (it is keyed on tunnel names in enroll, not here): a
	// fresh Begin against cap 1 still admits, which it could not if ObtainSelf had committed a success.
	if ok, _, err := lim.IssuanceBegin(context.Background(), "enroll.example.test", 1); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("ObtainSelf must not consume the per-tunnel issuance counter")
	}
}

// TestAllFailInRunRetryAfterUsesBackoff covers the shortest-remaining-cooldown rule when every CA
// fails DURING the run (none pre-cooling): the Retry-After must reflect the backoff the failures just
// set (~= --acme-backoff-initial), never the 1h --acme-cooldown-default.
func TestAllFailInRunRetryAfterUsesBackoff(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: transient(nil)}
	gts := &fakeCA{caID: CAGTS, err: transient(nil)}
	ch, _ := newChain(t, ChainConfig{}, le, gts) // backoff-initial 1m, cooldown-default 1h
	_, _, err := ch.Obtain(context.Background(), nil, "t")
	var ie *IssuerError
	if !asIssuerError(err, &ie) || ie.Class != ClassRateLimited {
		t.Fatalf("all-fail should be retryable rate-limited, got %v", err)
	}
	if ie.Retry != time.Minute {
		t.Fatalf("Retry-After must be the in-run backoff (1m), got %s", ie.Retry)
	}
}

// TestMixedPreCoolingAndInRunFailurePicksShortest: a long pre-existing cooldown must not mask a
// shorter cooldown set by an in-run failure.
func TestMixedPreCoolingAndInRunFailurePicksShortest(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS, err: transient(nil)}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	if err := lim.SetCACooldown(context.Background(), CALetsEncrypt, 30*time.Minute); err != nil { // pre-cooling
		t.Fatal(err)
	}
	_, _, err := ch.Obtain(context.Background(), nil, "t")
	var ie *IssuerError
	if !asIssuerError(err, &ie) || ie.Retry != time.Minute {
		t.Fatalf("Retry-After must be the SHORTEST cooldown (in-run 1m beats pre-cooling 30m), got %v", err)
	}
}

// TestShortRetryAfterHonoredAsIs: a CA saying "retry in 30s" must cool for ~30s — never be inflated
// to the 1h --acme-cooldown-default (the default applies only when the CA sent no hint).
func TestShortRetryAfterHonoredAsIs(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: rateLimited(30*time.Second, nil)}
	gts := &fakeCA{caID: CAGTS, err: rateLimited(45*time.Second, nil)}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	_, _, err := ch.Obtain(context.Background(), nil, "t")
	var ie *IssuerError
	if !asIssuerError(err, &ie) || ie.Class != ClassRateLimited {
		t.Fatalf("all rate-limited should be retryable, got %v", err)
	}
	// The phone is told the SHORTEST honored Retry-After (~30s), not the 1h default.
	if ie.Retry != 30*time.Second {
		t.Fatalf("Retry-After must be the shortest honored CA hint (30s), got %s", ie.Retry)
	}
	if d, err := lim.CACooldown(context.Background(), CALetsEncrypt); err != nil {
		t.Fatal(err)
	} else if d > 30*time.Second {
		t.Fatalf("LE cooldown must be the honored 30s, got %s", d)
	}
}

type recordingChainRecorder struct {
	mu        sync.Mutex
	issues    []string
	cooldowns []string
}

func (r *recordingChainRecorder) ACMECooldown(ca string) {
	r.mu.Lock()
	r.cooldowns = append(r.cooldowns, ca)
	r.mu.Unlock()
}

func (r *recordingChainRecorder) ACMEIssue(ca, result string) {
	r.mu.Lock()
	r.issues = append(r.issues, ca+" "+result)
	r.mu.Unlock()
}

func (r *recordingChainRecorder) ACMERenew(string, string) {}

func assertNoCAFailureState(t *testing.T, lim *limit.Limiter, ca string) {
	t.Helper()
	ctx := context.Background()
	if cool, err := lim.CACooldown(ctx, ca); err != nil || cool != 0 {
		t.Fatalf("%s cooldown = %s (err %v), want none", ca, cool, err)
	}
	if n, err := lim.BumpCAFailures(ctx, ca, time.Hour); err != nil || n != 1 {
		t.Fatalf("%s failure streak before this probe = %d (err %v), want 0", ca, n-1, err)
	}
}

func TestChain_LocalErrorSkipsCooldown(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: local(localChallengeRetry, ErrChallengePending)}
	gts := &fakeCA{caID: CAGTS}
	rec := &recordingChainRecorder{}
	ch, lim := newChain(t, ChainConfig{Recorder: rec}, le, gts)
	_, _, err := ch.Obtain(context.Background(), nil, "name")
	var ie *IssuerError
	if !errors.As(err, &ie) || ie.Class != ClassRateLimited || ie.Retry != localChallengeRetry {
		t.Fatalf("error = %v, want rate-limited with Retry %s", err, localChallengeRetry)
	}
	if gts.calls != 0 {
		t.Fatalf("the chain must stop on a local error, but GTS was called %d times", gts.calls)
	}
	if len(rec.issues) != 0 || len(rec.cooldowns) != 0 {
		t.Fatalf("a local error must record nothing, got issues=%v cooldowns=%v", rec.issues, rec.cooldowns)
	}
	assertNoCAFailureState(t, lim, CALetsEncrypt)
}

type cancellingCA struct {
	caID   string
	cancel context.CancelFunc
	err    error
	calls  int
}

func (c *cancellingCA) obtain(ctx context.Context, _ *x509.CertificateRequest, _ string) ([]byte, store.CertInfo, error) {
	c.calls++
	c.cancel()
	if c.err != nil {
		return nil, store.CertInfo{}, c.err
	}
	return nil, store.CertInfo{}, transient(ctx.Err())
}

func (c *cancellingCA) shouldRenew(context.Context, store.CertInfo, time.Time) (bool, time.Time, error) {
	return false, time.Time{}, nil
}

func (c *cancellingCA) id() string { return c.caID }

func TestChain_StopsWhenContextDone(t *testing.T) {
	t.Run("cancelled before the call", func(t *testing.T) {
		le := &fakeCA{caID: CALetsEncrypt}
		gts := &fakeCA{caID: CAGTS}
		rec := &recordingChainRecorder{}
		ch, lim := newChain(t, ChainConfig{Recorder: rec}, le, gts)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := ch.Obtain(ctx, nil, "name")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if le.calls != 0 || gts.calls != 0 || len(rec.issues) != 0 {
			t.Fatalf("no CA may be tried: le=%d gts=%d issues=%v", le.calls, gts.calls, rec.issues)
		}
		assertNoCAFailureState(t, lim, CALetsEncrypt)
	})
	t.Run("cancelled while the first CA runs", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		le := &cancellingCA{caID: CALetsEncrypt, cancel: cancel}
		gts := &fakeCA{caID: CAGTS}
		rec := &recordingChainRecorder{}
		ch, lim := newChain(t, ChainConfig{Recorder: rec}, le, gts)
		_, _, err := ch.Obtain(ctx, nil, "name")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if le.calls != 1 || gts.calls != 0 {
			t.Fatalf("only the in-flight CA may have run: le=%d gts=%d", le.calls, gts.calls)
		}
		if len(rec.issues) != 0 || len(rec.cooldowns) != 0 {
			t.Fatalf("an interrupted attempt must record nothing, got issues=%v cooldowns=%v", rec.issues, rec.cooldowns)
		}
		assertNoCAFailureState(t, lim, CALetsEncrypt)
	})
	t.Run("local error while the ctx is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		le := &cancellingCA{caID: CALetsEncrypt, cancel: cancel, err: local(localChallengeRetry, ErrChallengePending)}
		gts := &fakeCA{caID: CAGTS}
		rec := &recordingChainRecorder{}
		ch, lim := newChain(t, ChainConfig{Recorder: rec}, le, gts)
		_, _, err := ch.Obtain(ctx, nil, "name")
		var ie *IssuerError
		if !errors.Is(err, context.Canceled) || !errors.As(err, &ie) || ie.Class == ClassLocal {
			t.Fatalf("error = %v, want a context.Canceled error that is not of class %s", err, ClassLocal)
		}
		if !strings.Contains(err.Error(), ErrChallengePending.Error()) {
			t.Fatalf("error = %v, want the interrupted CA order's error carried in its text", err)
		}
		if gts.calls != 0 || len(rec.issues) != 0 || len(rec.cooldowns) != 0 {
			t.Fatalf("an interrupted attempt must record nothing: gts=%d issues=%v cooldowns=%v", gts.calls, rec.issues, rec.cooldowns)
		}
		assertNoCAFailureState(t, lim, CALetsEncrypt)
	})
}

func TestChain_LogsEachCAFailure(t *testing.T) {
	var buf bytes.Buffer
	le := &fakeCA{caID: CALetsEncrypt, err: rateLimited(0, errors.New("le refused the order"))}
	gts := &fakeCA{caID: CAGTS, err: transient(errors.New("gts unreachable"))}
	zs := &fakeCA{caID: CAZeroSSL}
	ch, _ := newChain(t, ChainConfig{Logger: slog.New(slog.NewTextHandler(&buf, nil))}, le, gts, zs)
	if _, _, err := ch.Obtain(context.Background(), nil, "name"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`msg="acme CA order failed" ca=letsencrypt name=name class=rate-limited err="acme: rate limited: le refused the order"`,
		`msg="acme CA order failed" ca=gts name=name class=transient err="acme: transient: gts unreachable"`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("log is missing %s; log = %q", want, buf.String())
		}
	}
}

func TestChain_LogsBookkeepingErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{name: "failed order", err: transient(errors.New("down")), want: []string{
			"acme CA cooldown check failed", "acme CA failure-streak bump failed", "acme CA cooldown write failed",
		}},
		{name: "rate-limited order", err: rateLimited(time.Minute, errors.New("slow down")), want: []string{
			"acme CA cooldown check failed", "acme CA cooldown write failed",
		}},
		{name: "successful order", want: []string{"acme CA cooldown check failed", "acme CA failure-streak reset failed"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			mr := miniredis.RunT(t)
			ch, _ := newChainOn(t, mr, ChainConfig{Logger: slog.New(slog.NewTextHandler(&buf, nil))},
				&fakeCA{caID: CALetsEncrypt, err: tc.err})
			mr.Close()
			_, _, err := ch.Obtain(context.Background(), nil, "name")
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("Obtain error = %v, want error %v", err, tc.err != nil)
			}
			for _, want := range tc.want {
				if !strings.Contains(buf.String(), `msg="`+want) {
					t.Fatalf("log is missing %q; log = %q", want, buf.String())
				}
			}
		})
	}
}
