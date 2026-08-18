package acme

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
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

func newChain(t *testing.T, cfg ChainConfig, cas ...caIssuer) (*chainIssuer, *limit.Limiter) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	lim := limit.NewLimiter(rdb, 1, 1, 1)
	lim.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	cfg.Limiter = lim
	if cfg.LEWeeklyBudget == 0 {
		cfg.LEWeeklyBudget = 50
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
	_ = lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour)
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
	_, _, _ = ch.Obtain(context.Background(), nil, "t")
	if d, _ := lim.CACooldown(context.Background(), CALetsEncrypt); d <= 0 {
		t.Error("LE should be cooling after a rate-limited answer")
	}
}

func TestAllCoolingReturnsRetryable(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	_ = lim.SetCACooldown(context.Background(), CALetsEncrypt, 2*time.Hour)
	_ = lim.SetCACooldown(context.Background(), CAGTS, 30*time.Minute)
	_, _, err := ch.Obtain(context.Background(), nil, "t")
	var ie *IssuerError
	if !asIssuerError(err, &ie) || ie.Class != ClassRateLimited {
		t.Fatalf("all cooling should be retryable rate-limited, got %v", err)
	}
	if ie.Retry != 30*time.Minute {
		t.Errorf("retry-after should be the shortest cooldown (30m), got %s", ie.Retry)
	}
}

func TestLEBudgetSkipsToGTS(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{LEWeeklyBudget: 1}, le, gts)
	// Exhaust the LE budget.
	_, _ = lim.ConsumeLEOrder(context.Background(), 1)
	_, info, err := ch.Obtain(context.Background(), nil, "t")
	if err != nil || info.CA != CAGTS {
		t.Fatalf("exhausted LE budget should skip to GTS, got %+v %v", info, err)
	}
	if le.calls != 0 {
		t.Error("LE must not be attempted with no budget")
	}
}

func TestLEBudgetRefundOnFailure(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt, err: transient(nil)}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{LEWeeklyBudget: 1}, le, gts)
	_, info, _ := ch.Obtain(context.Background(), nil, "t")
	if info.CA != CAGTS {
		t.Fatalf("LE failed → GTS, got %+v", info)
	}
	// The reserved LE slot was refunded, so a fresh reserve still succeeds within budget 1.
	if ok, _ := lim.ConsumeLEOrder(context.Background(), 1); !ok {
		t.Error("failed LE order must have refunded the budget")
	}
}

func TestRenewMigratesNonLEToLE(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, _ := newChain(t, ChainConfig{LEWeeklyBudget: 50}, le, gts)
	_, info, err := ch.Renew(context.Background(), nil, "t", store.CertInfo{CA: CAGTS})
	if err != nil || info.CA != CALetsEncrypt {
		t.Fatalf("non-LE renewal should migrate to LE, got %+v %v", info, err)
	}
}

func TestRenewLEIsBudgetExempt(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	ch, lim := newChain(t, ChainConfig{LEWeeklyBudget: 0}, le) // zero budget
	_, info, err := ch.Renew(context.Background(), nil, "t", store.CertInfo{CA: CALetsEncrypt})
	if err != nil || info.CA != CALetsEncrypt {
		t.Fatalf("LE renewal must be budget-exempt, got %+v %v", info, err)
	}
	if le.calls != 1 {
		t.Errorf("LE should have been attempted once (budget-exempt), calls=%d", le.calls)
	}
	_ = lim
}

func TestShouldRenewFixedCadence(t *testing.T) {
	gts := &fakeCA{caID: CAGTS}
	ch, _ := newChain(t, ChainConfig{}, gts)
	cur := store.CertInfo{CA: CAGTS, NotBefore: time.Unix(1_700_000_000, 0)}
	// now = NotBefore + 111h → not yet.
	ch.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0).Add(111 * time.Hour) })
	if due, _, _ := ch.ShouldRenew(context.Background(), cur); due {
		t.Error("should not renew before 112h")
	}
	ch.SetClock(func() time.Time { return time.Unix(1_700_000_000, 0).Add(113 * time.Hour) })
	if due, _, _ := ch.ShouldRenew(context.Background(), cur); !due {
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
