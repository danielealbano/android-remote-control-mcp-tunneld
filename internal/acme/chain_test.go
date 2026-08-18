package acme

import (
	"context"
	"crypto/x509"
	"strings"
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
	_ = lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour) // LE has an active retry-after
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
	if d, _ := lim.CACooldown(context.Background(), CALetsEncrypt); d < 30*time.Minute {
		t.Errorf("LE retry-after should honor the 30m Retry-After, got %s", d)
	}
	if gts.calls != 1 {
		t.Errorf("GTS should have been attempted once, calls=%d", gts.calls)
	}
}

func TestAllCoolingMessageIsQuotaExhausted(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	ch, lim := newChain(t, ChainConfig{}, le)
	_ = lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour)
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

// TestObtainSelfSelfCert covers the plan's "ObtainSelf self-cert" row: a server-side key + cert for a
// reserved host, subject to the per-CA cooldowns, and never touching per-tunnel issuance state.
func TestObtainSelfSelfCert(t *testing.T) {
	le := &fakeCA{caID: CALetsEncrypt}
	gts := &fakeCA{caID: CAGTS}
	ch, lim := newChain(t, ChainConfig{}, le, gts)
	_ = lim.SetCACooldown(context.Background(), CALetsEncrypt, time.Hour) // LE cooling → GTS

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
	// The per-tunnel issuance counter is untouched (it is keyed on tunnel names in enroll, not here).
	if ok, _ := lim.IssuanceAllowed(context.Background(), "enroll.example.test", 1); !ok {
		t.Fatal("ObtainSelf must not consume the per-tunnel issuance counter")
	}
}
