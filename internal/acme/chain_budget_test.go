package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

var frozenNow = time.Unix(1_700_000_000, 0)

type accountChain struct {
	ch  *chainIssuer
	lim *limit.Limiter
	rdb *redis.Client
	mr  *miniredis.Miniredis
	rec *recordingChainRecorder
	log *lockedBuffer
}

func newAccountChain(t *testing.T, cfg ChainConfig, accounts ...*account) *accountChain {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	lim := limit.NewLimiter(rdb, 1, 1, 1, time.Hour)
	lim.SetClock(func() time.Time { return frozenNow })
	ac := &accountChain{lim: lim, rdb: rdb, mr: mr, rec: &recordingChainRecorder{}, log: &lockedBuffer{}}
	cfg.Limiter = lim
	cfg.Recorder = ac.rec
	cfg.Logger = slog.New(slog.NewTextHandler(ac.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg.CooldownDefault, cfg.BackoffInitial, cfg.BackoffMax = time.Hour, time.Minute, 6*time.Hour
	cfg.RenewMargin, cfg.ShortlivedLifetime = 48*time.Hour, 160*time.Hour
	if cfg.NodeID == "" {
		cfg.NodeID = "node-test"
	}
	if cfg.Nodes == nil {
		cfg.Nodes = fakeNodes{ids: []string{"node-test"}}
	}
	if cfg.Budgets == (Budgets{}) {
		cfg.Budgets = smallBudgets()
	}
	if cfg.Rand == nil {
		cfg.Rand = func(int) int { return 0 }
	}
	ch, err := NewChainIssuer(cfg, accounts...)
	if err != nil {
		t.Fatal(err)
	}
	ac.ch = ch
	ac.ch.SetClock(func() time.Time { return frozenNow })
	return ac
}

func smallBudgets() Budgets {
	r := limit.Rate{Count: 10, Period: time.Hour, Burst: 10}
	return Budgets{Domain: "example.test", LEDomain: r, LEOrders: r, LEName: r,
		GTSOrders: r, GTSRequests: r, GTSCertPolls: r, ZeroSSLOrders: r, ZeroSSLRequests: r}
}

func (ac *accountChain) level(t *testing.T, b limit.Bucket) float64 {
	t.Helper()
	lv, err := ac.lim.ACMEBudgetLevel(context.Background(), b, []string{"node-test"})
	if err != nil {
		t.Fatal(err)
	}
	return lv
}

func (ac *accountChain) spend(t *testing.T, ca string, b limit.Bucket, n int) {
	t.Helper()
	for range n {
		if err := ac.lim.CommitACME(context.Background(), ca, b, "node-test", "pre"); err != nil {
			t.Fatal(err)
		}
	}
}

type trackingFake struct {
	caID       string
	label      string
	created    bool
	finalized  bool
	block      bool
	err        error
	onObtain   func(ctx context.Context)
	cleanupRan *atomic.Bool
	calls      atomic.Int32
	order      *callLog
}

type callLog struct {
	mu    sync.Mutex
	names []string
}

func (l *callLog) add(n string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, n)
}

func (l *callLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.names)
}

func (f *trackingFake) obtain(ctx context.Context, _ *x509.CertificateRequest, _ string) ([]byte, store.CertInfo, error) {
	f.calls.Add(1)
	if f.order != nil {
		f.order.add(f.label)
	}
	if f.onObtain != nil {
		f.onObtain(ctx)
	}
	if tr := trackFrom(ctx); tr != nil {
		if f.created {
			tr.setOrder("https://ca.example.test/order/1", "https://ca.example.test/finalize/1")
		}
		if f.finalized {
			tr.markFinalized(time.Now())
		}
		if f.cleanupRan != nil {
			tr.onAbandon(func(context.Context) error { f.cleanupRan.Store(true); return nil })
		}
	}
	if f.block {
		<-ctx.Done()
		if tr := trackFrom(ctx); tr != nil {
			tr.abandon()
		}
		return nil, store.CertInfo{}, transient(ctx.Err())
	}
	if f.err != nil {
		return nil, store.CertInfo{}, f.err
	}
	return []byte("CERT"), store.CertInfo{CA: f.caID, Serial: "01"}, nil
}

func (f *trackingFake) shouldRenew(_ context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error) {
	at := cur.NotBefore.Add(112 * time.Hour)
	return !now.Before(at), at, nil
}

func (f *trackingFake) id() string { return f.caID }

func acct(f *trackingFake, id string, timeout time.Duration) *account {
	label := f.label
	if label == "" {
		label = "local"
	}
	return &account{ca: f.caID, id: id, label: label, timeout: timeout, issuer: f}
}

func tlsCSR(t *testing.T, cn string, sans ...string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: sans}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestChain_SkipsWithoutBudget(t *testing.T) {
	t.Parallel()
	le := &trackingFake{caID: CALetsEncrypt}
	gts := &trackingFake{caID: CAGTS}
	leAcct := acct(le, "le-1", time.Minute)
	ac := newAccountChain(t, ChainConfig{}, leAcct, acct(gts, "gts-1", time.Minute))
	ac.spend(t, CALetsEncrypt, smallBudgets().leOrders(leAcct), 10)
	_, info, err := ac.ch.Obtain(context.Background(), nil, "p")
	if err != nil || info.CA != CAGTS {
		t.Fatalf("Obtain = %+v, %v; want GTS", info, err)
	}
	if le.calls.Load() != 0 {
		t.Fatal("an account without budget must get no request")
	}
}

func TestChain_SkipsUnderWaitUntil(t *testing.T) {
	t.Parallel()
	le := &trackingFake{caID: CALetsEncrypt}
	gts := &trackingFake{caID: CAGTS}
	ac := newAccountChain(t, ChainConfig{}, acct(le, "le-1", time.Minute), acct(gts, "gts-1", time.Minute))
	if err := ac.lim.SetCACooldown(context.Background(), "le-1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, info, err := ac.ch.Obtain(context.Background(), nil, "p"); err != nil || info.CA != CAGTS {
		t.Fatalf("Obtain = %+v, %v; want GTS", info, err)
	}
	if le.calls.Load() != 0 {
		t.Fatal("an account under a wait-until must get no request")
	}
}

func TestChain_AllUnavailable_RetryAfter(t *testing.T) {
	t.Parallel()
	le := &trackingFake{caID: CALetsEncrypt}
	gts := &trackingFake{caID: CAGTS}
	leAcct, gtsAcct := acct(le, "le-1", time.Minute), acct(gts, "gts-1", time.Minute)
	budgets := smallBudgets()
	budgets.LEOrders = limit.Rate{Count: 1, Period: time.Hour, Burst: 1}
	budgets.GTSOrders = limit.Rate{Count: 1, Period: 30 * time.Minute, Burst: 1}
	ac := newAccountChain(t, ChainConfig{Budgets: budgets, Rand: func(int) int { return 4 }}, leAcct, gtsAcct)
	ac.spend(t, CALetsEncrypt, budgets.leOrders(leAcct), 1)
	ac.spend(t, CAGTS, budgets.gtsOrders(gtsAcct), 1)
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p")
	var ie *IssuerError
	if !errors.As(err, &ie) || ie.Class != ClassRateLimited || ie.Retry != 30*time.Minute+5*time.Second {
		t.Fatalf("Obtain = %v, want rate-limited with the earliest slot (30 m) + 1+Rand(10) s", err)
	}
	if le.calls.Load()+gts.calls.Load() != 0 {
		t.Fatal("no account may get a request")
	}
}

func TestChain_GTSOrderedByBudget(t *testing.T) {
	t.Parallel()
	t.Run("most remaining budget first", func(t *testing.T) {
		calls := &callLog{}
		g1 := &trackingFake{caID: CAGTS, label: "gts-1", order: calls}
		g2 := &trackingFake{caID: CAGTS, label: "gts-2", order: calls, err: transient(errors.New("down"))}
		g3 := &trackingFake{caID: CAGTS, label: "gts-3", order: calls, err: transient(errors.New("down"))}
		a1, a2, a3 := acct(g1, "g1", time.Minute), acct(g2, "g2", time.Minute), acct(g3, "g3", time.Minute)
		ac := newAccountChain(t, ChainConfig{}, a1, a2, a3)
		ac.spend(t, CAGTS, smallBudgets().gtsOrders(a1), 6)
		ac.spend(t, CAGTS, smallBudgets().gtsOrders(a2), 2)
		if _, _, err := ac.ch.Obtain(context.Background(), nil, "p"); err != nil {
			t.Fatal(err)
		}
		if got := calls.get(); !slices.Equal(got, []string{"gts-3", "gts-2", "gts-1"}) {
			t.Fatalf("GTS accounts tried in %v, want the most remaining order budget first", got)
		}
	})
	t.Run("equal levels keep the shuffled order", func(t *testing.T) {
		calls := &callLog{}
		fakes := []*trackingFake{
			{caID: CAGTS, label: "gts-1", order: calls, err: transient(errors.New("down"))},
			{caID: CAGTS, label: "gts-2", order: calls, err: transient(errors.New("down"))},
			{caID: CAGTS, label: "gts-3", order: calls, err: transient(errors.New("down"))},
		}
		ac := newAccountChain(t, ChainConfig{}, acct(fakes[0], "g1", time.Minute), acct(fakes[1], "g2", time.Minute), acct(fakes[2], "g3", time.Minute))
		if _, _, err := ac.ch.Obtain(context.Background(), nil, "p"); err == nil {
			t.Fatal("every account failed, the run must fail")
		}
		if got := calls.get(); !slices.Equal(got, []string{"gts-2", "gts-3", "gts-1"}) {
			t.Fatalf("GTS accounts tried in %v, want the Rand-shuffled order [gts-2 gts-3 gts-1]", got)
		}
	})
}

func leBuckets(a *account, fqdn string) (orders, name, domain limit.Bucket) {
	b := smallBudgets()
	return b.leOrders(a), b.leName(fqdn), b.leDomain(fqdn)
}

func settleLevels(t *testing.T, f *trackingFake, timeout time.Duration) ([3]float64, bool, error) {
	t.Helper()
	var ran atomic.Bool
	f.cleanupRan = &ran
	a := acct(f, "le-1", timeout)
	ac := newAccountChain(t, ChainConfig{FinalizeGrace: 20 * time.Millisecond}, a)
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test")
	orders, name, domain := leBuckets(a, "p.example.test")
	return [3]float64{ac.level(t, orders), ac.level(t, name), ac.level(t, domain)}, ran.Load(), err
}

func TestChain_SettleSuccess(t *testing.T) {
	t.Parallel()
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, finalized: true}, time.Minute)
	if err != nil || levels != [3]float64{0.9, 0.9, 0.9} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want every bucket spent and no reservation left", levels, cleaned, err)
	}
}

func TestChain_SettleCreatedThenFailed(t *testing.T) {
	t.Parallel()
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, err: permanent(errors.New("bad csr"))}, time.Minute)
	if err == nil || levels != [3]float64{0.9, 1, 1} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want the order bucket spent and the success buckets released", levels, cleaned, err)
	}
}

func TestChain_SettleFailedBeforeCreate(t *testing.T) {
	t.Parallel()
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, err: transient(errors.New("down"))}, time.Minute)
	if err == nil || levels != [3]float64{1, 1, 1} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want everything released", levels, cleaned, err)
	}
}

func TestChain_SettleFinalizedAbandoned(t *testing.T) {
	t.Parallel()
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, finalized: true, block: true}, 50*time.Millisecond)
	if err == nil || levels != [3]float64{0.9, 0.9, 0.9} || !cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want every bucket spent and the challenge cleanups run", levels, cleaned, err)
	}
}

func TestChain_SettleFinalizedThenError(t *testing.T) {
	t.Parallel()
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, finalized: true, err: transient(errors.New("certificate wait"))}, time.Minute)
	if err == nil || levels != [3]float64{0.9, 0.9, 0.9} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want every bucket spent and no cleanup run", levels, cleaned, err)
	}
}

func TestChain_SettleWithoutReservation(t *testing.T) {
	t.Parallel()
	const ordersKey = "acme-budget:letsencrypt:orders:le-1"
	var ac *accountChain
	le := &trackingFake{caID: CALetsEncrypt, onObtain: func(ctx context.Context) {
		if err := ac.rdb.Del(ctx, ordersKey).Err(); err != nil {
			t.Errorf("unblock the orders bucket: %v", err)
		}
	}}
	a := acct(le, "le-1", time.Minute)
	ac = newAccountChain(t, ChainConfig{}, a)
	if err := ac.rdb.Set(context.Background(), ordersKey, "not-a-hash", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
		t.Fatal(err)
	}
	if le.calls.Load() != 1 || !strings.Contains(ac.log.String(), `msg="acme budget reservation failed (trying the account)"`) {
		t.Fatalf("a failed reservation must still try the account (calls %d); log = %q", le.calls.Load(), ac.log.String())
	}
	orders, name, domain := leBuckets(a, "p.example.test")
	if got := [3]float64{ac.level(t, orders), ac.level(t, name), ac.level(t, domain)}; got != [3]float64{0.9, 0.9, 0.9} {
		t.Fatalf("orders/name/domain levels = %v, want the success still spent", got)
	}
}

func TestChain_LERenewalExempt(t *testing.T) {
	t.Parallel()
	le := &trackingFake{caID: CALetsEncrypt}
	a := acct(le, "le-1", time.Minute)
	ac := newAccountChain(t, ChainConfig{}, a)
	if _, _, err := ac.ch.Renew(context.Background(), nil, "p.example.test", store.CertInfo{CA: CALetsEncrypt}); err != nil {
		t.Fatal(err)
	}
	orders, name, domain := leBuckets(a, "p.example.test")
	if got := [3]float64{ac.level(t, orders), ac.level(t, name), ac.level(t, domain)}; got != [3]float64{1, 0.9, 1} {
		t.Fatalf("orders/name/domain levels = %v, want only the name bucket drawn", got)
	}
}

func TestObtainSelf_LERenewalExempt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cur  store.CertInfo
		want [3]float64
	}{
		{name: "renewal of an LE cert", cur: store.CertInfo{CA: CALetsEncrypt}, want: [3]float64{1, 0.9, 1}},
		{name: "first issuance", want: [3]float64{0.9, 0.9, 0.9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			le := &trackingFake{caID: CALetsEncrypt}
			a := acct(le, "le-1", time.Minute)
			ac := newAccountChain(t, ChainConfig{}, a)
			if _, _, _, err := ac.ch.ObtainSelf(context.Background(), "enroll.example.test", tc.cur); err != nil {
				t.Fatal(err)
			}
			orders, name, domain := leBuckets(a, "enroll.example.test")
			if got := [3]float64{ac.level(t, orders), ac.level(t, name), ac.level(t, domain)}; got != tc.want {
				t.Fatalf("orders/name/domain levels = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChain_BucketNameFromCSR(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		csr  func(t *testing.T) *x509.CertificateRequest
		fqdn string
	}{
		{name: "first SAN", csr: func(t *testing.T) *x509.CertificateRequest { return tlsCSR(t, "", "q.example.test") }, fqdn: "q.example.test"},
		{name: "CN only", csr: func(t *testing.T) *x509.CertificateRequest { return tlsCSR(t, "p.example.test") }, fqdn: "p.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			le := &trackingFake{caID: CALetsEncrypt}
			a := acct(le, "le-1", time.Minute)
			ac := newAccountChain(t, ChainConfig{}, a)
			if _, _, err := ac.ch.Obtain(context.Background(), tc.csr(t), "p"); err != nil {
				t.Fatal(err)
			}
			_, name, domain := leBuckets(a, tc.fqdn)
			if ac.level(t, name) != 0.9 || ac.level(t, domain) != 0.9 {
				t.Fatalf("the name and domain buckets must be keyed on %s", tc.fqdn)
			}
			if !strings.HasSuffix(domain.Key, ":example.test") {
				t.Fatalf("domain bucket %s, want the registered domain example.test", domain.Key)
			}
			_, bare, _ := leBuckets(a, "p")
			if ac.level(t, bare) != 1 {
				t.Fatal("the bare tunnel name must never key a bucket")
			}
		})
	}
}

func TestChain_AttemptDeadline(t *testing.T) {
	le := &trackingFake{caID: CALetsEncrypt, block: true}
	gts := &trackingFake{caID: CAGTS}
	ac := newAccountChain(t, ChainConfig{}, acct(le, "le-1", 50*time.Millisecond), acct(gts, "gts-1", time.Minute))
	start := time.Now()
	_, info, err := ac.ch.Obtain(context.Background(), nil, "p")
	if err != nil || info.CA != CAGTS {
		t.Fatalf("Obtain = %+v, %v; want GTS after the LE deadline", info, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the LE attempt must be abandoned at its 50 ms deadline, the run took %s", elapsed)
	}
	if !slices.Contains(ac.rec.issues, CALetsEncrypt+" fail") {
		t.Fatalf("the deadline must count as an LE failure, issues %v", ac.rec.issues)
	}
	if cool, err := ac.lim.CACooldown(context.Background(), "le-1"); err != nil || cool != time.Minute {
		t.Fatalf("LE account wait-until = %s (%v), want the 1 m backoff", cool, err)
	}
}

func TestChain_LocalRefusalBacksOff(t *testing.T) {
	t.Parallel()
	le := newLazyCA(CALetsEncrypt, 160*time.Hour, 48*time.Hour, func(context.Context) (caIssuer, error) { return nil, errAccountBudget }, testLogger())
	gts := &trackingFake{caID: CAGTS}
	leAcct := &account{ca: CALetsEncrypt, id: "le-1", label: "local", timeout: time.Minute, issuer: le}
	ac := newAccountChain(t, ChainConfig{}, leAcct, acct(gts, "gts-1", time.Minute))
	if _, info, err := ac.ch.Obtain(context.Background(), nil, "p"); err != nil || info.CA != CAGTS {
		t.Fatalf("Obtain = %+v, %v; want GTS", info, err)
	}
	if !slices.Contains(ac.rec.issues, CALetsEncrypt+" fail") {
		t.Fatalf("a refused request must count as a failure, issues %v", ac.rec.issues)
	}
	if cool, err := ac.lim.CACooldown(context.Background(), "le-1"); err != nil || cool != time.Minute {
		t.Fatalf("LE account wait-until = %s (%v), want the 1 m backoff", cool, err)
	}
}

func TestChain_RunBudget(t *testing.T) {
	le := &trackingFake{caID: CALetsEncrypt, block: true}
	gts := &trackingFake{caID: CAGTS, block: true}
	ac := newAccountChain(t, ChainConfig{RunBudget: 100 * time.Millisecond}, acct(le, "le-1", time.Second), acct(gts, "gts-1", time.Second))
	start := time.Now()
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Obtain = %v, want the run budget's deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 600*time.Millisecond {
		t.Fatalf("no attempt may outlive the 100 ms run budget, the run took %s", elapsed)
	}
	if gts.calls.Load() != 0 {
		t.Fatal("the run must stop once its budget is spent")
	}
}

func TestChain_MissingCAsSkipped(t *testing.T) {
	t.Parallel()
	le := &trackingFake{caID: CALetsEncrypt}
	ac := newAccountChain(t, ChainConfig{}, acct(le, "le-1", time.Minute))
	if _, info, err := ac.ch.Obtain(context.Background(), nil, "p"); err != nil || info.CA != CALetsEncrypt {
		t.Fatalf("Obtain = %+v, %v; want LE", info, err)
	}
	if ac.ch.byID(CAGTS) != nil || ac.ch.byID(CAZeroSSL) != nil {
		t.Fatal("CAs without accounts must not be in the chain")
	}
	cur := store.CertInfo{CA: CAGTS, NotBefore: frozenNow}
	ac.ch.SetClock(func() time.Time { return frozenNow.Add(113 * time.Hour) })
	if due, at, err := ac.ch.ShouldRenew(context.Background(), cur); err != nil || !due || !at.Equal(frozenNow.Add(112*time.Hour)) {
		t.Fatalf("a missing CA must fall back to the fixed floor: due=%v at=%s err=%v", due, at, err)
	}
}

func TestChain_BudgetLevels(t *testing.T) {
	t.Parallel()
	le := &trackingFake{caID: CALetsEncrypt}
	g1 := &trackingFake{caID: CAGTS, label: "gts-1"}
	ac := newAccountChain(t, ChainConfig{}, acct(le, "le-1", time.Minute), acct(g1, "g1", time.Minute))
	levels, err := ac.ch.ACMEBudgetLevels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range levels {
		got = append(got, l.CA+"/"+l.Account+"/"+l.Budget)
		if l.Ratio != 1 {
			t.Fatalf("level %+v, want a full budget", l)
		}
	}
	want := []string{"letsencrypt/local/domain", "letsencrypt/local/orders", "gts/gts-1/orders", "gts/gts-1/requests", "gts/gts-1/cert-polls"}
	if !slices.Equal(got, want) {
		t.Fatalf("levels %v, want %v", got, want)
	}
	failing := newAccountChain(t, ChainConfig{Nodes: fakeNodes{err: errors.New("valkey down")}}, acct(le, "le-1", time.Minute))
	if _, err := failing.ch.ACMEBudgetLevels(context.Background()); err == nil {
		t.Fatal("a node-list error must be returned")
	}
}

func TestChain_LiveNodesError(t *testing.T) {
	t.Parallel()
	le := &trackingFake{caID: CALetsEncrypt}
	a := acct(le, "le-1", time.Minute)
	budgets := smallBudgets()
	budgets.LEOrders = limit.Rate{Count: 1, Period: time.Hour, Burst: 1}
	ac := newAccountChain(t, ChainConfig{Budgets: budgets, Nodes: fakeNodes{err: errors.New("valkey down")}}, a)
	ok, _, err := ac.lim.ReserveACME(context.Background(), CALetsEncrypt, []limit.Bucket{budgets.leOrders(a)}, "other-node", "m", frozenNow.Add(time.Hour), []string{"other-node"})
	if err != nil || !ok {
		t.Fatalf("pre-reservation on another node: ok=%v err=%v", ok, err)
	}
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p"); err != nil {
		t.Fatalf("with the node list unavailable only this node's reservations count: %v", err)
	}
	if le.calls.Load() != 1 || !strings.Contains(ac.log.String(), `msg="live node list unavailable (counting only this node's in-flight orders)"`) {
		t.Fatalf("calls %d; log = %q", le.calls.Load(), ac.log.String())
	}
}

func TestChain_OrderedLevelsError(t *testing.T) {
	t.Parallel()
	calls := &callLog{}
	g1 := &trackingFake{caID: CAGTS, label: "gts-1", order: calls}
	g2 := &trackingFake{caID: CAGTS, label: "gts-2", order: calls}
	ac := newAccountChain(t, ChainConfig{}, acct(g1, "g1", time.Minute), acct(g2, "g2", time.Minute))
	ac.mr.Close()
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p"); err != nil {
		t.Fatal(err)
	}
	if got := calls.get(); !slices.Equal(got, []string{"gts-2"}) {
		t.Fatalf("accounts tried %v, want the Rand-shuffled order (gts-2 first)", got)
	}
	if !strings.Contains(ac.log.String(), `msg="acme budget levels unavailable (accounts in random order)"`) {
		t.Fatalf("log = %q", ac.log.String())
	}
}

func TestChain_RetryAfterReportsTheWaitUntilInEffect(t *testing.T) {
	t.Parallel()
	var ac *accountChain
	le := &trackingFake{caID: CALetsEncrypt, err: transient(errors.New("down")), onObtain: func(ctx context.Context) {
		if err := ac.lim.SetCACooldown(ctx, "le-1", 10*time.Minute); err != nil {
			t.Errorf("set the other node's wait-until: %v", err)
		}
	}}
	ac = newAccountChain(t, ChainConfig{}, acct(le, "le-1", time.Minute))
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p")
	ie, ok := errors.AsType[*IssuerError](err)
	if !ok || ie.Class != ClassRateLimited || ie.Retry != 10*time.Minute+time.Second {
		t.Fatalf("Obtain = %v, want rate-limited with the 10 m wait-until in effect + 1 s, not the 1 m backoff", err)
	}
}

func TestChain_BuildRateLimitedSkipsTheBackoff(t *testing.T) {
	t.Parallel()
	limited := newLazyCA(CALetsEncrypt, 160*time.Hour, 48*time.Hour, func(context.Context) (caIssuer, error) {
		return nil, fmt.Errorf("acme: resolve the existing account by key: %w",
			&legoacme.ProblemDetails{HTTPStatus: http.StatusTooManyRequests, Type: "urn:ietf:params:acme:error:rateLimited"})
	}, testLogger())
	ac := newAccountChain(t, ChainConfig{}, &account{ca: CALetsEncrypt, id: "le-1", label: "local", timeout: time.Minute, issuer: limited})
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p")
	if ie, ok := errors.AsType[*IssuerError](err); !ok || ie.Class != ClassRateLimited {
		t.Fatalf("Obtain = %v, want rate-limited", err)
	}
	if ac.mr.Exists("acme-fail:le-1") {
		t.Fatal("a 429 while building the client must not start the failure streak")
	}
	if cool, err := ac.lim.CACooldown(context.Background(), "le-1"); err != nil || cool != time.Hour {
		t.Fatalf("LE account wait-until = %s (%v), want --acme-cooldown-default (1 h), not the 1 m backoff", cool, err)
	}
}

func TestNewChainIssuer_RequiresNodes(t *testing.T) {
	t.Parallel()
	if _, err := NewChainIssuer(ChainConfig{}, acct(&trackingFake{caID: CALetsEncrypt}, "le-1", time.Minute)); !errors.Is(err, errNoNodeLister) {
		t.Fatalf("NewChainIssuer without a node lister = %v, want errNoNodeLister", err)
	}
}

func TestChain_FailureWhileWaitingDoesNotBumpTheStreak(t *testing.T) {
	t.Parallel()
	var ac *accountChain
	le := &trackingFake{caID: CALetsEncrypt, err: transient(context.DeadlineExceeded), onObtain: func(ctx context.Context) {
		if err := ac.lim.SetCACooldown(ctx, "le-1", 3*time.Minute); err != nil {
			t.Errorf("set the wait-until the attempt was held under: %v", err)
		}
	}}
	ac = newAccountChain(t, ChainConfig{}, acct(le, "le-1", time.Minute))
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p")
	if ie, ok := errors.AsType[*IssuerError](err); !ok || ie.Class != ClassRateLimited || ie.Retry != 3*time.Minute+time.Second {
		t.Fatalf("Obtain = %v, want rate-limited with the 3 m wait in effect + 1 s", err)
	}
	if ac.mr.Exists("acme-fail:le-1") {
		t.Fatal("a failure while the account already waits must not add a step to the backoff")
	}
	if len(ac.rec.cooldowns) != 0 {
		t.Fatalf("a failure while the account already waits must set no cooldown, got %v", ac.rec.cooldowns)
	}
}

func TestAttemptContext(t *testing.T) {
	t.Parallel()
	wait := func(t *testing.T, ctx context.Context) {
		t.Helper()
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the attempt context was never cancelled")
		}
	}
	t.Run("unfinalized order stops at the deadline", func(t *testing.T) {
		ctx, cancel := attemptContext(context.Background(), newOrderTrack(limit.Bucket{}, limit.Bucket{}), 20*time.Millisecond, time.Hour)
		defer cancel()
		wait(t, ctx)
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatalf("cause = %v, want the attempt deadline", context.Cause(ctx))
		}
	})
	t.Run("finalized order gets the grace", func(t *testing.T) {
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.markFinalized(time.Now())
		start := time.Now()
		ctx, cancel := attemptContext(context.Background(), tr, 20*time.Millisecond, 200*time.Millisecond)
		defer cancel()
		wait(t, ctx)
		if elapsed := time.Since(start); elapsed < 220*time.Millisecond || !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatalf("cancelled after %s with cause %v, want the deadline plus the grace", elapsed, context.Cause(ctx))
		}
	})
	t.Run("finalize sent but unanswered gets the grace", func(t *testing.T) {
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setOrder("https://ca.test/order/1", "https://ca.test/finalize/1")
		tr.markSent(http.MethodPost, "https://ca.test/finalize/1")
		start := time.Now()
		ctx, cancel := attemptContext(context.Background(), tr, 20*time.Millisecond, 200*time.Millisecond)
		defer cancel()
		wait(t, ctx)
		if elapsed := time.Since(start); elapsed < 220*time.Millisecond {
			t.Fatalf("cancelled after %s, want the deadline plus the grace", elapsed)
		}
	})
	t.Run("caller cancel", func(t *testing.T) {
		ctx, cancel := attemptContext(context.Background(), newOrderTrack(limit.Bucket{}, limit.Bucket{}), time.Hour, time.Hour)
		cancel()
		wait(t, ctx)
		if !errors.Is(context.Cause(ctx), context.Canceled) {
			t.Fatalf("cause = %v, want the caller's cancel", context.Cause(ctx))
		}
	})
}

func TestChain_PrepaysAndRefundsRequestBudget(t *testing.T) {
	t.Parallel()
	gts := &trackingFake{caID: CAGTS, label: "gts-1", onObtain: func(ctx context.Context) {
		tr := trackFrom(ctx)
		for range 3 {
			if _, ok := tr.usePrepaid(); !ok {
				t.Error("the order must start with a prepaid balance")
			}
		}
	}}
	a := acct(gts, "gts-1", time.Minute)
	ac := newAccountChain(t, ChainConfig{}, a)
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
		t.Fatal(err)
	}
	if got := ac.level(t, smallBudgets().gtsRequests(a)); got != 0.7 {
		t.Fatalf("GTS request budget level = %v, want 0.7 (the 3 requests used; the other 6 of the 9 prepaid refunded)", got)
	}
}

func TestChain_RefundsTheRequestBudgetOfAnOrderThatDoesNotIssue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		err       error
		block     bool
		finalized bool
		grace     time.Duration
	}{
		{name: "the CA refuses the order", err: transient(errors.New("down"))},
		{name: "the order is abandoned at its deadline", block: true},
		{name: "a finalized order is abandoned after the grace", block: true, finalized: true, grace: 30 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gts := &trackingFake{caID: CAGTS, label: "gts-1", err: tc.err, block: tc.block, created: tc.finalized, finalized: tc.finalized,
				onObtain: func(ctx context.Context) {
					if _, ok := trackFrom(ctx).usePrepaid(); !ok {
						t.Error("the order must start with a prepaid balance")
					}
				}}
			a := acct(gts, "gts-1", 30*time.Millisecond)
			ac := newAccountChain(t, ChainConfig{FinalizeGrace: tc.grace}, a)
			if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err == nil {
				t.Fatal("an order that does not issue must fail")
			}
			if got := ac.level(t, smallBudgets().gtsRequests(a)); got != 0.9 {
				t.Fatalf("GTS request budget level = %v, want 0.9 (the one request used; the other 8 of the 9 prepaid refunded)", got)
			}
		})
	}
}

func TestChain_SkipsAccountWithoutRequestBudget(t *testing.T) {
	t.Parallel()
	gts := &trackingFake{caID: CAGTS, label: "gts-1"}
	a := acct(gts, "gts-1", time.Minute)
	ac := newAccountChain(t, ChainConfig{}, a)
	ac.spend(t, CAGTS, smallBudgets().gtsRequests(a), 2)
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test")
	var ie *IssuerError
	if !asIssuerError(err, &ie) || ie.Class != ClassRateLimited || ie.Retry <= 0 {
		t.Fatalf("err = %v, want rate-limited with a retry-after", err)
	}
	if gts.calls.Load() != 0 {
		t.Fatal("an account without request budget for a whole order must not be asked")
	}
	if got := ac.level(t, smallBudgets().gtsOrders(a)); got != 1 {
		t.Fatalf("GTS order budget level = %v, want 1 (the reservation released)", got)
	}
	if !strings.Contains(ac.log.String(), `msg="acme account out of request budget (skipped)"`) {
		t.Fatalf("the skip must be logged; log = %q", ac.log.String())
	}
}

func TestChain_ReservationCoversTheFinalizeGrace(t *testing.T) {
	t.Parallel()
	var ac *accountChain
	var score float64
	gts := &trackingFake{caID: CAGTS, label: "gts-1"}
	a := acct(gts, "gts-1", time.Minute)
	gts.onObtain = func(ctx context.Context) {
		zs, err := ac.rdb.ZRangeWithScores(ctx, "acme:inflight:"+smallBudgets().gtsOrders(a).Key+":node-test", 0, -1).Result()
		if err != nil || len(zs) != 1 {
			t.Errorf("in-flight reservation = %v (err %v), want one", zs, err)
			return
		}
		score = zs[0].Score
	}
	ac = newAccountChain(t, ChainConfig{FinalizeGrace: 7 * time.Second}, a)
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
		t.Fatal(err)
	}
	if want := float64(frozenNow.Add(time.Minute + 7*time.Second).UnixMilli()); score != want {
		t.Fatalf("reservation score = %v, want the attempt deadline plus the grace %v", score, want)
	}
}

var errInjectedValkey = errors.New("injected valkey failure")

type failCmds struct {
	name  string
	key   string
	armed atomic.Bool
}

func (ac *accountChain) failOn(name, key string, armed bool) *failCmds {
	h := &failCmds{name: name, key: key}
	h.armed.Store(armed)
	ac.rdb.AddHook(h)
	return h
}

func (h *failCmds) hits(cmds ...redis.Cmder) bool {
	if !h.armed.Load() {
		return false
	}
	for _, c := range cmds {
		if (h.name == "" || c.Name() == h.name) && (h.key == "" || slices.Contains(c.Args(), any(h.key))) {
			return true
		}
	}
	return false
}

func (h *failCmds) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *failCmds) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if h.hits(cmd) {
			cmd.SetErr(errInjectedValkey)
			return errInjectedValkey
		}
		return next(ctx, cmd)
	}
}

func (h *failCmds) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if h.hits(cmds...) {
			for _, c := range cmds {
				c.SetErr(errInjectedValkey)
			}
			return errInjectedValkey
		}
		return next(ctx, cmds)
	}
}

func TestChain_LogsPrepayRefundFailure(t *testing.T) {
	t.Parallel()
	var fail *failCmds
	gts := &trackingFake{caID: CAGTS, label: "gts-1", onObtain: func(context.Context) { fail.armed.Store(true) }}
	a := acct(gts, "gts-1", time.Minute)
	ac := newAccountChain(t, ChainConfig{}, a)
	fail = ac.failOn("", "acme-budget:"+smallBudgets().gtsRequests(a).Key, false)
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ac.log.String(), `msg="acme request budget refund failed (the budget refills on its own)"`) {
		t.Fatalf("a failed refund must be logged; log = %q", ac.log.String())
	}
}

func TestChain_LogsPrepayFailureAndTriesTheAccount(t *testing.T) {
	t.Parallel()
	gts := &trackingFake{caID: CAGTS, label: "gts-1"}
	a := acct(gts, "gts-1", time.Minute)
	ac := newAccountChain(t, ChainConfig{}, a)
	ac.failOn("", "acme-budget:"+smallBudgets().gtsRequests(a).Key, true)
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
		t.Fatal(err)
	}
	if gts.calls.Load() != 1 {
		t.Fatal("an account whose prepay failed must still be asked")
	}
	if !strings.Contains(ac.log.String(), `msg="acme request budget prepay failed (trying the account)"`) {
		t.Fatalf("a failed prepay must be logged; log = %q", ac.log.String())
	}
}

func TestChain_LogsReleaseFailureWhenSkippingWithoutRequestBudget(t *testing.T) {
	t.Parallel()
	gts := &trackingFake{caID: CAGTS, label: "gts-1"}
	a := acct(gts, "gts-1", time.Minute)
	ac := newAccountChain(t, ChainConfig{}, a)
	ac.spend(t, CAGTS, smallBudgets().gtsRequests(a), 2)
	ac.failOn("zrem", "", true)
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test")
	var ie *IssuerError
	if !asIssuerError(err, &ie) || ie.Class != ClassRateLimited || ie.Retry <= 0 {
		t.Fatalf("err = %v, want rate-limited with a retry-after", err)
	}
	if gts.calls.Load() != 0 {
		t.Fatal("an account without request budget for a whole order must not be asked")
	}
	for _, want := range []string{`msg="acme budget release failed (the reservation expires at its deadline)"`,
		`msg="acme account out of request budget (skipped)" ca=gts name=p.example.test retry_after=`} {
		if !strings.Contains(ac.log.String(), want) {
			t.Fatalf("log is missing %s; log = %q", want, ac.log.String())
		}
	}
}

func TestChain_DropsPrepaidAfterA429(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		before    bool
		during    bool
		expire    bool
		wantLevel float64
		wantDrop  bool
	}{
		{name: "a 429 during the order drops the balance", during: true, wantLevel: 0.1, wantDrop: true},
		{name: "a 429 before the prepay keeps the refund", before: true, wantLevel: 1},
		{name: "a mark that expires during the order keeps the refund", before: true, expire: true, wantLevel: 1},
		{name: "no 429 refunds the balance", wantLevel: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var ac *accountChain
			gts := &trackingFake{caID: CAGTS, label: "gts-1", onObtain: func(ctx context.Context) {
				if tc.during {
					if err := ac.lim.MarkCALimited(ctx, "gts-1", time.Minute); err != nil {
						t.Error(err)
					}
				}
				if tc.expire {
					ac.mr.Del("acme-429:gts-1")
				}
			}}
			a := acct(gts, "gts-1", time.Minute)
			ac = newAccountChain(t, ChainConfig{}, a)
			if tc.before {
				if err := ac.lim.MarkCALimited(context.Background(), "gts-1", time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
				t.Fatal(err)
			}
			if got := ac.level(t, smallBudgets().gtsRequests(a)); got != tc.wantLevel {
				t.Fatalf("GTS request budget level = %v, want %v", got, tc.wantLevel)
			}
			dropped := strings.Contains(ac.log.String(), `msg="acme order dropped its prepaid requests" ca=gts account=gts-1 reason="the account answered 429" dropped=9`)
			if dropped != tc.wantDrop {
				t.Fatalf("drop logged = %v, want %v; log = %q", dropped, tc.wantDrop, ac.log.String())
			}
		})
	}
}

func TestChain_429MarkReadFailure(t *testing.T) {
	t.Parallel()
	t.Run("before the prepay the order runs without one", func(t *testing.T) {
		t.Parallel()
		gts := &trackingFake{caID: CAGTS, label: "gts-1", onObtain: func(ctx context.Context) {
			if _, ok := trackFrom(ctx).usePrepaid(); ok {
				t.Error("an order whose 429 mark could not be read must not hold a prepaid balance")
			}
		}}
		a := acct(gts, "gts-1", time.Minute)
		ac := newAccountChain(t, ChainConfig{}, a)
		ac.failOn("", "acme-429:gts-1", true)
		if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
			t.Fatal(err)
		}
		if got := ac.level(t, smallBudgets().gtsRequests(a)); got != 1 {
			t.Fatalf("GTS request budget level = %v, want 1 (nothing prepaid)", got)
		}
		if !strings.Contains(ac.log.String(), `msg="acme 429 mark read failed (no prepay; requests draw on the shared budget)"`) {
			t.Fatalf("the failed read must be logged; log = %q", ac.log.String())
		}
	})
	t.Run("at the end the refund is skipped", func(t *testing.T) {
		t.Parallel()
		var fail *failCmds
		gts := &trackingFake{caID: CAGTS, label: "gts-1", onObtain: func(context.Context) { fail.armed.Store(true) }}
		a := acct(gts, "gts-1", time.Minute)
		ac := newAccountChain(t, ChainConfig{}, a)
		fail = ac.failOn("", "acme-429:gts-1", false)
		if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
			t.Fatal(err)
		}
		if got := ac.level(t, smallBudgets().gtsRequests(a)); got != 0.1 {
			t.Fatalf("GTS request budget level = %v, want 0.1 (the 9 prepaid not refunded)", got)
		}
		if !strings.Contains(ac.log.String(), `msg="acme 429 mark read failed (refund skipped; the budget refills on its own)"`) {
			t.Fatalf("the failed read must be logged; log = %q", ac.log.String())
		}
	})
}

func TestNewChain_RequiresTheMaxAttemptTimeout(t *testing.T) {
	t.Parallel()
	if _, err := NewChain(ChainConfig{Nodes: fakeNodes{ids: []string{"node-test"}}}); !errors.Is(err, errNoMaxAttemptTimeout) {
		t.Fatalf("NewChain = %v, want errNoMaxAttemptTimeout", err)
	}
}

func TestNewChain_RejectsAnAttemptTimeoutAboveTheMaximum(t *testing.T) {
	t.Parallel()
	_, err := NewChain(ChainConfig{Nodes: fakeNodes{ids: []string{"node-test"}}, MaxAttemptTimeout: 100 * time.Second},
		LegoConfig{CAID: CAGTS, AccountID: "gts-1", Label: "gts-1", AttemptTimeout: 101 * time.Second})
	if !errors.Is(err, errAttemptTimeoutAboveMax) {
		t.Fatalf("NewChain = %v, want errAttemptTimeoutAboveMax", err)
	}
}

type delayedFake struct {
	caID     string
	delay    time.Duration
	finalize bool
}

func (f *delayedFake) obtain(ctx context.Context, _ *x509.CertificateRequest, _ string) ([]byte, store.CertInfo, error) {
	if tr := trackFrom(ctx); tr != nil && f.finalize {
		tr.setOrder("https://ca.example.test/order/1", "https://ca.example.test/finalize/1")
		tr.markFinalized(time.Now())
	}
	select {
	case <-ctx.Done():
		return nil, store.CertInfo{}, transient(context.Cause(ctx))
	case <-time.After(f.delay):
		return []byte("CERT"), store.CertInfo{CA: f.caID, Serial: "01"}, nil
	}
}

func (f *delayedFake) shouldRenew(_ context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error) {
	at := cur.NotBefore.Add(112 * time.Hour)
	return !now.Before(at), at, nil
}

func (f *delayedFake) id() string { return f.caID }

func TestChain_FinalizedOrderGetsTheGrace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		finalize bool
		wantOK   bool
	}{
		{name: "a finalized order fetches its certificate after the deadline", finalize: true, wantOK: true},
		{name: "an unfinalized order is abandoned at the deadline", finalize: false, wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &delayedFake{caID: CALetsEncrypt, delay: time.Second, finalize: tc.finalize}
			ac := newAccountChain(t, ChainConfig{FinalizeGrace: 5 * time.Second},
				&account{ca: CALetsEncrypt, id: "le-1", label: "local", timeout: 100 * time.Millisecond, issuer: f})
			pemChain, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test")
			if got := err == nil && string(pemChain) == "CERT"; got != tc.wantOK {
				t.Fatalf("Obtain = %q, %v; want success %v", pemChain, err, tc.wantOK)
			}
		})
	}
}

func TestLimitedMarkTTL_OutlivesTheLongestOrder(t *testing.T) {
	t.Parallel()
	if got, want := limitedMarkTTL(100*time.Second, 30*time.Second), 100*time.Second+30*time.Second+settleTimeout+time.Minute; got != want {
		t.Fatalf("limitedMarkTTL = %s, want %s", got, want)
	}
}

func TestChain_BuildsTheClientBeforeTakingBudget(t *testing.T) {
	t.Parallel()
	var lim *limit.Limiter
	var reqLevel, orderLevel float64
	var levelErr error
	a := &account{ca: CAGTS, id: "gts-1", label: "gts-1", timeout: time.Minute}
	a.issuer = newLazyCA(CAGTS, 160*time.Hour, 48*time.Hour, func(ctx context.Context) (caIssuer, error) {
		var rerr, oerr error
		reqLevel, rerr = lim.ACMEBudgetLevel(ctx, smallBudgets().gtsRequests(a), []string{"node-test"})
		orderLevel, oerr = lim.ACMEBudgetLevel(ctx, smallBudgets().gtsOrders(a), []string{"node-test"})
		levelErr = errors.Join(rerr, oerr)
		return &trackingFake{caID: CAGTS, label: "gts-1"}, nil
	}, testLogger())
	ac := newAccountChain(t, ChainConfig{}, a)
	lim = ac.lim
	if _, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test"); err != nil {
		t.Fatal(err)
	}
	if levelErr != nil {
		t.Fatal(levelErr)
	}
	if reqLevel != 1 || orderLevel != 1 {
		t.Fatalf("request/order budget levels during the build = %v/%v, want 1/1 (nothing prepaid or reserved yet)", reqLevel, orderLevel)
	}
}
