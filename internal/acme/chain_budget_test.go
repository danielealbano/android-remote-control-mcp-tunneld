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
	ac := newAccountChain(t, ChainConfig{}, a)
	_, _, err := ac.ch.Obtain(context.Background(), nil, "p.example.test")
	orders, name, domain := leBuckets(a, "p.example.test")
	return [3]float64{ac.level(t, orders), ac.level(t, name), ac.level(t, domain)}, ran.Load(), err
}

func TestChain_SettleSuccess(t *testing.T) {
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, finalized: true}, time.Minute)
	if err != nil || levels != [3]float64{0.9, 0.9, 0.9} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want every bucket spent and no reservation left", levels, cleaned, err)
	}
}

func TestChain_SettleCreatedThenFailed(t *testing.T) {
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, err: permanent(errors.New("bad csr"))}, time.Minute)
	if err == nil || levels != [3]float64{0.9, 1, 1} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want the order bucket spent and the success buckets released", levels, cleaned, err)
	}
}

func TestChain_SettleFailedBeforeCreate(t *testing.T) {
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, err: transient(errors.New("down"))}, time.Minute)
	if err == nil || levels != [3]float64{1, 1, 1} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want everything released", levels, cleaned, err)
	}
}

func TestChain_SettleFinalizedAbandoned(t *testing.T) {
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, finalized: true, block: true}, 50*time.Millisecond)
	if err == nil || levels != [3]float64{0.9, 0.9, 0.9} || !cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want every bucket spent and the challenge cleanups run", levels, cleaned, err)
	}
}

func TestChain_SettleFinalizedThenError(t *testing.T) {
	levels, cleaned, err := settleLevels(t, &trackingFake{caID: CALetsEncrypt, created: true, finalized: true, err: transient(errors.New("certificate wait"))}, time.Minute)
	if err == nil || levels != [3]float64{0.9, 0.9, 0.9} || cleaned {
		t.Fatalf("orders/name/domain levels = %v (cleanup %v, err %v), want every bucket spent and no cleanup run", levels, cleaned, err)
	}
}

func TestChain_SettleWithoutReservation(t *testing.T) {
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
	if _, err := NewChainIssuer(ChainConfig{}, acct(&trackingFake{caID: CALetsEncrypt}, "le-1", time.Minute)); !errors.Is(err, errNoNodeLister) {
		t.Fatalf("NewChainIssuer without a node lister = %v, want errNoNodeLister", err)
	}
}

func TestChain_FailureWhileWaitingDoesNotBumpTheStreak(t *testing.T) {
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
