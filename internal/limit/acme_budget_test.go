package limit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type budgetHarness struct {
	l   *Limiter
	rdb *redis.Client
	mr  *miniredis.Miniredis
	now time.Time
	log *bytes.Buffer
}

func newBudgetHarness(t *testing.T) *budgetHarness {
	t.Helper()
	rdb, mr := newTestRedis(t)
	h := &budgetHarness{rdb: rdb, mr: mr, now: time.Unix(1_700_000_000, 0), log: &bytes.Buffer{}}
	h.l = NewLimiter(rdb, 125000, 1<<40, 1<<40, time.Hour, WithLogger(slog.New(slog.NewTextHandler(h.log, nil))))
	h.l.SetClock(func() time.Time { return h.now })
	return h
}

func (h *budgetHarness) reserve(t *testing.T, b Bucket, node, member string, deadline time.Time, live ...string) (bool, time.Duration) {
	t.Helper()
	ok, wait, err := h.l.ReserveACME(ctxT(t), "letsencrypt", []Bucket{b}, node, member, deadline, live)
	if err != nil {
		t.Fatal(err)
	}
	return ok, wait
}

func (h *budgetHarness) tokens(t *testing.T, b Bucket) float64 {
	t.Helper()
	v, err := h.rdb.HGet(ctxT(t), budgetKey(b), "t").Result()
	if err != nil {
		t.Fatal(err)
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func within(got, want, tol time.Duration) bool {
	d := got - want
	return d >= -tol && d <= tol
}

func TestSetCACooldown_NeverShortens(t *testing.T) {
	tests := []struct {
		name     string
		existing time.Duration
		set      time.Duration
		want     time.Duration
	}{
		{name: "shorter value keeps the longer wait", existing: 10 * time.Second, set: 2 * time.Second, want: 10 * time.Second},
		{name: "longer value extends", existing: 2 * time.Second, set: 10 * time.Second, want: 10 * time.Second},
		{name: "absent key is set", set: 5 * time.Second, want: 5 * time.Second},
		{name: "sub-second becomes 1 s", set: 300 * time.Millisecond, want: time.Second},
		{name: "fractional rounds up over an existing wait", existing: 7200 * time.Millisecond, set: 7400 * time.Millisecond, want: 8 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newBudgetHarness(t)
			ctx := ctxT(t)
			if tc.existing > 0 {
				if err := h.rdb.Set(ctx, cooldownKey("acct"), "1", tc.existing).Err(); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.l.SetCACooldown(ctx, "acct", tc.set); err != nil {
				t.Fatal(err)
			}
			if got := h.mr.TTL(cooldownKey("acct")); got != tc.want {
				t.Fatalf("wait-until TTL = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRate_Bucket(t *testing.T) {
	tests := []struct {
		name string
		rate Rate
		want Bucket
	}{
		{name: "le domain", rate: Rate{Count: 50, Period: 168 * time.Hour, Burst: 50}, want: Bucket{Key: "k", Capacity: 50, Refill: 168 * time.Hour / 50}},
		{name: "burst overrides capacity", rate: Rate{Count: 200, Period: time.Hour, Burst: 40}, want: Bucket{Key: "k", Capacity: 40, Refill: 18 * time.Second}},
		{name: "zero count refills per period", rate: Rate{Count: 0, Period: time.Minute, Burst: 1}, want: Bucket{Key: "k", Capacity: 1, Refill: time.Minute}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rate.Bucket("k"); got != tc.want {
				t.Fatalf("Bucket = %+v, want %+v", got, tc.want)
			}
		})
	}
	if got := (Rate{Count: 50, Period: 168 * time.Hour, Burst: 50}).Bucket("k").Refill; got != 201*time.Minute+36*time.Second {
		t.Fatalf("50/168h refill = %s, want 201.6 min", got)
	}
}

func TestReserveACME_Reserves(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 5, Period: time.Hour, Burst: 5}.Bucket("le:orders")
	deadline := h.now.Add(20 * time.Second)
	if ok, _ := h.reserve(t, b, "n1", "m1", deadline, "n1"); !ok {
		t.Fatal("a full bucket must reserve")
	}
	key := inflightKey(b, "n1")
	score, err := h.rdb.ZScore(ctxT(t), key, "m1").Result()
	if err != nil {
		t.Fatal(err)
	}
	if int64(score) != deadline.UnixMilli() {
		t.Fatalf("member score = %v, want the deadline %d", score, deadline.UnixMilli())
	}
	if h.mr.TTL(key) <= 0 {
		t.Fatal("the in-flight set must carry a TTL")
	}
}

func TestReserveACME_InflightCounts(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 2, Period: time.Hour, Burst: 2}.Bucket("le:orders")
	deadline := h.now.Add(time.Minute)
	for _, m := range []string{"m1", "m2"} {
		if ok, _ := h.reserve(t, b, "n1", m, deadline, "n1"); !ok {
			t.Fatalf("reservation %s must fit a capacity of 2", m)
		}
	}
	if ok, wait := h.reserve(t, b, "n1", "m3", deadline, "n1"); ok || wait <= 0 {
		t.Fatalf("a third reservation must be refused with a wait, got ok=%v wait=%s", ok, wait)
	}
}

func TestReserveACME_DeadNodeNotCounted(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 1, Period: time.Hour, Burst: 1}.Bucket("le:orders")
	deadline := h.now.Add(time.Minute)
	if ok, _ := h.reserve(t, b, "dead", "m1", deadline, "dead"); !ok {
		t.Fatal("first reservation must fit")
	}
	if ok, _ := h.reserve(t, b, "n1", "m2", deadline, "n1"); !ok {
		t.Fatal("a reservation of a node outside the live set must not count")
	}
}

func TestReserveACME_ExpiredNotCounted(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 1, Period: time.Hour, Burst: 1}.Bucket("le:orders")
	if ok, _ := h.reserve(t, b, "n1", "old", h.now.Add(-time.Second), "n1"); !ok {
		t.Fatal("first reservation must fit")
	}
	if ok, _ := h.reserve(t, b, "n1", "new", h.now.Add(time.Minute), "n1"); !ok {
		t.Fatal("a member past its deadline must be pruned and not counted")
	}
	if n, err := h.rdb.ZCard(ctxT(t), inflightKey(b, "n1")).Result(); err != nil || n != 1 {
		t.Fatalf("in-flight members = %d (%v), want only the new one", n, err)
	}
}

func TestReserveACME_WaitUntilNextToken(t *testing.T) {
	t.Run("empty bucket", func(t *testing.T) {
		h := newBudgetHarness(t)
		b := Rate{Count: 1, Period: 10 * time.Second, Burst: 1}.Bucket("le:orders")
		if err := h.l.CommitACME(ctxT(t), "letsencrypt", b, "n1", "m0"); err != nil {
			t.Fatal(err)
		}
		h.now = h.now.Add(4 * time.Second)
		if ok, wait := h.reserve(t, b, "n1", "m1", h.now.Add(time.Minute), "n1"); ok || !within(wait, 6*time.Second, time.Millisecond) {
			t.Fatalf("ok=%v wait=%s, want a 6 s wait", ok, wait)
		}
	})
	t.Run("capacity 1 with one in flight", func(t *testing.T) {
		h := newBudgetHarness(t)
		b := Rate{Count: 1, Period: 10 * time.Second, Burst: 1}.Bucket("le:orders")
		if ok, _ := h.reserve(t, b, "n1", "m1", h.now.Add(time.Minute), "n1"); !ok {
			t.Fatal("first reservation must fit")
		}
		if ok, wait := h.reserve(t, b, "n1", "m2", h.now.Add(time.Minute), "n1"); ok || wait != 10*time.Second {
			t.Fatalf("ok=%v wait=%s, want a refill-period wait", ok, wait)
		}
	})
}

func TestCommitACME_SpendsAndDrops(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 3, Period: time.Hour, Burst: 3}.Bucket("le:orders")
	if ok, _ := h.reserve(t, b, "n1", "m1", h.now.Add(time.Minute), "n1"); !ok {
		t.Fatal("reservation must fit")
	}
	if err := h.l.CommitACME(ctxT(t), "letsencrypt", b, "n1", "m1"); err != nil {
		t.Fatal(err)
	}
	if got := h.tokens(t, b); got != 2 {
		t.Fatalf("tokens = %v, want 2", got)
	}
	if n, err := h.rdb.ZCard(ctxT(t), inflightKey(b, "n1")).Result(); err != nil || n != 0 {
		t.Fatalf("in-flight members = %d (%v), want 0", n, err)
	}
	if h.mr.TTL(budgetKey(b)) <= 0 {
		t.Fatal("the budget hash must carry a TTL")
	}
	if err := h.l.CommitACME(ctxT(t), "letsencrypt", b, "n1", "never-reserved"); err != nil {
		t.Fatalf("a commit without a reservation must still spend: %v", err)
	}
	if got := h.tokens(t, b); got != 1 {
		t.Fatalf("tokens = %v, want 1", got)
	}
}

func TestReleaseACME_NoSpend(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 1, Period: time.Hour, Burst: 1}.Bucket("le:orders")
	if ok, _ := h.reserve(t, b, "n1", "m1", h.now.Add(time.Minute), "n1"); !ok {
		t.Fatal("reservation must fit")
	}
	if err := h.l.ReleaseACME(ctxT(t), []Bucket{b}, "n1", "m1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.reserve(t, b, "n1", "m2", h.now.Add(time.Minute), "n1"); !ok {
		t.Fatal("a released reservation must free its slot without spending")
	}
	if h.mr.Exists(budgetKey(b)) {
		t.Fatal("a release must not write the budget")
	}
}

func TestTakeACME_TakeOrWait(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 2, Period: time.Second, Burst: 2}.Bucket("gts:requests")
	for i := range 2 {
		if wait, err := h.l.TakeACME(ctxT(t), "gts", []Bucket{b}); err != nil || wait != 0 {
			t.Fatalf("take %d: wait=%s err=%v, want an immediate take", i+1, wait, err)
		}
	}
	wait, err := h.l.TakeACME(ctxT(t), "gts", []Bucket{b})
	if err != nil || !within(wait, 500*time.Millisecond, time.Millisecond) {
		t.Fatalf("third take: wait=%s err=%v, want the 500 ms to the next token", wait, err)
	}
	if got := h.tokens(t, b); got != 0 {
		t.Fatalf("a refused take must not spend: tokens = %v", got)
	}
}

func TestResyncACME_NextTokenAtRetryAfter(t *testing.T) {
	for _, retryAfter := range []time.Duration{3 * time.Second, 30 * time.Second} {
		t.Run(retryAfter.String(), func(t *testing.T) {
			h := newBudgetHarness(t)
			b := Rate{Count: 6, Period: time.Minute, Burst: 6}.Bucket("le:domain")
			if err := h.l.ResyncACME(ctxT(t), "letsencrypt", []Bucket{b}, retryAfter); err != nil {
				t.Fatal(err)
			}
			wait, err := h.l.TakeACME(ctxT(t), "letsencrypt", []Bucket{b})
			if err != nil || !within(wait, retryAfter, time.Millisecond) {
				t.Fatalf("wait=%s err=%v, want exactly %s to the next token", wait, err, retryAfter)
			}
			h.now = h.now.Add(retryAfter)
			if wait, err := h.l.TakeACME(ctxT(t), "letsencrypt", []Bucket{b}); err != nil || wait != 0 {
				t.Fatalf("at now+retryAfter: wait=%s err=%v, want a token", wait, err)
			}
		})
	}
}

func TestACMEBudgetLevel_Ratio(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 4, Period: time.Hour, Burst: 4}.Bucket("gts:orders")
	if ok, _ := h.reserve(t, b, "n1", "m1", h.now.Add(time.Minute), "n1"); !ok {
		t.Fatal("reservation must fit")
	}
	lv, err := h.l.ACMEBudgetLevel(ctxT(t), b, []string{"n1"})
	if err != nil || lv != 0.75 {
		t.Fatalf("level = %v (%v), want 0.75", lv, err)
	}
	if err := h.l.CommitACME(ctxT(t), "gts", b, "n1", "m1"); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := h.l.CommitACME(ctxT(t), "gts", b, "n1", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if lv, err := h.l.ACMEBudgetLevel(ctxT(t), b, []string{"n1"}); err != nil || lv != 0 {
		t.Fatalf("an overspent bucket level = %v (%v), want 0", lv, err)
	}
	if lv, err := h.l.ACMEBudgetLevel(ctxT(t), Bucket{Key: "zero"}, nil); err != nil || lv != 0 {
		t.Fatalf("a zero-capacity level = %v (%v), want 0", lv, err)
	}
}

func TestACMEBudget_UnparseableTreatedFull(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 1, Period: time.Hour, Burst: 1}.Bucket("le:orders")
	if err := h.rdb.HSet(ctxT(t), budgetKey(b), "t", "garbage", "at", "x").Err(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.reserve(t, b, "n1", "m1", h.now.Add(time.Minute), "n1"); !ok {
		t.Fatal("an unparseable budget must read as full")
	}
	if !strings.Contains(h.log.String(), `msg="unparseable acme budget (treated as full)"`) {
		t.Fatalf("the unparseable budget must be logged; log = %q", h.log.String())
	}
}

func TestBudgetLock_Contended(t *testing.T) {
	h := newBudgetHarness(t)
	if err := h.rdb.Set(ctxT(t), budgetLockKey("letsencrypt"), "someone-else", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	err := h.l.withBudgetLock(ctxT(t), "letsencrypt", func() error { return nil })
	if !errors.Is(err, ErrBudgetLockContended) {
		t.Fatalf("err = %v, want ErrBudgetLockContended", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.l.withBudgetLock(ctx, "letsencrypt", func() error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the ctx error", err)
	}
	if v, err := h.rdb.Get(ctxT(t), budgetLockKey("letsencrypt")).Result(); err != nil || v != "someone-else" {
		t.Fatalf("another holder's lock must be left alone: %q %v", v, err)
	}
}

func TestBudgetKeys_AllHaveTTL(t *testing.T) {
	h := newBudgetHarness(t)
	ctx := ctxT(t)
	b := Rate{Count: 3, Period: time.Hour, Burst: 3}.Bucket("le:orders")
	r := Rate{Count: 3, Period: time.Minute, Burst: 3}.Bucket("gts:requests")
	d := Rate{Count: 3, Period: time.Minute, Burst: 3}.Bucket("le:domain")
	if ok, _ := h.reserve(t, b, "n1", "m1", h.now.Add(time.Minute), "n1"); !ok {
		t.Fatal("reservation must fit")
	}
	if err := h.l.CommitACME(ctx, "letsencrypt", b, "n1", "m2"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.l.TakeACME(ctx, "gts", []Bucket{r}); err != nil {
		t.Fatal(err)
	}
	if err := h.l.ResyncACME(ctx, "letsencrypt", []Bucket{d}, time.Minute); err != nil {
		t.Fatal(err)
	}
	keys := h.mr.Keys()
	var checked int
	for _, k := range keys {
		if strings.HasPrefix(k, "acme-budget:") || strings.HasPrefix(k, "acme:inflight:") {
			checked++
			if h.mr.TTL(k) <= 0 {
				t.Errorf("key %s has no TTL", k)
			}
		}
	}
	if checked != 4 {
		t.Fatalf("checked %d budget keys (%v), want 4", checked, keys)
	}
}

func TestReserveACME_InflightTTLNeverShortened(t *testing.T) {
	h := newBudgetHarness(t)
	b := Rate{Count: 3, Period: time.Hour, Burst: 3}.Bucket("le:orders")
	if ok, _ := h.reserve(t, b, "n1", "long", h.now.Add(10*time.Minute), "n1"); !ok {
		t.Fatal("reservation must fit")
	}
	if ok, _ := h.reserve(t, b, "n1", "short", h.now.Add(30*time.Second), "n1"); !ok {
		t.Fatal("reservation must fit")
	}
	if ttl := h.mr.TTL(inflightKey(b, "n1")); ttl < 10*time.Minute {
		t.Fatalf("in-flight TTL = %s, want ≥ 10 min (never shortened)", ttl)
	}
	lv, err := h.l.ACMEBudgetLevel(ctxT(t), b, []string{"n1"})
	if err != nil || math.Abs(lv-1.0/3) > 1e-9 {
		t.Fatalf("level = %v (%v), want both reservations counted (1/3)", lv, err)
	}
}
