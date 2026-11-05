package metrics

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func gatherFamilies(t *testing.T, g prometheus.Gatherer) map[string][]string {
	t.Helper()
	fams, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, f := range fams {
		for _, m := range f.GetMetric() {
			var pairs []string
			for _, lp := range m.GetLabel() {
				pairs = append(pairs, lp.GetName()+"="+lp.GetValue())
			}
			out[f.GetName()] = append(out[f.GetName()], strings.Join(pairs, ","))
		}
	}
	return out
}

func TestACMEBudgetCollector_Emits(t *testing.T) {
	t.Parallel()
	m := NewMetrics()
	levels := []ACMEBudgetLevel{
		{CA: "letsencrypt", Account: "local", Budget: "orders", Ratio: 0.5},
		{CA: "gts", Account: "gts-1", Budget: "cert-polls", Ratio: 1},
	}
	if err := m.RegisterACMEBudgets(func(context.Context) ([]ACMEBudgetLevel, error) { return levels, nil }, testLog()); err != nil {
		t.Fatal(err)
	}
	fams, err := m.Gatherer(context.Background()).Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range fams {
		if f.GetName() != "tunneld_acme_budget_ratio" {
			continue
		}
		for _, mt := range f.GetMetric() {
			var pairs []string
			for _, lp := range mt.GetLabel() {
				pairs = append(pairs, lp.GetName()+"="+lp.GetValue())
			}
			got[strings.Join(pairs, ",")] = mt.GetGauge().GetValue()
		}
	}
	want := map[string]float64{
		"account=local,budget=orders,ca=letsencrypt": 0.5,
		"account=gts-1,budget=cert-polls,ca=gts":     1,
	}
	if len(got) != len(want) {
		t.Fatalf("budget series %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("budget series %v, want %v", got, want)
		}
	}
}

func TestACMEBudgetCollector_ErrorKeepsScrape(t *testing.T) {
	t.Parallel()
	var fail atomic.Bool
	logs := &syncBuffer{}
	m := NewMetrics()
	if err := m.RegisterACMEBudgets(func(context.Context) ([]ACMEBudgetLevel, error) {
		if fail.Load() {
			return nil, errors.New("valkey down")
		}
		return []ACMEBudgetLevel{{CA: "letsencrypt", Account: "local", Budget: "orders", Ratio: 1}}, nil
	}, slog.New(slog.NewTextHandler(logs, nil))); err != nil {
		t.Fatal(err)
	}
	ageWindow := func() {
		m.budgets.mu.Lock()
		m.budgets.warned = m.budgets.warned.Add(-2 * acmeBudgetWarnEvery)
		m.budgets.mu.Unlock()
	}
	const unavailable = `msg="issuance budget metrics are missing from this scrape"`
	const pending = `msg="issuance budget metrics were missing from more scrapes since the last report"`

	fail.Store(true)
	fams := gatherFamilies(t, m.Gatherer(context.Background()))
	if _, ok := fams["tunneld_acme_budget_ratio"]; ok {
		t.Fatal("a source error must drop the budget family for the scrape")
	}
	if _, ok := fams["tunneld_acme_issue_total"]; !ok {
		t.Fatal("a source error must keep the other families")
	}
	gatherFamilies(t, m.Gatherer(context.Background()))
	if n := strings.Count(logs.String(), unavailable); n != 1 || !strings.Contains(logs.String(), "suppressed_since_last_report=0") {
		t.Fatalf("two failing scrapes within a minute must log one Warn; log = %q", logs.String())
	}

	ageWindow()
	gatherFamilies(t, m.Gatherer(context.Background()))
	if n := strings.Count(logs.String(), unavailable); n != 2 || !strings.Contains(logs.String(), "suppressed_since_last_report=1") {
		t.Fatalf("the next Warn after the window must carry the suppressed count; log = %q", logs.String())
	}

	gatherFamilies(t, m.Gatherer(context.Background()))
	ageWindow()
	fail.Store(false)
	if _, ok := gatherFamilies(t, m.Gatherer(context.Background()))["tunneld_acme_budget_ratio"]; !ok {
		t.Fatal("a successful scrape must expose the budget family")
	}
	gatherFamilies(t, m.Gatherer(context.Background()))
	if n := strings.Count(logs.String(), pending); n != 1 || !strings.Contains(logs.String(), pending+" count=1") {
		t.Fatalf("a successful scrape after the window must log the pending count once; log = %q", logs.String())
	}
}

func TestACMEBudgetCollector_PanicIsContained(t *testing.T) {
	t.Parallel()
	logs := &syncBuffer{}
	m := NewMetrics()
	if err := m.RegisterACMEBudgets(func(context.Context) ([]ACMEBudgetLevel, error) { panic("budget boom") },
		slog.New(slog.NewTextHandler(logs, nil))); err != nil {
		t.Fatal(err)
	}
	fams := gatherFamilies(t, m.Gatherer(context.Background()))
	if _, ok := fams["tunneld_acme_issue_total"]; !ok {
		t.Fatal("a panicking budget source must keep the other families")
	}
	if out := logs.String(); !strings.Contains(out, "recovered from a crash") || !strings.Contains(out, `where="ACME budget metrics"`) {
		t.Fatalf("the panic must be logged; log = %q", out)
	}
}

func TestRegisterACMEBudgets_RejectsNil(t *testing.T) {
	t.Parallel()
	levels := func(context.Context) ([]ACMEBudgetLevel, error) { return nil, nil }
	if err := NewMetrics().RegisterACMEBudgets(nil, testLog()); err == nil {
		t.Fatal("a nil levels func must be refused")
	}
	if err := NewMetrics().RegisterACMEBudgets(levels, nil); err == nil {
		t.Fatal("a nil logger must be refused")
	}
}

func TestRegisterACMEBudgets_RejectsConflicts(t *testing.T) {
	t.Parallel()
	levels := func(context.Context) ([]ACMEBudgetLevel, error) { return nil, nil }
	tests := []struct {
		name  string
		first func(m *Metrics) error
	}{
		{name: "a second registration", first: func(m *Metrics) error { return m.RegisterACMEBudgets(levels, testLog()) }},
		{name: "another family with the same name", first: func(m *Metrics) error {
			return m.reg.Register(prometheus.NewGauge(prometheus.GaugeOpts{Name: "tunneld_acme_budget_ratio", Help: "other"}))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMetrics()
			if err := tc.first(m); err != nil {
				t.Fatal(err)
			}
			if err := m.RegisterACMEBudgets(levels, testLog()); err == nil {
				t.Fatal("a conflicting registration must be refused at startup")
			}
		})
	}
}

func TestMetrics_Gatherer_BudgetCollectorRegistrationFailure(t *testing.T) {
	t.Parallel()
	logs := &syncBuffer{}
	m := NewMetrics()
	m.budgets = &acmeBudgetSource{
		desc: prometheus.NewDesc("tunneld_acme_budget_ratio", "test", []string{"ca", "ca"}, nil),
		levels: func(context.Context) ([]ACMEBudgetLevel, error) {
			t.Error("a collector that failed to register must not read the budgets")
			return nil, nil
		},
		logger: slog.New(slog.NewTextHandler(logs, nil)),
	}
	fams := gatherFamilies(t, m.Gatherer(context.Background()))
	if _, ok := fams["tunneld_acme_issue_total"]; !ok {
		t.Fatal("a failed budget collector registration must keep the other families")
	}
	if n := strings.Count(logs.String(), `msg="issuance budget metrics are missing from this scrape"`); n != 1 {
		t.Fatalf("a failed budget collector registration must log one Warn; log = %q", logs.String())
	}
}

type scrapeCtxKey struct{}

type scrapeCtxState struct {
	value       any
	left        time.Duration
	hasDeadline bool
}

func TestMetricsHandler_BudgetScrapeUsesTheRequestContext(t *testing.T) {
	t.Parallel()
	m, _, store, _, rdb := setup(t)
	seen := make(chan scrapeCtxState, 1)
	if err := m.RegisterACMEBudgets(func(ctx context.Context) ([]ACMEBudgetLevel, error) {
		d, ok := ctx.Deadline()
		seen <- scrapeCtxState{value: ctx.Value(scrapeCtxKey{}), left: time.Until(d), hasDeadline: ok}
		return []ACMEBudgetLevel{{CA: "letsencrypt", Account: "local", Budget: "orders", Ratio: 1}}, nil
	}, testLog()); err != nil {
		t.Fatal(err)
	}
	h := Handler(m.Gatherer, rdb, store, &fakeNodeSrc{}, testLog())
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(context.WithValue(context.Background(), scrapeCtxKey{}, "scrape"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "tunneld_acme_budget_ratio") {
		t.Fatalf("/metrics = %d, want 200 with the budget family; body = %q", rr.Code, rr.Body.String())
	}
	got := <-seen
	if got.value != "scrape" {
		t.Fatal("the budget read must run on the scrape request's context, not a new background one")
	}
	if !got.hasDeadline || got.left <= 0 || got.left > acmeBudgetScrapeTimeout {
		t.Fatalf("the budget read ran with %s left (deadline set: %v), want the (0, %s] scrape bound", got.left, got.hasDeadline, acmeBudgetScrapeTimeout)
	}
}
