package metrics

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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

func gatherFamilies(t *testing.T, reg *prometheus.Registry) map[string][]string {
	t.Helper()
	fams, err := reg.Gather()
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
	if err := m.RegisterACMEBudgets(func(context.Context) ([]ACMEBudgetLevel, error) { return levels, nil }, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	fams, err := m.Registry().Gather()
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
	c := &acmeBudgetCollector{
		desc: prometheus.NewDesc("tunneld_acme_budget_ratio", "test", []string{"ca", "account", "budget"}, nil),
		levels: func(context.Context) ([]ACMEBudgetLevel, error) {
			if fail.Load() {
				return nil, errors.New("valkey down")
			}
			return []ACMEBudgetLevel{{CA: "letsencrypt", Account: "local", Budget: "orders", Ratio: 1}}, nil
		},
		logger: slog.New(slog.NewTextHandler(logs, nil)),
	}
	m := NewMetrics()
	if err := m.Registry().Register(c); err != nil {
		t.Fatal(err)
	}
	ageWindow := func() {
		c.mu.Lock()
		c.warned = c.warned.Add(-2 * acmeBudgetWarnEvery)
		c.mu.Unlock()
	}
	const unavailable = `msg="acme budget metrics unavailable for this scrape"`
	const pending = `msg="acme budget metrics: scrape errors since the last report"`

	fail.Store(true)
	fams := gatherFamilies(t, m.Registry())
	if _, ok := fams["tunneld_acme_budget_ratio"]; ok {
		t.Fatal("a source error must drop the budget family for the scrape")
	}
	if _, ok := fams["tunneld_acme_issue_total"]; !ok {
		t.Fatal("a source error must keep the other families")
	}
	gatherFamilies(t, m.Registry())
	if n := strings.Count(logs.String(), unavailable); n != 1 || !strings.Contains(logs.String(), "suppressed_since_last_report=0") {
		t.Fatalf("two failing scrapes within a minute must log one Warn; log = %q", logs.String())
	}

	ageWindow()
	gatherFamilies(t, m.Registry())
	if n := strings.Count(logs.String(), unavailable); n != 2 || !strings.Contains(logs.String(), "suppressed_since_last_report=1") {
		t.Fatalf("the next Warn after the window must carry the suppressed count; log = %q", logs.String())
	}

	gatherFamilies(t, m.Registry())
	ageWindow()
	fail.Store(false)
	if _, ok := gatherFamilies(t, m.Registry())["tunneld_acme_budget_ratio"]; !ok {
		t.Fatal("a successful scrape must expose the budget family")
	}
	gatherFamilies(t, m.Registry())
	if n := strings.Count(logs.String(), pending); n != 1 || !strings.Contains(logs.String(), pending+" count=1") {
		t.Fatalf("a successful scrape after the window must log the pending count once; log = %q", logs.String())
	}
}

func TestRegisterACMEBudgets_RejectsNil(t *testing.T) {
	t.Parallel()
	levels := func(context.Context) ([]ACMEBudgetLevel, error) { return nil, nil }
	if err := NewMetrics().RegisterACMEBudgets(nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("a nil levels func must be refused")
	}
	if err := NewMetrics().RegisterACMEBudgets(levels, nil); err == nil {
		t.Fatal("a nil logger must be refused")
	}
}
