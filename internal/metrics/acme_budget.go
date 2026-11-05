package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
)

const (
	acmeBudgetScrapeTimeout = 2 * time.Second
	acmeBudgetWarnEvery     = time.Minute
)

type ACMEBudgetLevel struct {
	CA      string
	Account string
	Budget  string
	Ratio   float64
}

type acmeBudgetSource struct {
	desc       *prometheus.Desc
	levels     func(context.Context) ([]ACMEBudgetLevel, error)
	logger     *slog.Logger
	mu         sync.Mutex
	warned     time.Time
	suppressed int
}

type acmeBudgetCollector struct {
	src *acmeBudgetSource
	ctx context.Context
}

func (c *acmeBudgetCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.src.desc }

func (c *acmeBudgetCollector) Collect(ch chan<- prometheus.Metric) {
	defer report.Recover(c.ctx, c.src.logger, "ACME budget metrics", func() {})
	ctx, cancel := context.WithTimeout(c.ctx, acmeBudgetScrapeTimeout)
	defer cancel()
	levels, err := c.src.levels(ctx)
	if err != nil {
		c.src.warn(err)
		return
	}
	c.src.reportSuppressed()
	for _, l := range levels {
		m, err := prometheus.NewConstMetric(c.src.desc, prometheus.GaugeValue, l.Ratio, l.CA, l.Account, l.Budget)
		if err != nil {
			c.src.warn(err)
			continue
		}
		ch <- m
	}
}

func (s *acmeBudgetSource) warn(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.warned) < acmeBudgetWarnEvery {
		s.suppressed++
		return
	}
	s.logger.Warn("issuance budget metrics are missing from this scrape", "err", err, "suppressed_since_last_report", s.suppressed)
	s.warned, s.suppressed = time.Now(), 0
}

func (s *acmeBudgetSource) reportSuppressed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.suppressed == 0 || time.Since(s.warned) < acmeBudgetWarnEvery {
		return
	}
	s.logger.Warn("issuance budget metrics were missing from more scrapes since the last report", "count", s.suppressed)
	s.warned, s.suppressed = time.Now(), 0
}

type acmeBudgetDescriber struct {
	desc *prometheus.Desc
}

func (d acmeBudgetDescriber) Describe(ch chan<- *prometheus.Desc) { ch <- d.desc }

func (acmeBudgetDescriber) Collect(chan<- prometheus.Metric) {}

func (m *Metrics) RegisterACMEBudgets(levels func(context.Context) ([]ACMEBudgetLevel, error), logger *slog.Logger) error {
	if levels == nil || logger == nil {
		return errors.New("metrics: acme budget levels and logger are required")
	}
	src := &acmeBudgetSource{
		desc: prometheus.NewDesc("tunneld_acme_budget_ratio",
			"Remaining ACME issuance budget (0-1) by CA, account and budget.", []string{"ca", "account", "budget"}, nil),
		levels: levels,
		logger: logger,
	}
	if err := m.reg.Register(acmeBudgetDescriber{desc: src.desc}); err != nil {
		return fmt.Errorf("metrics: register the acme budget descriptor: %w", err)
	}
	m.budgets = src
	return nil
}

func (m *Metrics) Gatherer(ctx context.Context) prometheus.Gatherer {
	if m.budgets == nil {
		return m.reg
	}
	scrape := prometheus.NewRegistry()
	if err := scrape.Register(&acmeBudgetCollector{src: m.budgets, ctx: ctx}); err != nil {
		m.budgets.warn(err)
		return m.reg
	}
	return prometheus.Gatherers{m.reg, scrape}
}
