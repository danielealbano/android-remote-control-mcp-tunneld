package metrics

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

type acmeBudgetCollector struct {
	desc       *prometheus.Desc
	levels     func(context.Context) ([]ACMEBudgetLevel, error)
	logger     *slog.Logger
	mu         sync.Mutex
	warned     time.Time
	suppressed int
}

func (c *acmeBudgetCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *acmeBudgetCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), acmeBudgetScrapeTimeout)
	defer cancel()
	levels, err := c.levels(ctx)
	if err != nil {
		c.warn(err)
		return
	}
	c.reportSuppressed()
	for _, l := range levels {
		m, err := prometheus.NewConstMetric(c.desc, prometheus.GaugeValue, l.Ratio, l.CA, l.Account, l.Budget)
		if err != nil {
			c.warn(err)
			continue
		}
		ch <- m
	}
}

func (c *acmeBudgetCollector) warn(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.warned) < acmeBudgetWarnEvery {
		c.suppressed++
		return
	}
	c.logger.Warn("acme budget metrics unavailable for this scrape", "err", err, "suppressed_since_last_report", c.suppressed)
	c.warned, c.suppressed = time.Now(), 0
}

func (c *acmeBudgetCollector) reportSuppressed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.suppressed == 0 || time.Since(c.warned) < acmeBudgetWarnEvery {
		return
	}
	c.logger.Warn("acme budget metrics: scrape errors since the last report", "count", c.suppressed)
	c.warned, c.suppressed = time.Now(), 0
}

func (m *Metrics) RegisterACMEBudgets(levels func(context.Context) ([]ACMEBudgetLevel, error), logger *slog.Logger) error {
	if levels == nil || logger == nil {
		return errors.New("metrics: acme budget levels and logger are required")
	}
	return m.reg.Register(&acmeBudgetCollector{
		desc: prometheus.NewDesc("tunneld_acme_budget_ratio",
			"Remaining ACME issuance budget (0-1) by CA, account and budget.", []string{"ca", "account", "budget"}, nil),
		levels: levels,
		logger: logger,
	})
}
