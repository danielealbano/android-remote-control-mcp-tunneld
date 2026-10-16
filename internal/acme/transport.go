package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

var (
	errOrderAbandoned = errors.New("acme: order attempt abandoned")
	errAccountCooling = errors.New("acme: account is waiting out a CA rate limit")
	errAccountBudget  = errors.New("acme: account has no request budget left")
)

const (
	maxACMEBody     = 1 << 20
	budgetOpTimeout = 3 * time.Second
)

type requestBudget interface {
	TakeACME(ctx context.Context, ca string, bs []limit.Bucket) (time.Duration, error)
	ResyncACME(ctx context.Context, ca string, bs []limit.Bucket, retryAfter time.Duration) error
}

type accountCooldowns interface {
	CACooldown(ctx context.Context, ca string) (time.Duration, error)
	SetCACooldown(ctx context.Context, ca string, d time.Duration) error
}

type budgetTransport struct {
	base      http.RoundTripper
	acct      *account
	budgets   Budgets
	requests  requestBudget
	cooldowns accountCooldowns
	recorder  Recorder
	cooldown  time.Duration
	firstPoll time.Duration
	pollEvery time.Duration
	logger    *slog.Logger
	now       func() time.Time
}

func (t *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr := trackFrom(req.Context())
	if err := t.before(req, tr); err != nil {
		if req.Body != nil {
			if cerr := req.Body.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
		}
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return t.rateLimited(req.Context(), resp, tr)
	}
	if tr == nil {
		return resp, nil
	}
	return t.observe(req, resp, tr)
}

func (t *budgetTransport) before(req *http.Request, tr *orderTrack) error {
	ctx := req.Context()
	if tr != nil && tr.abandoned() {
		return errOrderAbandoned
	}
	cool := t.cooling(ctx)
	bs := t.budgets.requestBuckets(t.acct, req)
	if tr == nil {
		if cool > 0 {
			return errAccountCooling
		}
		wait, err := t.take(ctx, bs)
		if err != nil {
			t.logger.Warn("acme request budget unavailable (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
			return nil
		}
		if wait > 0 {
			return errAccountBudget
		}
		return nil
	}
	poll := tr.isPoll(req.URL.String())
	for {
		for ; cool > 0; cool = t.cooling(ctx) {
			if err := t.sleep(ctx, tr, cool); err != nil {
				return err
			}
		}
		if poll {
			if d := tr.pollDue(t.firstPoll, t.pollEvery).Sub(t.now()); d > 0 {
				if err := t.sleep(ctx, tr, d); err != nil {
					return err
				}
				cool = t.cooling(ctx)
				continue
			}
		}
		wait, err := t.take(ctx, bs)
		if err != nil {
			t.logger.Warn("acme request budget unavailable (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
			wait = 0
		}
		if wait <= 0 {
			if poll {
				tr.markPoll(t.now())
			}
			return nil
		}
		if err := t.sleep(ctx, tr, wait); err != nil {
			return err
		}
		cool = t.cooling(ctx)
	}
}

func (t *budgetTransport) cooling(ctx context.Context) time.Duration {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	cool, err := t.cooldowns.CACooldown(octx, t.acct.id)
	if err != nil {
		t.logger.Warn("acme account wait-until check failed (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
		return 0
	}
	return cool
}

func (t *budgetTransport) take(ctx context.Context, bs []limit.Bucket) (time.Duration, error) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	return t.requests.TakeACME(octx, t.acct.ca, bs)
}

func (t *budgetTransport) sleep(ctx context.Context, tr *orderTrack, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tr.done:
		return errOrderAbandoned
	case <-timer.C:
		return nil
	}
}

func (t *budgetTransport) rateLimited(ctx context.Context, resp *http.Response, tr *orderTrack) (*http.Response, error) {
	t.recorder.ACMERateLimited(t.acct.ca)
	header := resp.Header.Get("Retry-After")
	d, perr := retryAfter(header, t.now())
	if perr != nil {
		t.logger.Warn("acme 429 with an unparseable Retry-After (the default cooldown applies)", "ca", t.acct.ca, "account", t.acct.label, "err", perr)
	}
	if d <= 0 {
		d = t.cooldown
	}
	t.setWaitUntil(ctx, d)
	if tr != nil {
		tr.signalLimited(d)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEBody))
	if cerr := resp.Body.Close(); cerr != nil {
		err = errors.Join(err, cerr)
	}
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &problem); err != nil {
		t.logger.Debug("acme 429 body is not a problem document (no budget resync)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
	}
	t.resync(ctx, t.budgets.resyncBuckets(t.acct, problem.Detail, tr), d)
	t.logger.Warn("acme CA answered 429; the account waits", "ca", t.acct.ca, "account", t.acct.label, "retry_after", d, "detail", problem.Detail)
	return resp, nil
}

func (t *budgetTransport) setWaitUntil(ctx context.Context, d time.Duration) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	if err := t.cooldowns.SetCACooldown(octx, t.acct.id, d); err != nil {
		t.logger.Warn("acme account wait-until write failed", "ca", t.acct.ca, "account", t.acct.label, "err", err)
	}
}

func (t *budgetTransport) resync(ctx context.Context, bs []limit.Bucket, d time.Duration) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	if err := t.requests.ResyncACME(octx, t.acct.ca, bs, d); err != nil {
		t.logger.Warn("acme budget resync failed", "ca", t.acct.ca, "account", t.acct.label, "err", err)
	}
}

func (t *budgetTransport) observe(req *http.Request, resp *http.Response, tr *orderTrack) (*http.Response, error) {
	if tr.isFinalize(req.URL.String()) {
		if resp.StatusCode/100 == 2 {
			tr.markFinalized(t.now())
		}
		return resp, nil
	}
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || location == "" || tr.hasOrder() {
		return resp, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEBody))
	if cerr := resp.Body.Close(); cerr != nil {
		err = errors.Join(err, cerr)
	}
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	var order struct {
		Finalize string `json:"finalize"`
	}
	if err := json.Unmarshal(raw, &order); err != nil {
		t.logger.Debug("acme 201 body is not JSON (not an order)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
		return resp, nil
	}
	if order.Finalize != "" {
		tr.setOrder(location, order.Finalize)
	}
	return resp, nil
}

func retryAfter(v string, now time.Time) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	if sec, err := strconv.Atoi(v); err == nil {
		return time.Duration(sec) * time.Second, nil
	}
	at, err := http.ParseTime(v)
	if err != nil {
		return 0, fmt.Errorf("acme: Retry-After %q is neither seconds nor an HTTP date: %w", v, err)
	}
	return at.Sub(now), nil
}
