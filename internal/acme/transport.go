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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

var (
	linkValue    = regexp.MustCompile(`<[^>]*>[^<]*`)
	alternateRel = regexp.MustCompile(`;\s*rel="alternate"`)
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
	CAWaitState(ctx context.Context, ca string) (time.Duration, string, error)
	SetCACooldown(ctx context.Context, ca string, d time.Duration) error
	MarkCALimited(ctx context.Context, ca string, ttl time.Duration) error
}

type budgetTransport struct {
	base      http.RoundTripper
	acct      *account
	budgets   Budgets
	requests  requestBudget
	cooldowns accountCooldowns
	recorder  Recorder
	cooldown  time.Duration
	markTTL   time.Duration
	firstPoll time.Duration
	pollEvery time.Duration
	logger    *slog.Logger
	now       func() time.Time
}

func (t *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := t.now()
	tr := trackFrom(req.Context())
	paid, err := t.before(req, tr)
	if err != nil {
		t.logUnsent(req, start, err)
		return nil, closeRequestBody(req, err)
	}
	if tr == nil {
		resp, err := t.send(req, start)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return t.rateLimited(req.Context(), resp, nil)
		}
		return resp, nil
	}
	sent := tr.markSent(req.Method, req.URL.String())
	if tr.abandoned() {
		tr.markAnswered(sent)
		if paid {
			tr.returnPrepaid()
		}
		t.logUnsent(req, start, errOrderAbandoned)
		return nil, closeRequestBody(req, errOrderAbandoned)
	}
	resp, err := t.send(req, start)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		resp, err = t.rateLimited(req.Context(), resp, tr)
	} else {
		resp, err = t.observe(req, resp, tr)
		if err == nil && resp.StatusCode/100 == 2 {
			if resp.Header.Get("Retry-After") == "" {
				resp.Header.Set("Retry-After", validationPoll(t.acct.ca))
			}
			dropAlternateChains(resp.Header)
		}
	}
	if err == nil {
		tr.markAnswered(sent)
	}
	return resp, err
}

func (t *budgetTransport) send(req *http.Request, start time.Time) (*http.Response, error) {
	sent := t.now()
	resp, err := t.base.RoundTrip(req)
	took := t.now().Sub(sent)
	if err != nil {
		t.logger.Debug("acme request", "ca", t.acct.ca, "account", t.acct.label, "method", req.Method, "path", req.URL.Path,
			"paced", sent.Sub(start), "took", took, "err", err)
		return nil, err
	}
	t.logger.Debug("acme request", "ca", t.acct.ca, "account", t.acct.label, "method", req.Method, "path", req.URL.Path,
		"status", resp.StatusCode, "retry_after", resp.Header.Get("Retry-After"), "paced", sent.Sub(start), "took", took)
	return resp, nil
}

func (t *budgetTransport) logUnsent(req *http.Request, start time.Time, err error) {
	t.logger.Debug("acme request", "ca", t.acct.ca, "account", t.acct.label, "method", req.Method, "path", req.URL.Path,
		"paced", t.now().Sub(start), "err", err)
}

func validationPoll(ca string) string {
	if ca == CAGTS {
		return "2"
	}
	return "1"
}

func dropAlternateChains(h http.Header) {
	if !strings.HasPrefix(h.Get("Content-Type"), "application/pem-certificate-chain") {
		return
	}
	var kept []string
	for _, v := range h.Values("Link") {
		for _, lv := range linkValue.FindAllString(v, -1) {
			lv = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(lv), ","))
			if !alternateRel.MatchString(lv) {
				kept = append(kept, lv)
			}
		}
	}
	h.Del("Link")
	for _, lv := range kept {
		h.Add("Link", lv)
	}
}

func closeRequestBody(req *http.Request, err error) error {
	if req.Body != nil {
		if cerr := req.Body.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}
	return err
}

func (t *budgetTransport) before(req *http.Request, tr *orderTrack) (bool, error) {
	ctx := req.Context()
	if tr != nil && tr.abandoned() {
		return false, errOrderAbandoned
	}
	cool, mark, known := t.waitState(ctx)
	bs := t.budgets.requestBuckets(t.acct, req)
	if tr == nil {
		if cool > 0 {
			return false, errAccountCooling
		}
		wait, err := t.take(ctx, bs)
		if err != nil {
			t.logger.Warn("acme request budget unavailable (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
			return false, nil
		}
		if wait > 0 {
			return false, errAccountBudget
		}
		return false, nil
	}
	poll := tr.isPoll(req.URL.String())
	for {
		for ; cool > 0; cool, mark, known = t.waitState(ctx) {
			if err := t.sleep(ctx, tr, cool); err != nil {
				return false, err
			}
		}
		if poll {
			if d := tr.pollDue(t.firstPoll, t.pollEvery).Sub(t.now()); d > 0 {
				if err := t.sleep(ctx, tr, d); err != nil {
					return false, err
				}
				cool, mark, known = t.waitState(ctx)
				continue
			}
		}
		if n := tr.dropPrepaid(mark, known); n > 0 {
			reason := "the account answered 429"
			if !known {
				reason = "the wait-until check failed"
			}
			t.logger.Debug("acme order dropped its prepaid requests", "ca", t.acct.ca, "account", t.acct.label, "reason", reason, "dropped", n)
		}
		charge := bs
		key, paid := tr.usePrepaid()
		if paid {
			charge = slices.DeleteFunc(slices.Clone(bs), func(b limit.Bucket) bool { return b.Key == key })
		}
		wait, err := t.take(ctx, charge)
		if err != nil {
			t.logger.Warn("acme request budget unavailable (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
			wait = 0
		}
		if wait <= 0 {
			if poll {
				tr.markPoll(t.now())
			}
			return paid, nil
		}
		if paid {
			tr.returnPrepaid()
		}
		if err := t.sleep(ctx, tr, wait); err != nil {
			return false, err
		}
		cool, mark, known = t.waitState(ctx)
	}
}

func (t *budgetTransport) waitState(ctx context.Context) (time.Duration, string, bool) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	cool, mark, err := t.cooldowns.CAWaitState(octx, t.acct.id)
	if err != nil {
		t.logger.Warn("acme account wait-until check failed (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
		return 0, "", false
	}
	return cool, mark, true
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
		return context.Cause(ctx)
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
	t.markLimited(ctx)
	if tr != nil {
		tr.signalLimited(d)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEBody))
	if cerr := resp.Body.Close(); cerr != nil {
		err = errors.Join(err, cerr)
	}
	if err != nil {
		return nil, fmt.Errorf("acme budget transport: read the 429 body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &problem); err != nil {
		t.logger.Debug("acme 429 body is not a problem document (no budget resync)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
	}
	t.resync(ctx, t.budgets.resyncBuckets(t.acct, problem.Detail, tr), d)
	t.markLimited(ctx)
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

func (t *budgetTransport) markLimited(ctx context.Context) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	if err := t.cooldowns.MarkCALimited(octx, t.acct.id, t.markTTL); err != nil {
		t.logger.Warn("acme account 429 mark write failed (running orders keep their prepaid requests)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
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
		return nil, fmt.Errorf("acme budget transport: read the 201 body: %w", err)
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
