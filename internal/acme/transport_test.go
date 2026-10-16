package acme

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type transportHarness struct {
	lim  *limit.Limiter
	rec  *recordingChainRecorder
	logs *lockedBuffer
	bt   *budgetTransport
	hc   *http.Client
}

func newTransportHarness(t *testing.T, acct *account, budgets Budgets) *transportHarness {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	lim := limit.NewLimiter(rdb, 1, 1, 1, time.Hour)
	h := &transportHarness{lim: lim, rec: &recordingChainRecorder{}, logs: &lockedBuffer{}}
	h.bt = &budgetTransport{
		base: http.DefaultTransport, acct: acct, budgets: budgets, requests: lim, cooldowns: lim,
		recorder: h.rec, cooldown: 2 * time.Second, firstPoll: 300 * time.Millisecond, pollEvery: 200 * time.Millisecond,
		logger: slog.New(slog.NewTextHandler(h.logs, nil)), now: time.Now,
	}
	h.hc = &http.Client{Transport: h.bt}
	return h
}

type caServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []time.Time
	path []string
}

func startCAServer(t *testing.T, handler http.HandlerFunc) *caServer {
	t.Helper()
	cs := &caServer{}
	cs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.hits = append(cs.hits, time.Now())
		cs.path = append(cs.path, r.URL.Path)
		cs.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(cs.srv.Close)
	return cs
}

func (cs *caServer) count() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.hits)
}

func (cs *caServer) hitTimes() []time.Time {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]time.Time(nil), cs.hits...)
}

func (h *transportHarness) do(t *testing.T, ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.hc.Do(req)
	if err == nil {
		t.Cleanup(func() { tunneltest.CloseOrLog(t, resp.Body) })
	}
	return resp, err
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const leDomainDetail = `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates (50) already issued for \"example.com\" in the last 168h0m0s: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-registered-domain"}`

func TestBudgetTransport_429(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	h := newTransportHarness(t, acct, testBudgets())
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := io.WriteString(w, leDomainDetail); err != nil {
			t.Error(err)
		}
	})
	b := testBudgets()
	tr := newOrderTrack(b.leName("p.example.com"), b.leDomain("p.example.com"))
	ctx := context.Background()
	resp, err := h.do(t, withTrack(ctx, tr), http.MethodPost, ca.srv.URL+"/new-order", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests || readAll(t, resp.Body) != leDomainDetail {
		t.Fatal("the 429 and its body must reach lego intact")
	}
	if got := h.rec.rateLimited; len(got) != 1 || got[0] != CALetsEncrypt {
		t.Fatalf("recorded 429s = %v, want one for letsencrypt", got)
	}
	if cool, err := h.lim.CACooldown(ctx, acct.id); err != nil || cool != 7*time.Second {
		t.Fatalf("account wait-until = %s (%v), want 7 s", cool, err)
	}
	if wait, err := h.lim.TakeACME(ctx, CALetsEncrypt, []limit.Bucket{b.leDomain("p.example.com")}); err != nil || wait <= 6*time.Second {
		t.Fatalf("the domain bucket must be resynced to the Retry-After, wait = %s (%v)", wait, err)
	}
	for _, other := range []limit.Bucket{b.leOrders(acct), b.leName("p.example.com")} {
		if wait, err := h.lim.TakeACME(ctx, CALetsEncrypt, []limit.Bucket{other}); err != nil || wait != 0 {
			t.Fatalf("bucket %s must not be resynced, wait = %s (%v)", other.Key, wait, err)
		}
	}
	select {
	case d := <-tr.limited:
		if d != 7*time.Second {
			t.Fatalf("tracker signalled %s, want 7 s", d)
		}
	default:
		t.Fatal("the tracker must be signalled")
	}
}

func TestBudgetTransport_429NeverShortens(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	h := newTransportHarness(t, acct, testBudgets())
	ctx := context.Background()
	if err := h.lim.SetCACooldown(ctx, acct.id, time.Minute); err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"5"}},
		Body: io.NopCloser(strings.NewReader("{}"))}
	if _, err := h.bt.rateLimited(ctx, resp, nil); err != nil {
		t.Fatal(err)
	}
	if cool, err := h.lim.CACooldown(ctx, acct.id); err != nil || cool != time.Minute {
		t.Fatalf("wait-until = %s (%v), want the longer 60 s kept", cool, err)
	}
}

type scriptedCooldowns struct {
	mu    sync.Mutex
	waits []time.Duration
	reads int
}

func (s *scriptedCooldowns) CACooldown(context.Context, string) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if len(s.waits) == 0 {
		return 0, nil
	}
	d := s.waits[0]
	s.waits = s.waits[1:]
	return d, nil
}

func (s *scriptedCooldowns) SetCACooldown(context.Context, string, time.Duration) error { return nil }

func (s *scriptedCooldowns) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func TestBudgetTransport_HoldsUnderWaitUntil(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	h := newTransportHarness(t, acct, testBudgets())
	h.bt.cooldowns = &scriptedCooldowns{waits: []time.Duration{300 * time.Millisecond}}
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	start := time.Now()
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	if _, err := h.do(t, withTrack(context.Background(), tr), http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
		t.Fatal(err)
	}
	if got := ca.hitTimes(); len(got) != 1 || got[0].Sub(start) < 300*time.Millisecond {
		t.Fatalf("a tracked request under a 300 ms wait-until must reach the CA ≥ 300 ms later, hits %v", got)
	}
}

func TestBudgetTransport_RechecksWaitUntilAfterHolds(t *testing.T) {
	t.Run("wait-until extended during the hold", func(t *testing.T) {
		acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
		h := newTransportHarness(t, acct, testBudgets())
		cd := &scriptedCooldowns{waits: []time.Duration{200 * time.Millisecond, 300 * time.Millisecond}}
		h.bt.cooldowns = cd
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		start := time.Now()
		if _, err := h.do(t, withTrack(context.Background(), newOrderTrack(limit.Bucket{}, limit.Bucket{})), http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
			t.Fatal(err)
		}
		if got := ca.hitTimes(); len(got) != 1 || got[0].Sub(start) < 500*time.Millisecond || cd.readCount() != 3 {
			t.Fatalf("the request must wait both wait-untils (≥ 500 ms) and re-read until none is left: hits %v, reads %d", got, cd.readCount())
		}
	})
	t.Run("wait-until set during a request-budget hold", func(t *testing.T) {
		acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
		budgets := testBudgets()
		budgets.GTSRequests = limit.Rate{Count: 1, Period: time.Second, Burst: 1}
		h := newTransportHarness(t, acct, budgets)
		cd := &scriptedCooldowns{waits: []time.Duration{0, 0, 300 * time.Millisecond}}
		h.bt.cooldowns = cd
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		ctx := withTrack(context.Background(), newOrderTrack(limit.Bucket{}, limit.Bucket{}))
		if _, err := h.do(t, ctx, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := h.do(t, ctx, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
			t.Fatal(err)
		}
		if got := ca.hitTimes(); len(got) != 2 || got[1].Sub(start) < 300*time.Millisecond || cd.readCount() != 4 {
			t.Fatalf("after the budget hold the request must wait the new wait-until: hits %v, reads %d", got, cd.readCount())
		}
	})
	t.Run("wait-until set during the poll hold", func(t *testing.T) {
		acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
		h := newTransportHarness(t, acct, testBudgets())
		cd := &scriptedCooldowns{waits: []time.Duration{0, 0, 300 * time.Millisecond}}
		h.bt.cooldowns = cd
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setOrder(ca.srv.URL+"/order/1", ca.srv.URL+"/finalize/1")
		ctx := withTrack(context.Background(), tr)
		if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/finalize/1", nil); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/order/1", nil); err != nil {
			t.Fatal(err)
		}
		if got := ca.hitTimes(); len(got) != 2 || got[1].Sub(start) < 300*time.Millisecond || cd.readCount() != 4 {
			t.Fatalf("after the poll hold the request must wait the new wait-until: hits %v, reads %d", got, cd.readCount())
		}
	})
}

func TestBudgetTransport_UntrackedRefused(t *testing.T) {
	t.Run("under a wait-until", func(t *testing.T) {
		acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
		h := newTransportHarness(t, acct, testBudgets())
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		if err := h.lim.SetCACooldown(context.Background(), acct.id, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := h.do(t, context.Background(), http.MethodGet, ca.srv.URL+"/directory", nil); !errors.Is(err, errAccountCooling) {
			t.Fatalf("err = %v, want errAccountCooling", err)
		}
		if ca.count() != 0 {
			t.Fatal("nothing may be sent")
		}
	})
	t.Run("without request budget", func(t *testing.T) {
		acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
		budgets := testBudgets()
		budgets.GTSRequests = limit.Rate{Count: 1, Period: time.Hour, Burst: 1}
		h := newTransportHarness(t, acct, budgets)
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		if _, err := h.do(t, context.Background(), http.MethodGet, ca.srv.URL+"/directory", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := h.do(t, context.Background(), http.MethodGet, ca.srv.URL+"/directory", nil); !errors.Is(err, errAccountBudget) {
			t.Fatalf("err = %v, want errAccountBudget", err)
		}
		if ca.count() != 1 {
			t.Fatalf("only the first request may be sent, the CA saw %d", ca.count())
		}
	})
}

type closeRecordingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeRecordingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestBudgetTransport_AbandonedFailsFast(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	h := newTransportHarness(t, acct, testBudgets())
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	t.Run("already abandoned", func(t *testing.T) {
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.abandon()
		body := &closeRecordingBody{Reader: strings.NewReader("{}")}
		req, err := http.NewRequestWithContext(withTrack(context.Background(), tr), http.MethodPost, ca.srv.URL+"/x", body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.bt.RoundTrip(req); !errors.Is(err, errOrderAbandoned) {
			t.Fatalf("err = %v, want errOrderAbandoned", err)
		}
		if !body.closed.Load() || ca.count() != 0 {
			t.Fatalf("the request body must be closed and nothing sent (closed=%v sent=%d)", body.closed.Load(), ca.count())
		}
	})
	if err := h.lim.SetCACooldown(context.Background(), acct.id, time.Minute); err != nil {
		t.Fatal(err)
	}
	t.Run("hold ends on abandon", func(t *testing.T) {
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		time.AfterFunc(100*time.Millisecond, tr.abandon)
		start := time.Now()
		if _, err := h.do(t, withTrack(context.Background(), tr), http.MethodGet, ca.srv.URL+"/x", nil); !errors.Is(err, errOrderAbandoned) {
			t.Fatalf("err = %v, want errOrderAbandoned", err)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("the hold must end on abandon, not at the wait-until")
		}
	})
	t.Run("hold ends on ctx cancel", func(t *testing.T) {
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		ctx, cancel := context.WithTimeout(withTrack(context.Background(), tr), 100*time.Millisecond)
		defer cancel()
		if _, err := h.do(t, ctx, http.MethodGet, ca.srv.URL+"/x", nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want the ctx error", err)
		}
	})
	if ca.count() != 0 {
		t.Fatalf("no held request may reach the CA, it saw %d", ca.count())
	}
}

func TestBudgetTransport_RecordsOrderAndFinalize(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	h := newTransportHarness(t, acct, testBudgets())
	var finalizeStatus atomic.Int32
	finalizeStatus.Store(http.StatusOK)
	var orderBody string
	ca := startCAServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/new-acct":
			w.Header().Set("Location", "/acct/1")
			w.WriteHeader(http.StatusCreated)
			if _, err := io.WriteString(w, `{"status":"valid"}`); err != nil {
				t.Error(err)
			}
		case "/new-order":
			w.Header().Set("Location", "/order/1")
			w.WriteHeader(http.StatusCreated)
			if _, err := io.WriteString(w, orderBody); err != nil {
				t.Error(err)
			}
		case "/finalize/1":
			w.WriteHeader(int(finalizeStatus.Load()))
		}
	})
	orderBody = `{"status":"pending","finalize":"` + ca.srv.URL + `/finalize/1"}`
	for _, status := range []int{http.StatusForbidden, http.StatusOK} {
		finalizeStatus.Store(int32(status))
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		ctx := withTrack(context.Background(), tr)
		if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/new-acct", nil); err != nil {
			t.Fatal(err)
		}
		if tr.hasOrder() {
			t.Fatal("a newAccount 201 (no finalize) is not an order")
		}
		resp, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/new-order", nil)
		if err != nil {
			t.Fatal(err)
		}
		if readAll(t, resp.Body) != orderBody || !tr.hasOrder() {
			t.Fatal("the order must be recorded and its body passed on intact")
		}
		if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/finalize/1", nil); err != nil {
			t.Fatal(err)
		}
		if got := tr.outcome().finalized; got != (status == http.StatusOK) {
			t.Fatalf("finalize answered %d: finalized = %v", status, got)
		}
	}
}

func TestBudgetTransport_PollSchedule(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	h := newTransportHarness(t, acct, testBudgets())
	h.bt.firstPoll = time.Second
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	tr.setOrder(ca.srv.URL+"/order/1", ca.srv.URL+"/finalize/1")
	ctx := withTrack(context.Background(), tr)
	stamp := func(field *time.Time) time.Time {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return *field
	}
	if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/finalize/1", nil); err != nil {
		t.Fatal(err)
	}
	finalizedAt := stamp(&tr.finalizedAt)
	if finalizedAt.IsZero() {
		t.Fatal("a 200 on the finalize URL must mark the order finalized")
	}
	if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/other", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/order/1", nil); err != nil {
		t.Fatal(err)
	}
	lastPoll := stamp(&tr.lastPoll)
	if _, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+"/order/1", nil); err != nil {
		t.Fatal(err)
	}
	hits := ca.hitTimes()
	if len(hits) != 4 {
		t.Fatalf("the CA saw %d requests, want 4", len(hits))
	}
	if !hits[1].Before(finalizedAt.Add(h.bt.firstPoll)) {
		t.Fatalf("a non-poll request must not wait for the poll schedule, came %s after finalize", hits[1].Sub(finalizedAt))
	}
	if hits[2].Before(finalizedAt.Add(h.bt.firstPoll)) {
		t.Fatalf("the first poll must wait the first delay after finalize, came after %s", hits[2].Sub(finalizedAt))
	}
	if hits[3].Before(lastPoll.Add(h.bt.pollEvery)) {
		t.Fatalf("the next poll must wait the interval after the previous one, came after %s", hits[3].Sub(lastPoll))
	}
}

func TestBudgetTransport_RequestBudgetWaits(t *testing.T) {
	acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
	budgets := testBudgets()
	budgets.GTSRequests = limit.Rate{Count: 2, Period: time.Second, Burst: 2}
	h := newTransportHarness(t, acct, budgets)
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	ctx := withTrack(context.Background(), newOrderTrack(limit.Bucket{}, limit.Bucket{}))
	for range 3 {
		if _, err := h.do(t, ctx, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
			t.Fatal(err)
		}
	}
	hits := ca.hitTimes()
	if len(hits) != 3 || hits[2].Sub(hits[0]) < 400*time.Millisecond {
		t.Fatalf("the third request must be held until the next token (≈500 ms), hits %v", hits)
	}
}

type blockingBudget struct{}

func (blockingBudget) TakeACME(ctx context.Context, _ string, _ []limit.Bucket) (time.Duration, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (blockingBudget) ResyncACME(ctx context.Context, _ string, _ []limit.Bucket, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

func (blockingBudget) CACooldown(ctx context.Context, _ string) (time.Duration, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func (blockingBudget) SetCACooldown(ctx context.Context, _ string, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestBudgetTransport_ValkeyCallsBounded(t *testing.T) {
	t.Parallel()
	acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
	h := newTransportHarness(t, acct, testBudgets())
	h.bt.requests, h.bt.cooldowns = blockingBudget{}, blockingBudget{}
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	start := time.Now()
	ctx := withTrack(context.Background(), newOrderTrack(limit.Bucket{}, limit.Bucket{}))
	if _, err := h.do(t, ctx, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
		t.Fatalf("a stuck Valkey must fail open, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*budgetOpTimeout+time.Second {
		t.Fatalf("each Valkey call must be bounded by budgetOpTimeout, the request took %s", elapsed)
	}
	if ca.count() != 1 {
		t.Fatal("the request must be sent")
	}
	for _, want := range []string{`msg="acme account wait-until check failed (request sent)"`, `msg="acme request budget unavailable (request sent)"`} {
		if !strings.Contains(h.logs.String(), want) {
			t.Fatalf("log is missing %s; log = %q", want, h.logs.String())
		}
	}
}

func TestRetryAfter_Parse(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{name: "seconds", in: "7", want: 7 * time.Second},
		{name: "http date", in: now.Add(90 * time.Second).Format(http.TimeFormat), want: 90 * time.Second},
		{name: "empty", in: "", want: 0},
		{name: "garbage", in: "soon", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := retryAfter(tc.in, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("retryAfter(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.in) {
				t.Fatalf("the error must name the bad value: %v", err)
			}
			if got != tc.want {
				t.Fatalf("retryAfter(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

type cannedTransport struct{ resp *http.Response }

func (c cannedTransport) RoundTrip(*http.Request) (*http.Response, error) { return c.resp, nil }

func TestBudgetTransport_429EdgeCases(t *testing.T) {
	ctx := context.Background()
	t.Run("unparseable Retry-After", func(t *testing.T) {
		acct := &account{ca: CAZeroSSL, id: "zs-acct", label: "local"}
		h := newTransportHarness(t, acct, testBudgets())
		resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"soon"}},
			Body: io.NopCloser(strings.NewReader("{}"))}
		if _, err := h.bt.rateLimited(ctx, resp, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(h.logs.String(), `msg="acme 429 with an unparseable Retry-After (the default cooldown applies)"`) {
			t.Fatalf("the bad header must be logged; log = %q", h.logs.String())
		}
		if cool, err := h.lim.CACooldown(ctx, acct.id); err != nil || cool != 2*time.Second {
			t.Fatalf("wait-until = %s (%v), want the 2 s default cooldown", cool, err)
		}
	})
	t.Run("unreadable body", func(t *testing.T) {
		acct := &account{ca: CAZeroSSL, id: "zs-acct", label: "local"}
		h := newTransportHarness(t, acct, testBudgets())
		h.bt.base = cannedTransport{resp: &http.Response{StatusCode: http.StatusTooManyRequests,
			Header: http.Header{"Retry-After": {"9"}}, Body: io.NopCloser(failingReader{})}}
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		req, err := http.NewRequestWithContext(withTrack(ctx, tr), http.MethodPost, "https://ca.example.test/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.bt.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("err = %v, want the body read error", err)
		}
		if cool, err := h.lim.CACooldown(ctx, acct.id); err != nil || cool != 9*time.Second {
			t.Fatalf("wait-until = %s (%v), want 9 s from the header", cool, err)
		}
		select {
		case d := <-tr.limited:
			if d != 9*time.Second {
				t.Fatalf("tracker signalled %s, want 9 s", d)
			}
		default:
			t.Fatal("the tracker must be signalled even when the body cannot be read")
		}
	})
}

func TestBudgetTransport_UnansweredOrderAndFinalizeCount(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	ca := startCAServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/refused") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		<-r.Context().Done()
	})
	tests := []struct {
		name          string
		order         bool
		path          string
		wantCreated   bool
		wantFinalized bool
	}{
		{name: "new order still in flight", path: "/new-order", wantCreated: true},
		{name: "new order refused", path: "/new-order/refused"},
		{name: "finalize still in flight", order: true, path: "/finalize/1", wantCreated: true, wantFinalized: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTransportHarness(t, acct, testBudgets())
			tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
			if tc.order {
				tr.setOrder(ca.srv.URL+"/order/1", ca.srv.URL+"/finalize/1")
			}
			ctx, cancel := context.WithTimeout(withTrack(context.Background(), tr), 200*time.Millisecond)
			defer cancel()
			resp, err := h.do(t, ctx, http.MethodPost, ca.srv.URL+tc.path, nil)
			if (err == nil) != strings.HasSuffix(tc.path, "/refused") {
				t.Fatalf("POST %s: resp %v, err %v", tc.path, resp, err)
			}
			if out := tr.outcome(); out.created != tc.wantCreated || out.finalized != tc.wantFinalized {
				t.Fatalf("outcome %+v, want created %v finalized %v", out, tc.wantCreated, tc.wantFinalized)
			}
		})
	}
}
