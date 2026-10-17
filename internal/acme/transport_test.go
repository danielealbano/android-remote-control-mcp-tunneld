package acme

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
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
	mr   *miniredis.Miniredis
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
	h := &transportHarness{mr: mr, lim: lim, rec: &recordingChainRecorder{}, logs: &lockedBuffer{}}
	h.bt = &budgetTransport{
		base: http.DefaultTransport, acct: acct, budgets: budgets, requests: lim, cooldowns: lim,
		recorder: h.rec, cooldown: 2 * time.Second, markTTL: 3 * time.Minute, firstPoll: 300 * time.Millisecond, pollEvery: 200 * time.Millisecond,
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

func (h *transportHarness) do(ctx context.Context, t *testing.T, method, url string, body io.Reader) (*http.Response, error) {
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
	resp, err := h.do(withTrack(ctx, tr), t, http.MethodPost, ca.srv.URL+"/new-order", nil)
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
	_, mark, err := h.lim.CAWaitState(ctx, acct.id)
	if err != nil || mark == "" {
		t.Fatalf("429 mark = %q (%v), want one", mark, err)
	}
	if ttl := h.mr.TTL("acme-429:" + acct.id); ttl != h.bt.markTTL {
		t.Fatalf("429 mark TTL = %s, want the transport's %s", ttl, h.bt.markTTL)
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
	if _, mark, err := h.lim.CAWaitState(ctx, acct.id); err != nil || mark == "" {
		t.Fatalf("429 mark = %q (%v), want one even when the wait-until is not extended", mark, err)
	}
}

type markRecorder struct {
	bounds []time.Duration
	ttls   []time.Duration
}

func (m *markRecorder) CAWaitState(context.Context, string) (time.Duration, string, error) {
	return 0, "", nil
}

func (m *markRecorder) SetCACooldown(context.Context, string, time.Duration) error { return nil }

func (m *markRecorder) MarkCALimited(ctx context.Context, _ string, ttl time.Duration) error {
	if dl, ok := ctx.Deadline(); ok {
		m.bounds = append(m.bounds, time.Until(dl))
	}
	m.ttls = append(m.ttls, ttl)
	return errors.New("valkey down")
}

type callOrder struct {
	mu    sync.Mutex
	calls []string
}

func (c *callOrder) add(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, name)
}

func (c *callOrder) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func (c *callOrder) TakeACME(context.Context, string, []limit.Bucket) (time.Duration, error) {
	c.add("take")
	return 0, nil
}

func (c *callOrder) ResyncACME(context.Context, string, []limit.Bucket, time.Duration) error {
	c.add("resync")
	return nil
}

func (c *callOrder) CAWaitState(context.Context, string) (time.Duration, string, error) {
	c.add("wait-state")
	return 0, "", nil
}

func (c *callOrder) SetCACooldown(context.Context, string, time.Duration) error {
	c.add("wait-until")
	return nil
}

func (c *callOrder) MarkCALimited(context.Context, string, time.Duration) error {
	c.add("mark")
	return nil
}

func TestBudgetTransport_429MarksAfterTheResync(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    io.Reader
		wantErr bool
		want    []string
	}{
		{name: "the account is marked before and after the budget resync", body: strings.NewReader("{}"), want: []string{"wait-until", "mark", "resync", "mark"}},
		{name: "an unreadable 429 body still marks the account", body: iotest.ErrReader(errors.New("boom")), wantErr: true, want: []string{"wait-until", "mark"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
			h := newTransportHarness(t, acct, testBudgets())
			calls := &callOrder{}
			h.bt.requests, h.bt.cooldowns = calls, calls
			resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"5"}}, Body: io.NopCloser(tc.body)}
			if _, err := h.bt.rateLimited(context.Background(), resp, nil); (err != nil) != tc.wantErr {
				t.Fatalf("rateLimited error = %v, want error %v", err, tc.wantErr)
			}
			if got := calls.got(); !slices.Equal(got, tc.want) {
				t.Fatalf("Valkey calls = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBudgetTransport_HeldRequestReportsTheAttemptDeadline(t *testing.T) {
	t.Parallel()
	acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
	h := newTransportHarness(t, acct, testBudgets())
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	if err := h.lim.SetCACooldown(context.Background(), acct.id, time.Minute); err != nil {
		t.Fatal(err)
	}
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	ctx, cancel := attemptContext(withTrack(context.Background(), tr), tr, 50*time.Millisecond, time.Hour)
	defer cancel()
	if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/authz/1", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a request held past the attempt deadline = %v, want context.DeadlineExceeded", err)
	}
	if ca.count() != 0 {
		t.Fatal("a held request must not be sent")
	}
}

func TestBudgetTransport_429MarkWriteFailureBoundedAndLogged(t *testing.T) {
	t.Parallel()
	acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
	h := newTransportHarness(t, acct, testBudgets())
	marks := &markRecorder{}
	h.bt.cooldowns = marks
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"5"}},
		Body: io.NopCloser(strings.NewReader("{}"))}
	if _, err := h.bt.rateLimited(context.Background(), resp, nil); err != nil {
		t.Fatal(err)
	}
	if len(marks.bounds) != 2 {
		t.Fatalf("mark writes = %d, want one before and one after the resync", len(marks.bounds))
	}
	for i, bound := range marks.bounds {
		if bound <= 0 || bound > budgetOpTimeout || marks.ttls[i] != h.bt.markTTL {
			t.Fatalf("mark write %d: deadline %s, TTL %s; want within budgetOpTimeout (%s) and the transport's %s", i+1, bound, marks.ttls[i], budgetOpTimeout, h.bt.markTTL)
		}
	}
	if want := `msg="acme account 429 mark write failed (running orders keep their prepaid requests)"`; !strings.Contains(h.logs.String(), want) {
		t.Fatalf("log is missing %s; log = %q", want, h.logs.String())
	}
}

type scriptedCooldowns struct {
	mu    sync.Mutex
	waits []time.Duration
	reads int
}

func (s *scriptedCooldowns) CAWaitState(context.Context, string) (time.Duration, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if len(s.waits) == 0 {
		return 0, "", nil
	}
	d := s.waits[0]
	s.waits = s.waits[1:]
	return d, "", nil
}

func (s *scriptedCooldowns) SetCACooldown(context.Context, string, time.Duration) error { return nil }

func (s *scriptedCooldowns) MarkCALimited(context.Context, string, time.Duration) error { return nil }

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
	if _, err := h.do(withTrack(context.Background(), tr), t, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
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
		if _, err := h.do(withTrack(context.Background(), newOrderTrack(limit.Bucket{}, limit.Bucket{})), t, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
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
		if _, err := h.do(ctx, t, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := h.do(ctx, t, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
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
		if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/finalize/1", nil); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/order/1", nil); err != nil {
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
		if _, err := h.do(context.Background(), t, http.MethodGet, ca.srv.URL+"/directory", nil); !errors.Is(err, errAccountCooling) {
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
		if _, err := h.do(context.Background(), t, http.MethodGet, ca.srv.URL+"/directory", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := h.do(context.Background(), t, http.MethodGet, ca.srv.URL+"/directory", nil); !errors.Is(err, errAccountBudget) {
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
		if _, err := h.do(withTrack(context.Background(), tr), t, http.MethodGet, ca.srv.URL+"/x", nil); !errors.Is(err, errOrderAbandoned) {
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
		if _, err := h.do(ctx, t, http.MethodGet, ca.srv.URL+"/x", nil); !errors.Is(err, context.DeadlineExceeded) {
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
		if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/new-acct", nil); err != nil {
			t.Fatal(err)
		}
		if tr.hasOrder() {
			t.Fatal("a newAccount 201 (no finalize) is not an order")
		}
		resp, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/new-order", nil)
		if err != nil {
			t.Fatal(err)
		}
		if readAll(t, resp.Body) != orderBody || !tr.hasOrder() {
			t.Fatal("the order must be recorded and its body passed on intact")
		}
		if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/finalize/1", nil); err != nil {
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
	if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/finalize/1", nil); err != nil {
		t.Fatal(err)
	}
	finalizedAt := stamp(&tr.finalizedAt)
	if finalizedAt.IsZero() {
		t.Fatal("a 200 on the finalize URL must mark the order finalized")
	}
	if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/other", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/order/1", nil); err != nil {
		t.Fatal(err)
	}
	lastPoll := stamp(&tr.lastPoll)
	if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/order/1", nil); err != nil {
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
		if _, err := h.do(ctx, t, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
			t.Fatal(err)
		}
	}
	hits := ca.hitTimes()
	if len(hits) != 3 || hits[2].Sub(hits[0]) < 400*time.Millisecond {
		t.Fatalf("the third request must be held until the next token (≈500 ms), hits %v", hits)
	}
}

type blockingBudget struct {
	mu     sync.Mutex
	bounds []time.Duration
}

func (b *blockingBudget) wait(ctx context.Context) error {
	start := time.Now()
	bound := time.Duration(-1)
	if dl, ok := ctx.Deadline(); ok {
		bound = dl.Sub(start)
	}
	b.mu.Lock()
	b.bounds = append(b.bounds, bound)
	b.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (b *blockingBudget) recorded() []time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.bounds)
}

func (b *blockingBudget) TakeACME(ctx context.Context, _ string, _ []limit.Bucket) (time.Duration, error) {
	return 0, b.wait(ctx)
}

func (b *blockingBudget) ResyncACME(ctx context.Context, _ string, _ []limit.Bucket, _ time.Duration) error {
	return b.wait(ctx)
}

func (b *blockingBudget) CAWaitState(ctx context.Context, _ string) (time.Duration, string, error) {
	return 0, "", b.wait(ctx)
}

func (b *blockingBudget) SetCACooldown(ctx context.Context, _ string, _ time.Duration) error {
	return b.wait(ctx)
}

func (b *blockingBudget) MarkCALimited(ctx context.Context, _ string, _ time.Duration) error {
	return b.wait(ctx)
}

func TestBudgetTransport_ValkeyCallsBounded(t *testing.T) {
	t.Parallel()
	acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
	h := newTransportHarness(t, acct, testBudgets())
	stuck := &blockingBudget{}
	h.bt.requests, h.bt.cooldowns = stuck, stuck
	h.bt.logger = slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	tr.setPrepaid(testBudgets().gtsRequests(acct).Key, 2, "")
	if _, err := h.do(withTrack(context.Background(), tr), t, http.MethodGet, ca.srv.URL+"/x", nil); err != nil {
		t.Fatalf("a stuck Valkey must fail open, got %v", err)
	}
	if left, _ := tr.drainPrepaid(); left != 0 {
		t.Fatalf("prepaid left %d, want the balance dropped when the 429 mark cannot be read", left)
	}
	bounds := stuck.recorded()
	if len(bounds) != 2 {
		t.Fatalf("want the wait-until check and the budget take, got %d Valkey calls", len(bounds))
	}
	for i, b := range bounds {
		if b <= 0 || b > budgetOpTimeout {
			t.Fatalf("Valkey call %d ran with a deadline %s away, want at most budgetOpTimeout (%s)", i+1, b, budgetOpTimeout)
		}
	}
	if ca.count() != 1 {
		t.Fatal("the request must be sent")
	}
	for _, want := range []string{`msg="acme account wait-until check failed (request sent)"`, `msg="acme request budget unavailable (request sent)"`,
		`msg="acme order dropped its prepaid requests" ca=gts account=gts-1 reason="the wait-until check failed" dropped=2`} {
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
			resp, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+tc.path, nil)
			if (err == nil) != strings.HasSuffix(tc.path, "/refused") {
				t.Fatalf("POST %s: resp %v, err %v", tc.path, resp, err)
			}
			if out := tr.outcome(); out.created != tc.wantCreated || out.finalized != tc.wantFinalized {
				t.Fatalf("outcome %+v, want created %v finalized %v", out, tc.wantCreated, tc.wantFinalized)
			}
		})
	}
}

type gatedCooldowns struct {
	entered chan struct{}
	release chan struct{}
}

func (g *gatedCooldowns) CAWaitState(ctx context.Context, _ string) (time.Duration, string, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	select {
	case <-g.release:
		return 0, "", nil
	case <-ctx.Done():
		return 0, "", ctx.Err()
	}
}

func (g *gatedCooldowns) SetCACooldown(context.Context, string, time.Duration) error { return nil }

func (g *gatedCooldowns) MarkCALimited(context.Context, string, time.Duration) error { return nil }

func TestBudgetTransport_AbandonedDuringItsChecksNotSent(t *testing.T) {
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	h := newTransportHarness(t, acct, testBudgets())
	gate := &gatedCooldowns{entered: make(chan struct{}, 1), release: make(chan struct{})}
	h.bt.cooldowns = gate
	h.bt.logger = slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	tr.setPrepaid("le:requests:le-acct", 1, "")
	req, err := http.NewRequestWithContext(withTrack(context.Background(), tr), http.MethodPost, ca.srv.URL+"/new-order", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := h.hc.Do(req)
		if resp != nil {
			err = errors.Join(err, resp.Body.Close())
		}
		done <- err
	}()
	<-gate.entered
	tr.abandon()
	close(gate.release)
	if err := <-done; !errors.Is(err, errOrderAbandoned) {
		t.Fatalf("Do = %v, want errOrderAbandoned", err)
	}
	if ca.count() != 0 {
		t.Fatal("a request whose attempt was abandoned during its checks must not be sent")
	}
	if tr.outcome().created {
		t.Fatal("a request that was never sent must not count as a created order")
	}
	if left, _ := tr.drainPrepaid(); left != 1 {
		t.Fatalf("prepaid left %d, want the unit of the refused request given back", left)
	}
	if log := h.logs.String(); !strings.Contains(log, `msg="acme request" ca=letsencrypt account=local method=POST path=/new-order paced=`) ||
		!strings.Contains(log, "err=") || strings.Contains(log, "took=") {
		t.Errorf("a request abandoned during its checks must log paced and err without took; log = %q", log)
	}
}

func TestBudgetTransport_LogsEachRequestAtDebug(t *testing.T) {
	t.Parallel()
	ok := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusOK)
	})
	bare := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	b := testBudgets()
	tests := []struct {
		name    string
		tracked bool
		method  string
		url     string
		want    []string
		wantRA  string
		wantErr bool
	}{
		{name: "untracked", method: http.MethodGet, url: ok.srv.URL + "/directory",
			want: []string{"method=GET", "path=/directory", "status=200", "retry_after=3", "paced=", "took="}, wantRA: "3"},
		{name: "tracked", tracked: true, method: http.MethodPost, url: ok.srv.URL + "/new-order",
			want: []string{"method=POST", "path=/new-order", "status=200", "retry_after=3", "paced=", "took="}, wantRA: "3"},
		{name: "tracked without the CA's Retry-After", tracked: true, method: http.MethodPost, url: bare.srv.URL + "/challenge/x",
			want: []string{"method=POST", "path=/challenge/x", "status=200", `retry_after=""`, "paced=", "took="}, wantRA: "2"},
		{name: "transport error", method: http.MethodGet, url: gone.URL + "/directory", wantErr: true,
			want: []string{"method=GET", "path=/directory", "paced=", "took=", "err="}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
			h := newTransportHarness(t, acct, b)
			h.bt.logger = slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			ctx := context.Background()
			if tc.tracked {
				ctx = withTrack(ctx, newOrderTrack(b.leName("p.example.com"), b.leDomain("p.example.com")))
			}
			resp, err := h.do(ctx, t, tc.method, tc.url, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && resp.Header.Get("Retry-After") != tc.wantRA {
				t.Errorf("response Retry-After = %q, want %q", resp.Header.Get("Retry-After"), tc.wantRA)
			}
			line := ""
			for _, l := range strings.Split(h.logs.String(), "\n") {
				if strings.Contains(l, `msg="acme request"`) {
					line = l
				}
			}
			if !strings.Contains(line, "level=DEBUG") || !strings.Contains(line, "ca=gts account=gts-1") {
				t.Fatalf("want one Debug acme request line for the account; log = %q", h.logs.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(line, w) {
					t.Errorf("line %q lacks %q", line, w)
				}
			}
		})
	}
}

func TestBudgetTransport_ShortRetryAfterOnTrackedResponses(t *testing.T) {
	t.Parallel()
	b := testBudgets()
	tests := []struct {
		name    string
		ca      string
		tracked bool
		status  int
		caRA    string
		want    string
	}{
		{name: "tracked without Retry-After", tracked: true, status: http.StatusOK, want: "2"},
		{name: "Let's Encrypt gets 1 s", ca: CALetsEncrypt, tracked: true, status: http.StatusOK, want: "1"},
		{name: "ZeroSSL gets 1 s", ca: CAZeroSSL, tracked: true, status: http.StatusOK, want: "1"},
		{name: "tracked keeps the CA's value", tracked: true, status: http.StatusOK, caRA: "5", want: "5"},
		{name: "tracked error response untouched", tracked: true, status: http.StatusBadRequest, want: ""},
		{name: "untracked untouched", status: http.StatusOK, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.caRA != "" {
					w.Header().Set("Retry-After", tc.caRA)
				}
				w.WriteHeader(tc.status)
			})
			acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
			if tc.ca != "" {
				acct = &account{ca: tc.ca, id: tc.ca + "-acct", label: "local"}
			}
			h := newTransportHarness(t, acct, b)
			ctx := context.Background()
			if tc.tracked {
				ctx = withTrack(ctx, newOrderTrack(b.leName("p.example.com"), b.leDomain("p.example.com")))
			}
			resp, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/challenge/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := resp.Header.Get("Retry-After"); got != tc.want {
				t.Errorf("Retry-After = %q, want %q", got, tc.want)
			}
		})
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type clockedBudget struct {
	clk  *testClock
	hold time.Duration
}

func (b clockedBudget) TakeACME(context.Context, string, []limit.Bucket) (time.Duration, error) {
	b.clk.advance(b.hold)
	return 0, nil
}

func (b clockedBudget) ResyncACME(context.Context, string, []limit.Bucket, time.Duration) error {
	return nil
}

type clockedRoundTripper struct {
	clk    *testClock
	answer time.Duration
}

func (r clockedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.clk.advance(r.answer)
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
}

func TestBudgetTransport_LogsHoldAndAnswerTimesSeparately(t *testing.T) {
	t.Parallel()
	clk := &testClock{t: time.Unix(1_700_000_000, 0)}
	logs := &lockedBuffer{}
	bt := &budgetTransport{
		base: clockedRoundTripper{clk: clk, answer: 300 * time.Millisecond},
		acct: &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}, budgets: testBudgets(),
		requests: clockedBudget{clk: clk, hold: 600 * time.Millisecond}, cooldowns: &scriptedCooldowns{},
		recorder: &recordingChainRecorder{}, cooldown: 2 * time.Second, now: clk.now,
		logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://ca.example.test/directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := bt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	tunneltest.CloseOrLog(t, resp.Body)
	if want := `path=/directory status=200 retry_after="" paced=600ms took=300ms`; !strings.Contains(logs.String(), want) {
		t.Errorf("want the hold in paced and only the CA's answer in took (%s); log = %q", want, logs.String())
	}
}

func TestBudgetTransport_LogsUnsentRequests(t *testing.T) {
	t.Parallel()
	b := testBudgets()
	tests := []struct {
		name    string
		prepare func(t *testing.T, h *transportHarness, acct *account) context.Context
		wantErr error
	}{
		{name: "refused under a wait-until", wantErr: errAccountCooling,
			prepare: func(t *testing.T, h *transportHarness, acct *account) context.Context {
				if err := h.lim.SetCACooldown(context.Background(), acct.id, time.Minute); err != nil {
					t.Fatal(err)
				}
				return context.Background()
			}},
		{name: "abandoned order", wantErr: errOrderAbandoned,
			prepare: func(*testing.T, *transportHarness, *account) context.Context {
				tr := newOrderTrack(b.leName("p.example.com"), b.leDomain("p.example.com"))
				tr.abandon()
				return withTrack(context.Background(), tr)
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
			h := newTransportHarness(t, acct, b)
			h.bt.logger = slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			if _, err := h.do(tc.prepare(t, h, acct), t, http.MethodPost, ca.srv.URL+"/new-order", nil); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if ca.count() != 0 {
				t.Fatal("nothing may be sent")
			}
			log := h.logs.String()
			if !strings.Contains(log, `msg="acme request" ca=letsencrypt account=local method=POST path=/new-order paced=`) ||
				!strings.Contains(log, "err=") || strings.Contains(log, "took=") {
				t.Errorf("an unsent request must log paced and err without took; log = %q", log)
			}
		})
	}
}

func TestBudgetTransport_DropsAlternateChains(t *testing.T) {
	t.Parallel()
	const chainType = "application/pem-certificate-chain"
	b := testBudgets()
	tests := []struct {
		name        string
		tracked     bool
		contentType string
		links       []string
		want        []string
	}{
		{name: "separate link values", tracked: true, contentType: chainType,
			links: []string{`<https://ca.test/cert/1/1>;rel="alternate"`, `<https://ca.test/issuer>;rel="up"`},
			want:  []string{`<https://ca.test/issuer>;rel="up"`}},
		{name: "one combined link value", tracked: true, contentType: chainType,
			links: []string{`<https://ca.test/cert/1/1>; rel="alternate", <https://ca.test/issuer>; rel="up"`},
			want:  []string{`<https://ca.test/issuer>; rel="up"`}},
		{name: "only alternates", tracked: true, contentType: chainType + "; charset=utf-8",
			links: []string{`<https://ca.test/cert/1/1>;rel="alternate", <https://ca.test/cert/1/2>;rel="alternate"`},
			want:  nil},
		{name: "not a certificate download", tracked: true, contentType: "application/json",
			links: []string{`<https://ca.test/cert/1/1>;rel="alternate"`},
			want:  []string{`<https://ca.test/cert/1/1>;rel="alternate"`}},
		{name: "untracked", contentType: chainType,
			links: []string{`<https://ca.test/cert/1/1>;rel="alternate"`},
			want:  []string{`<https://ca.test/cert/1/1>;rel="alternate"`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				for _, l := range tc.links {
					w.Header().Add("Link", l)
				}
				w.WriteHeader(http.StatusOK)
			})
			h := newTransportHarness(t, &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}, b)
			ctx := context.Background()
			if tc.tracked {
				ctx = withTrack(ctx, newOrderTrack(b.leName("p.example.com"), b.leDomain("p.example.com")))
			}
			resp, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/cert/1", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := resp.Header.Values("Link"); !slices.Equal(got, tc.want) {
				t.Errorf("Link = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBudgetTransport_UsesPrepaidBeforeSharedBudget(t *testing.T) {
	t.Parallel()
	small := limit.Rate{Count: 10, Period: time.Hour, Burst: 10}
	b := testBudgets()
	b.GTSRequests, b.GTSCertPolls = small, small
	acct := &account{ca: CAGTS, id: "gts-acct", label: "gts-1"}
	level := func(t *testing.T, h *transportHarness, bk limit.Bucket) float64 {
		t.Helper()
		lv, err := h.lim.ACMEBudgetLevel(context.Background(), bk, nil)
		if err != nil {
			t.Fatal(err)
		}
		return lv
	}
	t.Run("prepaid requests skip the shared budget", func(t *testing.T) {
		h := newTransportHarness(t, acct, b)
		h.lim.SetClock(func() time.Time { return frozenNow })
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setPrepaid(b.gtsRequests(acct).Key, 2, "")
		ctx := withTrack(context.Background(), tr)
		for range 3 {
			if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/authz/1", nil); err != nil {
				t.Fatal(err)
			}
		}
		if got := level(t, h, b.gtsRequests(acct)); got != 0.9 {
			t.Fatalf("shared request budget level = %v, want 0.9 (only the third request charged)", got)
		}
	})
	t.Run("a prepaid certificate download still charges the cert-poll budget", func(t *testing.T) {
		h := newTransportHarness(t, acct, b)
		h.lim.SetClock(func() time.Time { return frozenNow })
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setPrepaid(b.gtsRequests(acct).Key, 1, "")
		if _, err := h.do(withTrack(context.Background(), tr), t, http.MethodPost, ca.srv.URL+"/cert/1", nil); err != nil {
			t.Fatal(err)
		}
		if req, cert := level(t, h, b.gtsRequests(acct)), level(t, h, b.gtsCertPolls(acct)); req != 1 || cert != 0.9 {
			t.Fatalf("request/cert-poll levels = %v/%v, want 1/0.9", req, cert)
		}
	})
	t.Run("a request held by a wait-until keeps its prepaid unit", func(t *testing.T) {
		h := newTransportHarness(t, acct, b)
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		if err := h.lim.SetCACooldown(context.Background(), acct.id, time.Minute); err != nil {
			t.Fatal(err)
		}
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setPrepaid(b.gtsRequests(acct).Key, 1, "")
		ctx, cancel := context.WithTimeout(withTrack(context.Background(), tr), 50*time.Millisecond)
		defer cancel()
		if _, err := h.do(ctx, t, http.MethodPost, ca.srv.URL+"/authz/1", nil); err == nil {
			t.Fatal("a request held past its context must fail")
		}
		if left, _ := tr.drainPrepaid(); ca.count() != 0 || left != 1 {
			t.Fatalf("sent %d, prepaid left %d; want nothing sent and the unit given back", ca.count(), left)
		}
	})
	t.Run("a prepaid download held by the cert-poll budget uses one unit when it is sent", func(t *testing.T) {
		slow := b
		slow.GTSCertPolls = limit.Rate{Count: 1, Period: 300 * time.Millisecond, Burst: 1}
		h := newTransportHarness(t, acct, slow)
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		ctx := context.Background()
		if wait, err := h.lim.TakeACME(ctx, CAGTS, []limit.Bucket{slow.gtsCertPolls(acct)}); err != nil || wait != 0 {
			t.Fatalf("drain the cert-poll budget: wait %s (%v)", wait, err)
		}
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setPrepaid(slow.gtsRequests(acct).Key, 2, "")
		held, cancel := context.WithTimeout(withTrack(ctx, tr), 50*time.Millisecond)
		defer cancel()
		if _, err := h.do(held, t, http.MethodPost, ca.srv.URL+"/cert/1", nil); err == nil {
			t.Fatal("a download held past its context must fail")
		}
		if _, err := h.do(withTrack(ctx, tr), t, http.MethodPost, ca.srv.URL+"/cert/1", nil); err != nil {
			t.Fatal(err)
		}
		if left, _ := tr.drainPrepaid(); ca.count() != 1 || left != 1 {
			t.Fatalf("sent %d, prepaid left %d; want one download sent and one unit used", ca.count(), left)
		}
	})
	t.Run("an expired mark keeps the prepaid balance", func(t *testing.T) {
		h := newTransportHarness(t, acct, b)
		h.lim.SetClock(func() time.Time { return frozenNow })
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setPrepaid(b.gtsRequests(acct).Key, 2, "an-expired-mark")
		if _, err := h.do(withTrack(context.Background(), tr), t, http.MethodPost, ca.srv.URL+"/authz/1", nil); err != nil {
			t.Fatal(err)
		}
		if got := level(t, h, b.gtsRequests(acct)); got != 1 {
			t.Fatalf("shared request budget level = %v, want 1 (the prepaid unit used)", got)
		}
		if left, _ := tr.drainPrepaid(); left != 1 {
			t.Fatalf("prepaid left %d, want 1", left)
		}
	})
	t.Run("a 429 on the account drops the prepaid balance", func(t *testing.T) {
		h := newTransportHarness(t, acct, b)
		h.lim.SetClock(func() time.Time { return frozenNow })
		h.bt.logger = slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		ca := startCAServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		ctx := context.Background()
		if err := h.lim.MarkCALimited(ctx, acct.id, time.Minute); err != nil {
			t.Fatal(err)
		}
		_, before, err := h.lim.CAWaitState(ctx, acct.id)
		if err != nil {
			t.Fatal(err)
		}
		tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
		tr.setPrepaid(b.gtsRequests(acct).Key, 3, before)
		if _, err := h.do(withTrack(ctx, tr), t, http.MethodPost, ca.srv.URL+"/authz/1", nil); err != nil {
			t.Fatal(err)
		}
		if got := level(t, h, b.gtsRequests(acct)); got != 1 {
			t.Fatalf("shared request budget level = %v, want 1 (a mark older than the prepay keeps the balance)", got)
		}
		if err := h.lim.MarkCALimited(ctx, acct.id, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := h.do(withTrack(ctx, tr), t, http.MethodPost, ca.srv.URL+"/authz/1", nil); err != nil {
			t.Fatal(err)
		}
		if got := level(t, h, b.gtsRequests(acct)); got != 0.9 {
			t.Fatalf("shared request budget level = %v, want 0.9 (the request after the 429 charged)", got)
		}
		if left, _ := tr.drainPrepaid(); left != 0 {
			t.Fatalf("prepaid left %d, want the balance dropped", left)
		}
		if want := `msg="acme order dropped its prepaid requests" ca=gts account=gts-1 reason="the account answered 429" dropped=2`; !strings.Contains(h.logs.String(), want) {
			t.Fatalf("log is missing %s; log = %q", want, h.logs.String())
		}
	})
}
