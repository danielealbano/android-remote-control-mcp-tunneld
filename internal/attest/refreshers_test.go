package attest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureHandler is a slog.Handler that records emitted records so tests can assert the refreshers log
// their last-known-good failures at Warn.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) count(level slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if r.Level == level {
			n++
		}
	}
	return n
}

// switchServer serves a switchable root-set response: a JSON array of PEM strings, or a 500.
type switchServer struct {
	fail atomic.Bool
	body atomic.Pointer[[]byte]
}

func (s *switchServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if s.fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(*s.body.Load())
	}
}

func (s *switchServer) set(body []byte) { s.body.Store(&body) }

func rootsJSON(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var pems []string
	for _, c := range certs {
		pems = append(pems, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
	}
	b, err := json.Marshal(pems)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRootRefresherSwapAndLastKnownGood(t *testing.T) {
	fc := newFakeCA(t)
	sw := &switchServer{}
	sw.set(rootsJSON(t, fc.rootCert))
	srv := httptest.NewServer(sw.handler())
	defer srv.Close()

	ch := &captureHandler{}
	rs, err := NewRootSet(context.Background(), srv.URL, srv.Client(), slog.New(ch))
	if err != nil {
		t.Fatalf("initial fetch: %v", err)
	}
	first := rs.Pool()
	if first == nil {
		t.Fatal("initial pool must be non-nil")
	}

	// A successful refresh atomically swaps the pool.
	fc2 := newFakeCA(t)
	sw.set(rootsJSON(t, fc2.rootCert))
	ctx, cancel := context.WithCancel(context.Background())
	go rs.Refresh(ctx, 5*time.Millisecond)
	waitFor(t, time.Second, func() bool { return rs.Pool() != first })
	swapped := rs.Pool()

	// A failing refetch RETAINS the last-known-good pool AND logs the failure at Warn.
	sw.fail.Store(true)
	waitFor(t, time.Second, func() bool { return ch.count(slog.LevelWarn) > 0 })
	if rs.Pool() != swapped {
		t.Fatal("a failing refetch must retain the last-known-good pool")
	}
	cancel()
}

func TestRootSetInitialFailureFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	rs, err := NewRootSet(context.Background(), srv.URL, srv.Client(), nil)
	if err == nil {
		t.Fatal("initial fetch failure must be reported")
	}
	if rs == nil {
		t.Fatal("RootSet must be non-nil even when the initial fetch fails")
	}
	if rs.Pool() == nil {
		t.Fatal("failed initial fetch must leave a non-nil EMPTY pool (nil would verify against system roots)")
	}
	// The empty pool fails closed: a full verify through the Verifier rejects an otherwise-valid chain.
	ca := newFakeCA(t)
	p := defaultParams()
	chain, _ := ca.buildChain(t, p)
	status := &StatusList{now: time.Now}
	status.snap.Store(&statusSnapshot{entries: map[string]string{}, fetchedAt: frozenNow()})
	set, perr := parseDigests([]byte(hexOf(p.signerDigest)))
	if perr != nil {
		t.Fatal(perr)
	}
	signers := &SignerAllowlist{}
	signers.set.Store(&set)
	v := NewVerifier(rs, status, signers, 24*time.Hour)
	if _, verr := v.Verify(chain, p.challenge, frozenNow()); !errors.Is(verr, ErrChainUntrusted) {
		t.Fatalf("verify must fail closed (ErrChainUntrusted) against the empty pool, got %v", verr)
	}
}

// TestRootSetRejectsMalformedBundle covers the fail-closed parse branches: only a bare JSON array of PEM
// strings is accepted, so a non-array body, the old {"roots":…} object, a raw PEM bundle, and an empty
// array are ALL errors that leave a non-nil empty pool (never nil, which would verify against system roots).
func TestRootSetRejectsMalformedBundle(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "old roots-object no longer accepted", body: `{"roots":["x"]}`},
		{name: "non-JSON body", body: `not json`},
		{name: "raw PEM bundle no longer accepted", body: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
		{name: "empty array", body: `[]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			rs, err := NewRootSet(context.Background(), srv.URL, srv.Client(), nil)
			if err == nil {
				t.Fatal("a malformed root bundle must be reported as an error")
			}
			if rs == nil {
				t.Fatal("RootSet must be non-nil even when the initial parse fails")
			}
			if rs.Pool() == nil {
				t.Fatal("a failed parse must leave a non-nil EMPTY pool (nil would verify against system roots)")
			}
		})
	}
}

func TestStatusRefresherSwapAndLastKnownGood(t *testing.T) {
	sw := &switchServer{}
	sw.set([]byte(`{"entries":{}}`))
	srv := httptest.NewServer(sw.handler())
	defer srv.Close()

	ch := &captureHandler{}
	sl, err := NewStatusList(context.Background(), srv.URL, srv.Client(), slog.New(ch))
	if err != nil {
		t.Fatalf("initial fetch: %v", err)
	}
	first := sl.FetchedAt()
	if first.IsZero() {
		t.Fatal("initial snapshot must be stamped")
	}
	if sl.Revoked("ab") {
		t.Fatal("empty status list must not report revoked")
	}

	// A successful refresh advances fetchedAt and swaps the entries.
	sw.set([]byte(`{"entries":{"abcd":{"status":"REVOKED"}}}`))
	ctx, cancel := context.WithCancel(context.Background())
	go sl.Refresh(ctx, 5*time.Millisecond)
	waitFor(t, time.Second, func() bool { return sl.Revoked("abcd") })
	swapped := sl.FetchedAt()
	if !swapped.After(first) {
		t.Fatal("fetchedAt must advance on a successful refresh")
	}

	// A failing refetch RETAINS the last-known-good snapshot (fetchedAt does NOT advance) AND logs Warn.
	sw.fail.Store(true)
	waitFor(t, time.Second, func() bool { return ch.count(slog.LevelWarn) > 0 })
	if !sl.FetchedAt().Equal(swapped) || !sl.Revoked("abcd") {
		t.Fatal("a failing refetch must retain the last-known-good snapshot")
	}
	cancel()
}

func TestStatusListInitialFailureFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	sl, err := NewStatusList(context.Background(), srv.URL, srv.Client(), nil)
	if err == nil {
		t.Fatal("initial fetch failure must be reported")
	}
	if sl == nil {
		t.Fatal("StatusList must be non-nil even when the initial fetch fails")
	}
	if !sl.Revoked("anything") {
		t.Fatal("a missing snapshot must fail closed (everything revoked)")
	}
	if !sl.FetchedAt().IsZero() {
		t.Fatal("a missing snapshot must report a zero fetch time (staleness gate refuses)")
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}
