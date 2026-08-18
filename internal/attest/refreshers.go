package attest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// orDiscard returns logger, or a sink logger when logger is nil, so the refreshers never nil-deref
// while remaining usable without an explicit logger in tests.
func orDiscard(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// RootSet holds the current Google attestation root pool behind an atomic pointer, refreshed with
// last-known-good retention.
type RootSet struct {
	url    string
	client *http.Client
	logger *slog.Logger
	pool   atomic.Pointer[x509.CertPool]
}

// NewRootSet fetches the initial root pool. The returned RootSet is ALWAYS non-nil: on a fetch
// failure it holds an EMPTY pool (every chain verify fails — fail-closed) and the error reports the
// failure so the caller can log it; a later Refresh success self-heals the pool.
func NewRootSet(ctx context.Context, url string, client *http.Client, logger *slog.Logger) (*RootSet, error) {
	r := &RootSet{url: url, client: client, logger: orDiscard(logger)}
	pool, err := r.fetch(ctx)
	if err != nil {
		r.pool.Store(x509.NewCertPool()) // fail-closed until Refresh succeeds
		return r, err
	}
	r.pool.Store(pool)
	return r, nil
}

// Pool returns the current root pool (lock-free).
func (r *RootSet) Pool() *x509.CertPool { return r.pool.Load() }

// rootResponse is the published root-set JSON: an array of PEM certificate strings.
type rootResponse struct {
	Roots []string `json:"roots"`
}

func (r *RootSet) fetch(ctx context.Context) (*x509.CertPool, error) {
	body, err := httpGet(ctx, r.client, r.url)
	if err != nil {
		return nil, fmt.Errorf("attest: fetch roots: %w", err)
	}
	pool := x509.NewCertPool()
	// Accept either a JSON {"roots":[pem,...]} document or a raw concatenated PEM bundle.
	var rr rootResponse
	if json.Unmarshal(body, &rr) == nil && len(rr.Roots) > 0 {
		for _, p := range rr.Roots {
			if !pool.AppendCertsFromPEM([]byte(p)) {
				return nil, fmt.Errorf("attest: root PEM parse failed")
			}
		}
		return pool, nil
	}
	if !pool.AppendCertsFromPEM(body) {
		return nil, fmt.Errorf("attest: root bundle parse failed")
	}
	return pool, nil
}

// Refresh periodically refetches the root pool, keeping the last-known-good pool on any failure.
func (r *RootSet) Refresh(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Hour
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if pool, err := r.fetch(ctx); err == nil {
				r.pool.Store(pool)
			} else {
				r.logger.Warn("attestation root refresh failed; keeping last-known-good pool (will retry)", "url", r.url, "err", err)
			}
		}
	}
}

// StatusList holds the Google attestation revocation-status list behind an atomic snapshot, with the
// fetch time so the verifier can enforce the staleness gate.
type StatusList struct {
	url    string
	client *http.Client
	logger *slog.Logger
	snap   atomic.Pointer[statusSnapshot]
	now    func() time.Time
}

type statusSnapshot struct {
	entries   map[string]string // serial(hex, lowercase) → status
	fetchedAt time.Time
}

// statusResponse is the published status JSON: {"entries":{"<serialHex>":{"status":"REVOKED",...}}}.
type statusResponse struct {
	Entries map[string]struct {
		Status string `json:"status"`
	} `json:"entries"`
}

// NewStatusList fetches the initial status list. The returned StatusList is ALWAYS non-nil: on a
// fetch failure it holds no snapshot (Revoked reports true and FetchedAt is zero, so the staleness
// gate refuses — fail-closed) and the error reports the failure; a later Refresh success self-heals.
func NewStatusList(ctx context.Context, url string, client *http.Client, logger *slog.Logger) (*StatusList, error) {
	s := &StatusList{url: url, client: client, logger: orDiscard(logger), now: time.Now}
	snap, err := s.fetch(ctx)
	if err != nil {
		return s, err
	}
	s.snap.Store(snap)
	return s, nil
}

func (s *StatusList) fetch(ctx context.Context) (*statusSnapshot, error) {
	body, err := httpGet(ctx, s.client, s.url)
	if err != nil {
		return nil, fmt.Errorf("attest: fetch status: %w", err)
	}
	var sr statusResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("attest: decode status: %w", err)
	}
	entries := map[string]string{}
	for serial, e := range sr.Entries {
		entries[normalizeSerial(serial)] = e.Status
	}
	return &statusSnapshot{entries: entries, fetchedAt: s.now()}, nil
}

// Revoked reports whether serial (hex) appears in the status list (any listed serial is not valid).
func (s *StatusList) Revoked(serialHex string) bool {
	snap := s.snap.Load()
	if snap == nil {
		return true // fail-closed: no list ⇒ cannot prove non-revocation
	}
	_, listed := snap.entries[normalizeSerial(serialHex)]
	return listed
}

// FetchedAt returns the snapshot's fetch time (for the staleness gate).
func (s *StatusList) FetchedAt() time.Time {
	snap := s.snap.Load()
	if snap == nil {
		return time.Time{}
	}
	return snap.fetchedAt
}

// Refresh periodically refetches the status list, keeping the last-known-good snapshot on failure.
func (s *StatusList) Refresh(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Hour
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if snap, err := s.fetch(ctx); err == nil {
				s.snap.Store(snap)
			} else {
				s.logger.Warn("attestation status refresh failed; keeping last-known-good snapshot (staleness gate will refuse once too old)", "url", s.url, "err", err)
			}
		}
	}
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// normalizeSerial lowercases a hex serial and strips a leading "0x" if present.
func normalizeSerial(s string) string {
	s = trimHexPrefix(s)
	b := make([]byte, 0, len(s))
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'F':
			b = append(b, byte(c-'A'+'a'))
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			b = append(b, byte(c))
		}
	}
	return string(b)
}

func trimHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}
