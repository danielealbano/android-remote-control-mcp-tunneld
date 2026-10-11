package acme

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

var _ HTTPKeyAuths = (*ChallengeStore)(nil)

type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r)
	h.mu.Unlock()
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

func (h *recordingHandler) aboveDebug() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		if r.Level > slog.LevelDebug {
			out = append(out, r.Message)
		}
	}
	return out
}

type fakeKeyAuths struct {
	values map[string]string
	err    error
}

func (f *fakeKeyAuths) HTTPKeyAuth(_ context.Context, domain, token string) (string, bool, error) {
	v, ok := f.values[domain+"|"+token]
	return v, ok, f.err
}

func serveChallenge(t *testing.T, keyAuths HTTPKeyAuths, method, host, target string) (*httptest.ResponseRecorder, []string, *recordingHandler) {
	t.Helper()
	var misses []string
	rec := &recordingHandler{}
	h := HTTPChallengeHandler(keyAuths, func(ip string) { misses = append(misses, ip) }, slog.New(rec))
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	req.RemoteAddr = "192.0.2.10:4242"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr, misses, rec
}

func TestHTTPChallengeHandler_Serves(t *testing.T) {
	t.Parallel()
	keyAuths := &fakeKeyAuths{values: map[string]string{"a.example.test|tok_1-x": "tok_1-x.thumb"}}
	tests := []struct {
		name   string
		method string
		host   string
	}{
		{name: "get", method: http.MethodGet, host: "a.example.test"},
		{name: "head", method: http.MethodHead, host: "a.example.test"},
		{name: "host with port", method: http.MethodGet, host: "a.example.test:80"},
		{name: "upper case host", method: http.MethodGet, host: "A.Example.TEST"},
		{name: "trailing dot", method: http.MethodGet, host: "a.example.test."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rr, misses, rec := serveChallenge(t, keyAuths, tc.method, tc.host, "/.well-known/acme-challenge/tok_1-x")
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rr.Code)
			}
			if ct := rr.Header().Get("Content-Type"); ct != "text/plain" {
				t.Fatalf("Content-Type = %q", ct)
			}
			if tc.method == http.MethodGet && rr.Body.String() != "tok_1-x.thumb" {
				t.Fatalf("body = %q", rr.Body.String())
			}
			if len(misses) != 0 {
				t.Fatalf("onMiss called %d times", len(misses))
			}
			if above := rec.aboveDebug(); len(above) != 0 {
				t.Fatalf("records above Debug: %v", above)
			}
		})
	}
}

func TestHTTPChallengeHandler_Misses(t *testing.T) {
	t.Parallel()
	keyAuths := &fakeKeyAuths{values: map[string]string{"a.example.test|tok": "tok.thumb"}}
	tests := []struct {
		name   string
		method string
		host   string
		target string
	}{
		{name: "post", method: http.MethodPost, host: "a.example.test", target: "/.well-known/acme-challenge/tok"},
		{name: "other path", method: http.MethodGet, host: "a.example.test", target: "/index.html"},
		{name: "empty token", method: http.MethodGet, host: "a.example.test", target: "/.well-known/acme-challenge/"},
		{name: "invalid token", method: http.MethodGet, host: "a.example.test", target: "/.well-known/acme-challenge/to.k"},
		{name: "over-long token", method: http.MethodGet, host: "a.example.test", target: "/.well-known/acme-challenge/" + strings.Repeat("a", maxChallengeToken+1)},
		{name: "over-long host", method: http.MethodGet, host: strings.Repeat("a", maxChallengeHost+1), target: "/.well-known/acme-challenge/tok"},
		{name: "empty host", method: http.MethodGet, host: "", target: "/.well-known/acme-challenge/tok"},
		{name: "unknown token", method: http.MethodGet, host: "a.example.test", target: "/.well-known/acme-challenge/other"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rr, misses, rec := serveChallenge(t, keyAuths, tc.method, tc.host, tc.target)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rr.Code)
			}
			if len(misses) != 1 || misses[0] != "192.0.2.10" {
				t.Fatalf("onMiss calls = %v, want one call with the client IP", misses)
			}
			if above := rec.aboveDebug(); len(above) != 0 {
				t.Fatalf("records above Debug: %v", above)
			}
		})
	}
}

func TestHTTPChallengeHandler_StoreError(t *testing.T) {
	t.Parallel()
	keyAuths := &fakeKeyAuths{values: map[string]string{"a.example.test|tok": "tok.thumb"}, err: errors.New("valkey down")}
	rr, misses, rec := serveChallenge(t, keyAuths, http.MethodGet, "a.example.test", "/.well-known/acme-challenge/tok")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	if len(misses) != 0 {
		t.Fatalf("onMiss called on a store error: %v", misses)
	}
	if strings.Contains(rr.Body.String(), "tok.thumb") {
		t.Fatalf("body leaks a key authorization: %q", rr.Body.String())
	}
	if above := rec.aboveDebug(); len(above) != 0 {
		t.Fatalf("records above Debug: %v", above)
	}
}
