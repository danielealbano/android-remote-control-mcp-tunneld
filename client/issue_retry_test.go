package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

type issueScript struct {
	issueErrs []error
	nonceErrs []error
	issued    []string
	fetched   int
	slept     []time.Duration
	sleepErr  error
}

func (s *issueScript) issue(n string) (*Identity, error) {
	s.issued = append(s.issued, n)
	if len(s.issueErrs) > 0 {
		err := s.issueErrs[0]
		s.issueErrs = s.issueErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	return &Identity{Name: "issued-with-" + n}, nil
}

func (s *issueScript) freshNonce() (string, error) {
	s.fetched++
	if len(s.nonceErrs) > 0 {
		err := s.nonceErrs[0]
		s.nonceErrs = s.nonceErrs[1:]
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("fresh-%d", s.fetched), nil
}

func (s *issueScript) sleep(_ context.Context, d time.Duration) error {
	s.slept = append(s.slept, d)
	return s.sleepErr
}

func TestIssueWithRetries_Rule(t *testing.T) {
	t.Parallel()
	retryable := &EnrollError{Status: http.StatusServiceUnavailable, Reason: "acme_transient", Retryable: true}
	paced := &EnrollError{Status: http.StatusServiceUnavailable, Reason: "acme_rate_limited", Retryable: true, RetryAfter: 7 * time.Second}
	final := &EnrollError{Status: http.StatusBadRequest, Reason: "acme_failed"}
	transport := &transportError{errInjected}
	tests := []struct {
		name        string
		script      issueScript
		wantErr     error
		wantSlept   []time.Duration
		wantIssued  []string
		wantFetched int
	}{
		{name: "success first try", wantIssued: []string{"n0"}},
		{name: "retry_after honoured", script: issueScript{issueErrs: []error{paced}},
			wantSlept: []time.Duration{7 * time.Second}, wantIssued: []string{"n0", "fresh-1"}, wantFetched: 1},
		{name: "default schedule then give up", script: issueScript{issueErrs: []error{retryable, retryable, retryable, retryable}},
			wantErr: retryable, wantSlept: []time.Duration{5 * time.Second, 10 * time.Second, 15 * time.Second},
			wantIssued: []string{"n0", "fresh-1", "fresh-2", "fresh-3"}, wantFetched: 3},
		{name: "transport error retried", script: issueScript{issueErrs: []error{transport}},
			wantSlept: []time.Duration{5 * time.Second}, wantIssued: []string{"n0", "fresh-1"}, wantFetched: 1},
		{name: "non-retryable stops", script: issueScript{issueErrs: []error{final}},
			wantErr: final, wantIssued: []string{"n0"}},
		{name: "sleep error joined", script: issueScript{issueErrs: []error{retryable}, sleepErr: context.Canceled},
			wantErr: context.Canceled, wantSlept: []time.Duration{5 * time.Second}, wantIssued: []string{"n0"}},
		{name: "failed nonce fetch consumes a retry", script: issueScript{issueErrs: []error{retryable}, nonceErrs: []error{transport}},
			wantSlept: []time.Duration{5 * time.Second, 10 * time.Second}, wantIssued: []string{"n0", "fresh-2"}, wantFetched: 2},
		{name: "non-retryable nonce fetch ends", script: issueScript{issueErrs: []error{retryable}, nonceErrs: []error{final}},
			wantErr: final, wantSlept: []time.Duration{5 * time.Second}, wantIssued: []string{"n0"}, wantFetched: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.script
			id, err := issueWithRetries(context.Background(), s.sleep, "n0", s.issue, s.freshNonce)
			if tc.wantErr == nil {
				if err != nil || id == nil {
					t.Fatalf("issueWithRetries = %v, %v; want an identity", id, err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !slices.Equal(s.slept, tc.wantSlept) {
				t.Fatalf("slept %v, want %v", s.slept, tc.wantSlept)
			}
			if !slices.Equal(s.issued, tc.wantIssued) {
				t.Fatalf("issued with %v, want %v", s.issued, tc.wantIssued)
			}
			if s.fetched != tc.wantFetched {
				t.Fatalf("fetched %d fresh nonces, want %d", s.fetched, tc.wantFetched)
			}
		})
	}
}

func TestEnroll_Phase2RetriesWithFreshNonce(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	var calls atomic.Int32
	opts := &enrollServerOpts{issueFail: func() *errorResponse {
		if calls.Add(1) == 1 {
			return &errorResponse{Reason: "acme_transient", Retryable: true}
		}
		return nil
	}}
	dialAddr, _ := startEnrollServer(t, ca, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var slept []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	id, err := enroll(ctx, sleep, dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool)
	if err != nil || len(id.PublicCertPEM) == 0 {
		t.Fatalf("enroll = %+v, %v; want a completed identity on retry 1", id, err)
	}
	if !slices.Equal(slept, []time.Duration{5 * time.Second}) {
		t.Fatalf("slept %v, want one 5 s wait", slept)
	}
	nonces := opts.nonces()
	if len(nonces) != 2 || nonces[1] == nonces[0] {
		t.Fatalf("issue nonces = %v, want the Phase-1 nonce then a newly fetched one", nonces)
	}
}

func newCAIdentity(t *testing.T, ca *testCA) *Identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Identity{Name: testName, IdentityCertPEM: ca.signLeaf(t, testName, &key.PublicKey, false, nil), IdentityKey: key, CA: "test"}
}

func TestRenew_RetriesWithFreshNonce(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	var calls atomic.Int32
	opts := &enrollServerOpts{issueFail: func() *errorResponse {
		if calls.Add(1) == 1 {
			return &errorResponse{Reason: "acme_rate_limited", Retryable: true, RetryAfter: 3}
		}
		return nil
	}}
	dialAddr, _ := startEnrollServer(t, ca, opts)
	c, err := New(dialAddr, testEnrollHost, testControlHost, testTunnelDomain, ca.pool, newCAIdentity(t, ca), func(io.ReadWriteCloser) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Renew(ctx, "cc"); err != nil {
		t.Fatalf("Renew must complete on its retry: %v", err)
	}
	if !slices.Equal(slept, []time.Duration{3 * time.Second}) {
		t.Fatalf("slept %v, want the server's 3 s", slept)
	}
	if nonces := opts.nonces(); len(nonces) != 2 || nonces[0] != "cc" || nonces[1] == "cc" {
		t.Fatalf("issue nonces = %v, want the nudge nonce then one fetched from the enroll host", nonces)
	}
	if len(c.Identity().PublicCertPEM) == 0 {
		t.Fatal("the renewed identity must be installed")
	}
}

func TestIssueCerts_TransportErrorIsRetryable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rt   http.RoundTripper
	}{
		{name: "dropped connection", rt: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errInjected })},
		{name: "truncated response", rt: truncatedRT{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := issueCerts(context.Background(), &http.Client{Transport: tc.rt}, testControlHost, testName, testTunnelDomain, "", "00")
			var te *transportError
			if !errors.As(err, &te) {
				t.Fatalf("err = %v, want a *transportError", err)
			}
			if _, ok := issueRetryWait(err, 0); !ok {
				t.Fatal("a transport error must be retryable")
			}
		})
	}
}
