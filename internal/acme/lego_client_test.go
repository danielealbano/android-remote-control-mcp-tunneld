package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/challenge/dns01"
	legolog "github.com/go-acme/lego/v5/log"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestClassifyLegoErrors covers the plan's "error classification" row: sample ACME problem documents
// map to the rate-limited / transient / permanent classes.
func TestClassifyLegoErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "429 rate limited", err: &legoacme.ProblemDetails{HTTPStatus: 429}, want: ClassRateLimited},
		{name: "rateLimited type", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited", HTTPStatus: 403}, want: ClassRateLimited},
		{name: "500 transient", err: &legoacme.ProblemDetails{HTTPStatus: 500}, want: ClassTransient},
		{name: "badCSR permanent", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:badCSR", HTTPStatus: 400}, want: ClassPermanent},
		{name: "malformed permanent", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:malformed", HTTPStatus: 400}, want: ClassPermanent},
		{name: "rejectedIdentifier permanent", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:rejectedIdentifier", HTTPStatus: 400}, want: ClassPermanent},
		{name: "unknown problem transient", err: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:serverInternal", HTTPStatus: 400}, want: ClassTransient},
		{name: "transport error transient", err: errors.New("dial tcp: connection refused"), want: ClassTransient},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ie := classifyLego(tc.err)
			if ie.Class != tc.want {
				t.Fatalf("classifyLego(%v).Class = %q, want %q", tc.err, ie.Class, tc.want)
			}
		})
	}
}

// TestShouldRenewLEMarginFloor covers the LE renewal timing as built (docs/ARCHITECTURE.md §3): an LE
// cert renews at NotAfter − --acme-renew-margin — for a shortlived (~160h) cert that is NotBefore+112h,
// the same uniform ~4.7-day cadence as the fixed non-LE path.
func TestShouldRenewLEMarginFloor(t *testing.T) {
	lc := &legoClient{cfg: LegoConfig{CAID: CALetsEncrypt, UseARI: true,
		RenewMargin: 48 * time.Hour, Shortlived: 160 * time.Hour}}
	issued := time.Unix(1_700_000_000, 0)
	cur := store.CertInfo{CA: CALetsEncrypt, NotBefore: issued, NotAfter: issued.Add(160 * time.Hour)}

	due, at, err := lc.shouldRenew(context.Background(), cur, issued.Add(111*time.Hour))
	if err != nil || due {
		t.Fatalf("before NotAfter−margin the cert must not be due (due=%v err=%v)", due, err)
	}
	if want := issued.Add(112 * time.Hour); !at.Equal(want) {
		t.Fatalf("renew-at = %s, want NotAfter−margin = %s", at, want)
	}
	if due, _, _ := lc.shouldRenew(context.Background(), cur, issued.Add(113*time.Hour)); !due {
		t.Fatal("past NotAfter−margin the cert must be due")
	}
}

// TestClassifyRateLimitedErrorHonorsRetryAfter: lego's *acme.RateLimitedError carries the CA's
// Retry-After header — classification must honor it (and fall back to 0 → the
// cooldown default when the header is absent or unparsable).
func TestClassifyRateLimitedErrorHonorsRetryAfter(t *testing.T) {
	tests := []struct {
		name  string
		retry time.Duration
		want  time.Duration
	}{
		{name: "seconds form", retry: 2 * time.Minute, want: 2 * time.Minute},
		{name: "absent or unparsable header", retry: 0, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &legoacme.RateLimitedError{
				ProblemDetails: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited", HTTPStatus: 429},
				RetryAfter:     tc.retry,
			}
			ie := classifyLego(err)
			if ie.Class != ClassRateLimited {
				t.Fatalf("class = %q, want rate-limited", ie.Class)
			}
			if ie.Retry != tc.want {
				t.Fatalf("Retry = %s, want %s", ie.Retry, tc.want)
			}
		})
	}
}

func TestSetLogOutput_WritesToWriter(t *testing.T) {
	prev := legolog.Default()
	t.Cleanup(func() { legolog.SetDefault(prev) })
	var buf bytes.Buffer
	SetLogOutput(&buf)
	legolog.Info("probe")
	if !strings.Contains(buf.String(), "probe") {
		t.Fatalf("lego log line not written to the configured writer: %q", buf.String())
	}
}

func dnsOptionName(opt dns01.ChallengeOption) string {
	return runtime.FuncForPC(reflect.ValueOf(opt).Pointer()).Name()
}

func TestLegoConfig_DNSChallengeOpts_RecursiveCheckAlwaysOff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		skip bool
		want []string
	}{
		{name: "default", skip: false, want: []string{"DisableRecursiveNSsPropagationRequirement"}},
		{name: "skip propagation check", skip: true,
			want: []string{"DisableRecursiveNSsPropagationRequirement", "DisableAuthoritativeNssPropagationRequirement"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := LegoConfig{DNSSkipPropagationCheck: tc.skip}.dnsChallengeOpts()
			if len(opts) != len(tc.want) {
				t.Fatalf("got %d options, want %d", len(opts), len(tc.want))
			}
			for i, w := range tc.want {
				if n := dnsOptionName(opts[i]); !strings.Contains(n, w) {
					t.Fatalf("option %d = %s, want %s", i, n, w)
				}
			}
		})
	}
}

func TestLegoConfig_ApplyDNSResolvers(t *testing.T) {
	prev := dns01.DefaultClient()
	t.Cleanup(func() { dns01.SetDefaultClient(prev) })
	LegoConfig{}.applyDNSResolvers()
	if dns01.DefaultClient() != prev {
		t.Fatal("no resolvers must leave lego's default DNS client untouched")
	}
	LegoConfig{DNSResolvers: []string{"127.0.0.1:53"}}.applyDNSResolvers()
	if dns01.DefaultClient() == prev {
		t.Fatal("configured resolvers must replace lego's default DNS client")
	}
}

func acmeDirectoryStub(t *testing.T) string {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/account", "newOrder": srv.URL + "/order",
		})
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "stub-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	return srv.URL + "/directory"
}

func TestNewLegoClient_UnsupportedChallenge(t *testing.T) {
	_, err := NewLegoClient(context.Background(), LegoConfig{
		CAID: CALetsEncrypt, DirectoryURL: acmeDirectoryStub(t), Challenge: "dns-02",
	})
	if err == nil {
		t.Fatal("an unknown challenge method must fail client construction")
	}
	if !strings.Contains(err.Error(), CALetsEncrypt) || !strings.Contains(err.Error(), "dns-02") {
		t.Fatalf("error must name the CA and the method, got %v", err)
	}
}

func TestNewLegoClient_ChallengeNeedsStore(t *testing.T) {
	for _, method := range []string{"tls-alpn-01", "http-01"} {
		t.Run(method, func(t *testing.T) {
			_, err := NewLegoClient(context.Background(), LegoConfig{
				CAID: CAGTS, DirectoryURL: acmeDirectoryStub(t), Challenge: method,
			})
			if err == nil {
				t.Fatalf("%s without a challenge store must fail", method)
			}
			if !strings.Contains(err.Error(), CAGTS) {
				t.Fatalf("error must name the CA, got %v", err)
			}
		})
	}
}

func TestClassifyLego_ChallengeStoreIsLocal(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "direct", err: fmt.Errorf("[a.example.test] acme: error presenting token: %w", ErrChallengePending)},
		{name: "multi-error", err: errors.Join(errors.New("other domain"), fmt.Errorf("presenting token: %w", ErrChallengePending))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ie := classifyLego(tc.err)
			if ie.Class != ClassLocal || ie.Retry != localChallengeRetry {
				t.Fatalf("class=%s retry=%s, want %s / %s", ie.Class, ie.Retry, ClassLocal, localChallengeRetry)
			}
		})
	}
}
