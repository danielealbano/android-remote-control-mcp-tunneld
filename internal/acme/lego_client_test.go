package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
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
	lc := &legoClient{cfg: LegoConfig{CAID: CALetsEncrypt, UseARI: true, Logger: testLogger(),
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
	if due, _, err := lc.shouldRenew(context.Background(), cur, issued.Add(113*time.Hour)); err != nil {
		t.Fatal(err)
	} else if !due {
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
		if err := json.NewEncoder(w).Encode(map[string]string{
			"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/account", "newOrder": srv.URL + "/order",
		}); err != nil {
			t.Errorf("directory stub encode: %v", err)
		}
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
			if !strings.Contains(err.Error(), CAGTS) || !strings.Contains(err.Error(), "needs a challenge store") {
				t.Fatalf("error must name the CA and the missing challenge store, got %v", err)
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

func TestLegoObtain_LimitedSignalEndsAttempt(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	l := &legoClient{
		cfg: LegoConfig{CAID: CAGTS, Logger: testLogger()},
		obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			<-release
			return nil, errors.New("released")
		},
	}
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	done := make(chan error, 1)
	go func() {
		_, _, err := l.obtain(withTrack(context.Background(), tr), &x509.CertificateRequest{}, "n")
		done <- err
	}()
	tr.signalLimited(3 * time.Second)
	select {
	case err := <-done:
		var ie *IssuerError
		if !errors.As(err, &ie) || ie.Class != ClassRateLimited || ie.Retry != 3*time.Second || !errors.Is(err, errCARateLimited) {
			t.Fatalf("obtain = %v, want rate-limited 3 s from the 429 signal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a 429 signal must end the attempt at once")
	}
	if !tr.abandoned() {
		t.Fatal("the tracker must be abandoned")
	}
}

func TestLegoObtain_OrderPanicFailsTheAttempt(t *testing.T) {
	l := &legoClient{
		cfg: LegoConfig{CAID: CALetsEncrypt, Logger: testLogger()},
		obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			panic("order boom")
		},
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := l.obtain(context.Background(), &x509.CertificateRequest{}, "n")
		done <- err
	}()
	select {
	case err := <-done:
		var ie *IssuerError
		if !errors.Is(err, report.ErrPanicked) || !errors.As(err, &ie) || ie.Class != ClassLocal {
			t.Fatalf("obtain = %v, want a local error carrying the panic", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a panicking order must fail the attempt at once")
	}
}

func TestNewLegoClient_ResolveOnly(t *testing.T) {
	var accountCalls atomic.Int32
	var onlyExisting atomic.Bool
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]string{
				"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/account", "newOrder": srv.URL + "/order",
			}); err != nil {
				t.Errorf("directory stub encode: %v", err)
			}
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			accountCalls.Add(1)
			var jws struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Errorf("decode JWS: %v", err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
			if err != nil {
				t.Errorf("decode JWS payload: %v", err)
			}
			var payload struct {
				OnlyReturnExisting bool `json:"onlyReturnExisting"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Errorf("decode account payload %q: %v", raw, err)
			}
			onlyExisting.Store(payload.OnlyReturnExisting)
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			if _, err := fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"no account for this key"}`); err != nil {
				t.Errorf("write problem: %v", err)
			}
		}
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "stub-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewLegoClient(context.Background(), LegoConfig{
		CAID: CAGTS, Label: "gts-1", DirectoryURL: srv.URL + "/directory", AccountKey: key, ResolveOnly: true,
	})
	if err == nil || !strings.Contains(err.Error(), "tunneld never creates this account") {
		t.Fatalf("NewLegoClient = %v, want the look-up failure", err)
	}
	if !onlyExisting.Load() {
		t.Fatal("the account request must set onlyReturnExisting")
	}
	if n := accountCalls.Load(); n != 1 {
		t.Fatalf("new-account requests = %d, want exactly the one look-up", n)
	}
}

func TestLegoObtain_AttemptDeadlineCause(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	l := &legoClient{
		cfg: LegoConfig{CAID: CAGTS, Logger: testLogger()},
		obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			<-release
			return nil, errors.New("released")
		},
	}
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	ctx, cancel := attemptContext(withTrack(context.Background(), tr), tr, 20*time.Millisecond, time.Hour, slog.New(slog.DiscardHandler))
	defer cancel()
	_, _, err := l.obtain(ctx, &x509.CertificateRequest{}, "n")
	var ie *IssuerError
	if !errors.As(err, &ie) || ie.Class != ClassTransient || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("obtain = %v, want a transient attempt deadline", err)
	}
}

func TestLegoObtain_TimerPanicIsALocalError(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	l := &legoClient{
		cfg: LegoConfig{CAID: CAGTS, Logger: testLogger()},
		obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			<-release
			return nil, errors.New("released")
		},
	}
	ctx, cancel := attemptContext(context.Background(), nil, 20*time.Millisecond, time.Hour, slog.New(slog.DiscardHandler))
	defer cancel()
	_, _, err := l.obtain(ctx, &x509.CertificateRequest{}, "n")
	var ie *IssuerError
	if !errors.As(err, &ie) || ie.Class != ClassLocal || !errors.Is(err, report.ErrPanicked) {
		t.Fatalf("obtain = %v, want a local error carrying the timer's panic", err)
	}
}

func TestNewChain_A429MarksTheAccountForLongerThanAnyOrder(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"slow down"}`); err != nil {
			t.Errorf("write problem: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "stub-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	ch, err := NewChain(ChainConfig{
		Limiter: limit.NewLimiter(rdb, 1, 1, 1, time.Hour), Logger: logger,
		CooldownDefault: time.Hour, BackoffInitial: time.Minute, BackoffMax: 6 * time.Hour,
		RenewMargin: 48 * time.Hour, ShortlivedLifetime: 160 * time.Hour,
		NodeID: "node-test", Nodes: fakeNodes{ids: []string{"node-test"}}, Budgets: smallBudgets(),
		MaxAttemptTimeout: 100 * time.Second,
	}, LegoConfig{
		CAID: CAGTS, AccountID: "gts-1", Label: "gts-1", DirectoryURL: srv.URL + "/directory", AccountKey: key,
		ResolveOnly: true, AttemptTimeout: time.Minute, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ch.Obtain(context.Background(), nil, "p.example.test"); err == nil {
		t.Fatal("an account whose CA answers 429 must not issue")
	}
	if ttl, want := mr.TTL("acme-429:gts-1"), limitedMarkTTL(100*time.Second, defaultFinalizeGrace); ttl != want {
		t.Fatalf("429 mark TTL = %s, want %s; logs: %s", ttl, want, logs.String())
	}
}

func TestNewLegoConfig_CertificateWait(t *testing.T) {
	t.Parallel()
	if got := newLegoConfig(LegoConfig{CertificateWait: 90 * time.Second}, &acmeUser{}).Certificate.Timeout; got != 90*time.Second {
		t.Fatalf("lego certificate wait = %s, want 90s", got)
	}
	if got := newLegoConfig(LegoConfig{}, &acmeUser{}).Certificate.Timeout; got != 30*time.Second {
		t.Fatalf("lego certificate wait without one = %s, want lego's 30s default", got)
	}
}

func TestNewChain_CertificateWaitCoversTheAttemptAndTheGrace(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]string{
				"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/account", "newOrder": srv.URL + "/order",
			}); err != nil {
				t.Errorf("directory stub encode: %v", err)
			}
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			w.Header().Set("Location", srv.URL+"/account/1")
			w.Header().Set("Content-Type", "application/json")
			if _, err := fmt.Fprint(w, `{"status":"valid"}`); err != nil {
				t.Errorf("write account: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "stub-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	ch, err := NewChain(ChainConfig{
		Limiter: limit.NewLimiter(rdb, 1, 1, 1, time.Hour), Logger: logger,
		NodeID: "node-test", Nodes: fakeNodes{ids: []string{"node-test"}}, Budgets: smallBudgets(),
		FinalizeGrace: 7 * time.Second, MaxAttemptTimeout: 100 * time.Second,
	}, LegoConfig{
		CAID: CAGTS, AccountID: "gts-1", Label: "gts-1", DirectoryURL: srv.URL + "/directory", AccountKey: key,
		ResolveOnly: true, AttemptTimeout: time.Minute, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	lazy, ok := ch.groups[0][0].issuer.(*lazyCA)
	if !ok {
		t.Fatalf("the account issuer is %T, want *lazyCA", ch.groups[0][0].issuer)
	}
	if err := lazy.prepare(context.Background()); err != nil {
		t.Fatalf("build the client: %v; logs: %s", err, logs.String())
	}
	built, ok := lazy.cached()
	if !ok {
		t.Fatal("the built client must be cached")
	}
	if got := built.(*legoClient).cfg.CertificateWait; got != time.Minute+7*time.Second {
		t.Fatalf("certificate wait = %s, want the attempt timeout plus the grace (1m7s)", got)
	}
}

func testCertChain(t *testing.T) (leaf, intermediate, root []byte) {
	t.Helper()
	issue := func(cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: isCA,
		}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	encode := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	rootCert, rootKey := issue("root", true, nil, nil)
	interCert, interKey := issue("intermediate", true, rootCert, rootKey)
	leafCert, _ := issue("leaf", false, interCert, interKey)
	return encode(leafCert), encode(interCert), encode(rootCert)
}

func TestAdjacentChain_Variants(t *testing.T) {
	t.Parallel()
	leaf, inter, root := testCertChain(t)
	adjacent := bytes.Join([][]byte{leaf, inter, root}, nil)
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})
	garbled := append(bytes.Clone(leaf), []byte("-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n")...)
	tests := []struct {
		name   string
		issued []byte
		want   []byte
	}{
		{name: "already adjacent", issued: adjacent, want: adjacent},
		{name: "blank lines between the certificates", issued: bytes.Join([][]byte{leaf, inter, root}, []byte("\n")), want: adjacent},
		{name: "text between the certificates", issued: bytes.Join([][]byte{leaf, inter, root}, []byte("a comment\n")), want: adjacent},
		{name: "leaf only is kept", issued: leaf, want: leaf},
		{name: "a bundle holding another block type is kept as sent", issued: append(bytes.Clone(leaf), key...), want: append(bytes.Clone(leaf), key...)},
		{name: "a bundle holding a garbled block is kept as sent", issued: garbled, want: garbled},
		{name: "nothing", issued: nil, want: nil},
		{name: "not PEM", issued: []byte("not a certificate"), want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := adjacentChain(tc.issued); !bytes.Equal(got, tc.want) {
				t.Fatalf("adjacentChain = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestChainIssue_Variants(t *testing.T) {
	t.Parallel()
	leaf, inter, root := testCertChain(t)
	otherLeaf, _, _ := testCertChain(t)
	tests := []struct {
		name   string
		issued []byte
		want   string
	}{
		{name: "whole chain", issued: bytes.Join([][]byte{leaf, inter, root}, nil)},
		{name: "blank lines between the certificates", issued: bytes.Join([][]byte{leaf, inter, root}, []byte("\n"))},
		{name: "leaf only", issued: leaf, want: "holds 1 certificate(s)"},
		{name: "wrong order", issued: bytes.Join([][]byte{inter, leaf, root}, nil), want: "certificate 0 of the chain is not signed by the next"},
		{name: "unrelated issuer", issued: bytes.Join([][]byte{otherLeaf, inter}, nil), want: "certificate 0 of the chain is not signed by the next"},
		{name: "unparseable certificate", issued: append(bytes.Clone(leaf), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})...), want: "certificate 1 of the chain"},
		{name: "another block type", issued: append(bytes.Clone(leaf), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})...), want: `holds a "EC PRIVATE KEY" block`},
		{name: "garbled block", issued: append(bytes.Clone(leaf), []byte("-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n")...), want: "holds 2 PEM blocks, 1 parsed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := chainIssue(tc.issued)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("chainIssue = %v, want none", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("chainIssue = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestChainCertCount_Variants(t *testing.T) {
	t.Parallel()
	leaf, inter, root := testCertChain(t)
	tests := []struct {
		name string
		pem  []byte
		want int
	}{
		{name: "nothing", pem: nil, want: 0},
		{name: "one", pem: leaf, want: 1},
		{name: "three", pem: bytes.Join([][]byte{leaf, inter, root}, nil), want: 3},
		{name: "three with blank lines", pem: bytes.Join([][]byte{leaf, inter, root}, []byte("\n")), want: 3},
		{name: "a garbled block is not a certificate", pem: append(bytes.Clone(leaf), []byte("-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n")...), want: 1},
		{name: "another block type is not a certificate", pem: append(bytes.Clone(leaf), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})...), want: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := chainCertCount(tc.pem); got != tc.want {
				t.Fatalf("chainCertCount = %d, want %d", got, tc.want)
			}
		})
	}
}

func (h *recordingHandler) loggedAt(level slog.Level, msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.ContainsFunc(h.records, func(r slog.Record) bool { return r.Level == level && r.Message == msg })
}

func TestLegoObtain_IssuedBundle(t *testing.T) {
	t.Parallel()
	leaf, inter, root := testCertChain(t)
	const incomplete = "the certificate authority returned a certificate chain that is incomplete or does not verify; it is used as is"
	tests := []struct {
		name     string
		issued   []byte
		want     []byte
		wantWarn bool
	}{
		{name: "blank lines are removed", issued: bytes.Join([][]byte{leaf, inter, root}, []byte("\n")), want: bytes.Join([][]byte{leaf, inter, root}, nil)},
		{name: "a leaf-only chain is returned and logged", issued: leaf, want: leaf, wantWarn: true},
		{name: "a chain missing an intermediate is returned and logged", issued: bytes.Join([][]byte{leaf, root}, nil), want: bytes.Join([][]byte{leaf, root}, nil), wantWarn: true},
		{name: "a chain in the wrong order is returned and logged", issued: bytes.Join([][]byte{inter, leaf}, nil), want: bytes.Join([][]byte{inter, leaf}, nil), wantWarn: true},
		{name: "a garbled block is kept as sent and logged", issued: append(bytes.Clone(leaf), []byte("-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n")...), want: append(bytes.Clone(leaf), []byte("-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n")...), wantWarn: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recordingHandler{}
			l := &legoClient{
				cfg: LegoConfig{CAID: CAGTS, Logger: slog.New(rec)},
				obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
					return &certificate.Resource{Certificate: tc.issued}, nil
				},
			}
			got, info, err := l.obtain(context.Background(), &x509.CertificateRequest{}, "n")
			if err != nil {
				t.Fatalf("obtain must not fail on the shape of the chain: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("obtain = %q, want %q", got, tc.want)
			}
			block, _ := pem.Decode(tc.issued)
			first, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if info.CA != CAGTS || info.Serial != first.SerialNumber.Text(16) || !info.NotAfter.Equal(first.NotAfter) {
				t.Fatalf("cert info = %+v, want the first certificate's serial %s and not_after %s", info, first.SerialNumber.Text(16), first.NotAfter)
			}
			if warned := rec.loggedAt(slog.LevelWarn, incomplete); warned != tc.wantWarn {
				t.Fatalf("warned = %v, want %v; records = %v", warned, tc.wantWarn, rec.aboveDebug())
			}
		})
	}
	unusable := []struct {
		name   string
		issued []byte
	}{
		{name: "no certificate at all", issued: []byte("not a certificate")},
		{name: "the first certificate does not parse", issued: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})},
		{name: "the first block is not a certificate", issued: append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), leaf...)},
	}
	for _, tc := range unusable {
		t.Run(tc.name+" fails as permanent, unchanged", func(t *testing.T) {
			t.Parallel()
			l := &legoClient{
				cfg: LegoConfig{CAID: CAGTS, Logger: testLogger()},
				obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
					return &certificate.Resource{Certificate: tc.issued}, nil
				},
			}
			_, _, err := l.obtain(context.Background(), &x509.CertificateRequest{}, "n")
			var ie *IssuerError
			if !errors.As(err, &ie) || ie.Class != ClassPermanent {
				t.Fatalf("obtain = %v, want a permanent failure", err)
			}
		})
	}
}
