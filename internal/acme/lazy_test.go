package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certificate"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestLegoClient_ObtainRespectsCtxCancel verifies obtain returns promptly when ctx is cancelled even
// though the lego call is still blocked.
func TestLegoClient_ObtainRespectsCtxCancel(t *testing.T) {
	block := make(chan struct{})
	defer close(block) // release the stranded obtain goroutine on test exit (the result chan is buffered)
	l := &legoClient{
		cfg: LegoConfig{CAID: "x", Logger: testLogger()},
		obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			<-block
			return nil, errors.New("released")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := l.obtain(ctx, &x509.CertificateRequest{}, "n")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled obtain must return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("obtain did not honor ctx cancellation while the lego call blocked")
	}
}

func TestLazyCA_ConcurrentResolveSingleBuild(t *testing.T) {
	var builds atomic.Int32
	l := newLazyCA("x", 160*time.Hour, 48*time.Hour, func(context.Context) (caIssuer, error) {
		builds.Add(1)
		return &fakeCA{caID: "x"}, nil
	}, testLogger())
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.resolve(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if builds.Load() != 1 {
		t.Fatalf("concurrent resolve must build exactly once, got %d", builds.Load())
	}

	var errBuilds atomic.Int32
	le := newLazyCA("y", 0, 0, func(context.Context) (caIssuer, error) {
		errBuilds.Add(1)
		return nil, errors.New("boom")
	}, testLogger())
	if _, err := le.resolve(context.Background()); err == nil {
		t.Fatal("a build error must surface")
	}
	if _, err := le.resolve(context.Background()); err == nil {
		t.Fatal("a build error must surface on retry too")
	}
	if errBuilds.Load() != 2 {
		t.Fatalf("a build error must be retried on the next call, got %d builds", errBuilds.Load())
	}
}

func TestLazyCA_ResolveCancelWhileBuildHangs(t *testing.T) {
	release := make(chan struct{})
	l := newLazyCA("x", 0, 0, func(context.Context) (caIssuer, error) {
		<-release
		return &fakeCA{caID: "x"}, nil
	}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := l.resolve(ctx); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled resolve must return an error while the build hangs")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolve did not return on ctx cancel while the build hung")
	}
	close(release) // let the abandoned build finish + cache in the background
}

func TestLazyCA_ObtainReportsTheAttemptDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	l := newLazyCA(CAGTS, 0, 0, func(ctx context.Context) (caIssuer, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("released")
	}, testLogger())
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	ctx, cancel := attemptContext(withTrack(context.Background(), tr), tr, 20*time.Millisecond, time.Hour, slog.New(slog.DiscardHandler))
	defer cancel()
	_, _, err := l.obtain(ctx, &x509.CertificateRequest{}, "n")
	var ie *IssuerError
	if !errors.As(err, &ie) || ie.Class != ClassTransient || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("obtain = %v, want a transient attempt deadline", err)
	}
}

func TestLazyCA_PanicsAreLocalErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		build func(context.Context) (caIssuer, error)
	}{
		{name: "the build panics", build: func(context.Context) (caIssuer, error) { panic("build boom") }},
		{name: "a request of the build panics", build: func(context.Context) (caIssuer, error) {
			return nil, fmt.Errorf("account lookup: %w", report.ErrPanicked)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var builds atomic.Int32
			l := newLazyCA(CAGTS, 0, 0, func(ctx context.Context) (caIssuer, error) {
				if builds.Add(1) == 1 {
					return tc.build(ctx)
				}
				return &fakeCA{caID: CAGTS}, nil
			}, slog.New(slog.DiscardHandler))
			err := l.prepare(context.Background())
			var ie *IssuerError
			if !errors.As(err, &ie) || ie.Class != ClassLocal || ie.Reason != "panicked" || !errors.Is(err, report.ErrPanicked) {
				t.Fatalf("prepare = %v, want a local error carrying the panic", err)
			}
			if err := l.prepare(context.Background()); err != nil {
				t.Fatalf("the next use must build again, got %v", err)
			}
		})
	}
}

func TestLazyCA_TimerPanicIsALocalError(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	l := newLazyCA(CAGTS, 0, 0, func(ctx context.Context) (caIssuer, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("released")
	}, slog.New(slog.DiscardHandler))
	ctx, cancel := attemptContext(context.Background(), nil, 20*time.Millisecond, time.Hour, slog.New(slog.DiscardHandler))
	defer cancel()
	_, _, err := l.obtain(ctx, &x509.CertificateRequest{}, "n")
	var ie *IssuerError
	if !errors.As(err, &ie) || ie.Class != ClassLocal || !errors.Is(err, report.ErrPanicked) {
		t.Fatalf("obtain = %v, want a local error carrying the timer's panic", err)
	}
}

func TestLazyCA_ShouldRenewNeverTriggersBuild(t *testing.T) {
	var builds atomic.Int32
	l := newLazyCA("x", 160*time.Hour, 48*time.Hour, func(context.Context) (caIssuer, error) {
		builds.Add(1)
		return &fakeCA{caID: "x"}, nil
	}, testLogger())
	cur := store.CertInfo{NotBefore: time.Unix(1_700_000_000, 0)}
	now := time.Unix(1_700_000_000, 0)
	_, at, err := l.shouldRenew(context.Background(), cur, now)
	if err != nil {
		t.Fatal(err)
	}
	if builds.Load() != 0 {
		t.Fatalf("shouldRenew must NOT trigger a build, got %d", builds.Load())
	}
	if want := cur.NotBefore.Add(112 * time.Hour); !at.Equal(want) {
		t.Errorf("fixed-floor renewal at = %v, want %v", at, want)
	}
}

// deadlineDNS records whether Present was called with a ctx carrying a deadline.
type deadlineDNS struct{ hasDeadline bool }

func (d *deadlineDNS) Present(ctx context.Context, _, _ string) error {
	_, d.hasDeadline = ctx.Deadline()
	return nil
}
func (d *deadlineDNS) CleanUp(context.Context, string, string) error { return nil }

func TestLegoDNSAdapter_PresentUsesDeadline(t *testing.T) {
	d := &deadlineDNS{}
	a := &legoDNSAdapter{p: d}
	if err := a.Present(context.Background(), "example.test", "token", "keyauth"); err != nil {
		t.Fatal(err)
	}
	if !d.hasDeadline {
		t.Fatal("Present must pass a ctx with a deadline to the DNSProvider")
	}
}

func TestLazyCA_BuildCtxSurvivesCallerButIsBounded(t *testing.T) {
	t.Parallel()
	got := make(chan context.Context, 1)
	release := make(chan struct{})
	defer close(release)
	l := newLazyCA("x", 0, 0, func(ctx context.Context) (caIssuer, error) {
		got <- ctx
		<-release
		return &fakeCA{caID: "x"}, nil
	}, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	resolved := make(chan error, 1)
	go func() {
		_, err := l.resolve(ctx)
		resolved <- err
	}()
	bctx := <-got
	cancel()
	if err := <-resolved; err == nil {
		t.Fatal("a cancelled caller must return an error")
	}
	if bctx.Err() != nil {
		t.Fatalf("the build ctx must survive the caller's cancellation, got %v", bctx.Err())
	}
	deadline, ok := bctx.Deadline()
	if !ok || time.Until(deadline) > lazyBuildTimeout {
		t.Fatalf("the build ctx must carry a deadline within lazyBuildTimeout, got %v (ok=%v)", deadline, ok)
	}
}

func TestLegoClient_ObtainDetachesCallerCancel(t *testing.T) {
	t.Parallel()
	got := make(chan context.Context, 1)
	release := make(chan struct{})
	defer close(release)
	l := &legoClient{
		cfg: LegoConfig{CAID: "x", Logger: testLogger()},
		obtainCSR: func(ctx context.Context, _ certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			got <- ctx
			<-release
			return nil, errors.New("released")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := l.obtain(ctx, &x509.CertificateRequest{}, "n")
		done <- err
	}()
	octx := <-got
	cancel()
	if err := <-done; err == nil {
		t.Fatal("a cancelled obtain must return an error")
	}
	if octx.Err() != nil {
		t.Fatalf("the lego call's ctx must survive the caller's cancellation, got %v", octx.Err())
	}
	if _, ok := octx.Deadline(); ok {
		t.Fatal("the lego call's ctx must carry no deadline")
	}
}

func TestLegoClient_AbandonedOrderOutcomeLogged(t *testing.T) {
	tests := []struct {
		name string
		res  *certificate.Resource
		err  error
		want string
	}{
		{name: "order failed", err: errors.New("ca said no"), want: "an order that was given up on failed later; nothing waits for it any more"},
		{name: "certificate issued", res: &certificate.Resource{Domains: []string{"n.example.test"}},
			want: "an order that was given up on still produced a certificate, which was thrown away"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingHandler{}
			started := make(chan struct{})
			release := make(chan struct{})
			l := &legoClient{
				cfg: LegoConfig{CAID: "x", Logger: slog.New(rec)},
				obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
					close(started)
					<-release
					return tc.res, tc.err
				},
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				_, _, err := l.obtain(ctx, &x509.CertificateRequest{}, "n")
				done <- err
			}()
			<-started
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("obtain = %v, want context.Canceled", err)
			}
			close(release)
			deadline := time.Now().Add(2 * time.Second)
			for !slices.Contains(rec.aboveDebug(), tc.want) {
				if time.Now().After(deadline) {
					t.Fatalf("the abandoned outcome was not logged; records = %v", rec.aboveDebug())
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

func TestLazyCA_BuildIgnoresAttemptTracker(t *testing.T) {
	sawTracker := make(chan bool, 1)
	release := make(chan struct{})
	l := newLazyCA("x", 0, 0, func(ctx context.Context) (caIssuer, error) {
		sawTracker <- trackFrom(ctx) != nil
		<-release
		return &fakeCA{caID: "x"}, nil
	}, testLogger())
	tr := newOrderTrack(limit.Bucket{}, limit.Bucket{})
	first := make(chan error, 1)
	go func() {
		_, err := l.resolve(withTrack(context.Background(), tr))
		first <- err
	}()
	if <-sawTracker {
		t.Fatal("the shared build must not see the triggering attempt's tracker")
	}
	tr.abandon()
	second := make(chan error, 1)
	go func() {
		_, err := l.resolve(context.Background())
		second <- err
	}()
	close(release)
	for _, ch := range []chan error{first, second} {
		if err := <-ch; err != nil {
			t.Fatalf("resolve = %v, want the built client", err)
		}
	}
}

type panicOnHead struct{ base http.RoundTripper }

func (p panicOnHead) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodHead {
		panic("nonce boom")
	}
	return p.base.RoundTrip(r)
}

func TestLazyCA_NoncePanicHiddenByLegoIsALocalError(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
		if r.URL.Path != "/directory" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"newNonce": srv.URL + "/nonce", "newAccount": srv.URL + "/account", "newOrder": srv.URL + "/order",
		}); err != nil {
			t.Errorf("write directory: %v", err)
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
	h := newTransportHarness(t, &account{id: "le-local", ca: CALetsEncrypt, label: "local"}, Budgets{})
	cfg := LegoConfig{CAID: CALetsEncrypt, Label: "local", DirectoryURL: srv.URL + "/directory", AccountKey: key,
		Wrap: func(base http.RoundTripper) http.RoundTripper { h.bt.base = panicOnHead{base}; return h.bt }}
	l := newLazyCA(CALetsEncrypt, 0, 0, func(ctx context.Context) (caIssuer, error) { return NewLegoClient(ctx, cfg) },
		slog.New(slog.DiscardHandler))
	err = l.prepare(context.Background())
	var ie *IssuerError
	if !errors.As(err, &ie) || ie.Class != ClassLocal || ie.Reason != "panicked" || !errors.Is(err, report.ErrPanicked) {
		t.Fatalf("prepare = %v, want a local error carrying the nonce request's panic", err)
	}
}
