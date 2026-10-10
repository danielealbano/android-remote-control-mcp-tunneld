package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certificate"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// TestLegoClient_ObtainRespectsCtxCancel verifies obtain returns promptly when ctx is cancelled even
// though the lego call is still blocked.
func TestLegoClient_ObtainRespectsCtxCancel(t *testing.T) {
	block := make(chan struct{})
	defer close(block) // release the stranded obtain goroutine on test exit (the result chan is buffered)
	l := &legoClient{
		cfg: LegoConfig{CAID: "x"},
		obtainCSR: func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			<-block
			return nil, nil
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
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = l.resolve(context.Background()) }()
	}
	wg.Wait()
	if builds.Load() != 1 {
		t.Fatalf("concurrent resolve must build exactly once, got %d", builds.Load())
	}

	var errBuilds atomic.Int32
	le := newLazyCA("y", 0, 0, func(context.Context) (caIssuer, error) {
		errBuilds.Add(1)
		return nil, errors.New("boom")
	})
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
	})
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

func TestLazyCA_ShouldRenewNeverTriggersBuild(t *testing.T) {
	var builds atomic.Int32
	l := newLazyCA("x", 160*time.Hour, 48*time.Hour, func(context.Context) (caIssuer, error) {
		builds.Add(1)
		return &fakeCA{caID: "x"}, nil
	})
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
	})
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
		cfg: LegoConfig{CAID: "x"},
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
