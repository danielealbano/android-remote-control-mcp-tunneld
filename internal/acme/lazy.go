package acme

import (
	"context"
	"crypto/x509"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// lazyCA defers the network-touching per-CA client construction (ACME account registration) to first
// use, caching it on success and retrying on the next call after a failure. This makes server startup
// non-blocking on ACME reachability: an unreachable CA at boot simply issues a transient error (the
// chain applies its cooldown and falls through to the next CA), and the client self-heals when the CA
// becomes reachable again.
type lazyCA struct {
	caID        string
	shortlived  time.Duration // configured cert lifetime for the degraded renewal floor
	renewMargin time.Duration // configured --acme-renew-margin for the degraded renewal floor
	build       func() (caIssuer, error)

	group singleflight.Group        // dedups concurrent first-use registration
	inner atomic.Pointer[caIssuer]  // fast-path read; nil until first successful build
}

var _ caIssuer = (*lazyCA)(nil)

// newLazyCA wraps a builder for one CA's client behind lazy, self-healing construction.
func newLazyCA(caID string, shortlived, renewMargin time.Duration, build func() (caIssuer, error)) *lazyCA {
	return &lazyCA{caID: caID, shortlived: shortlived, renewMargin: renewMargin, build: build}
}

// NewChain builds the [LE, GTS, ZeroSSL] chain with lazy, self-healing per-CA clients constructed from
// the given lego configs (order preserved: MUST be LE, GTS, ZeroSSL). Each client's network-touching
// construction (ACME account registration) is deferred to first use, so startup never blocks on CA
// reachability and an unreachable CA self-heals once it recovers.
func NewChain(cfg ChainConfig, legoCfgs ...LegoConfig) *chainIssuer {
	cas := make([]caIssuer, 0, len(legoCfgs))
	for _, lc := range legoCfgs {
		cas = append(cas, newLazyCA(lc.CAID, lc.Shortlived, lc.RenewMargin,
			func() (caIssuer, error) { return NewLegoClient(lc) }))
	}
	return NewChainIssuer(cfg, cas...)
}

func (l *lazyCA) id() string { return l.caID }

// cached returns the built client only if already constructed (never triggers a network build).
func (l *lazyCA) cached() (caIssuer, bool) {
	if c := l.inner.Load(); c != nil {
		return *c, true
	}
	return nil, false
}

// resolve returns the built client, performing first-use registration once (deduped via singleflight).
// It is ctx-aware: a cancelled/shutdown caller returns promptly while the build completes+caches in the
// background; a build error is surfaced to the caller and retried on the next call.
func (l *lazyCA) resolve(ctx context.Context) (caIssuer, error) {
	if c, ok := l.cached(); ok {
		return c, nil
	}
	ch := l.group.DoChan("build", func() (any, error) {
		if c, ok := l.cached(); ok {
			return c, nil
		}
		c, err := l.build()
		if err != nil {
			return nil, err // not cached → retried on the next call
		}
		l.inner.Store(&c)
		return c, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		return r.Val.(caIssuer), nil
	}
}

func (l *lazyCA) obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return nil, store.CertInfo{}, transient(err)
	}
	return c.obtain(ctx, csr, name)
}

func (l *lazyCA) shouldRenew(ctx context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error) {
	c, ok := l.cached()
	if !ok {
		// The CA client is not yet built: fall back to the CONFIGURED fixed floor WITHOUT triggering a
		// network registration, so a hung CA never pins the renewal scheduler (defaults guard a zero
		// config in tests). The actual renewal via obtain builds the client when it is due.
		shortlived, margin := l.shortlived, l.renewMargin
		if shortlived <= 0 {
			shortlived = 160 * time.Hour
		}
		if margin <= 0 {
			margin = 48 * time.Hour
		}
		at := cur.NotBefore.Add(shortlived - margin)
		return !now.Before(at), at, nil
	}
	return c.shouldRenew(ctx, cur, now)
}
