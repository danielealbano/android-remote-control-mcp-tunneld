package acme

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

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

	mu    sync.Mutex
	inner caIssuer
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

func (l *lazyCA) resolve() (caIssuer, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inner != nil {
		return l.inner, nil
	}
	c, err := l.build()
	if err != nil {
		return nil, err
	}
	l.inner = c
	return c, nil
}

func (l *lazyCA) obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, store.CertInfo{}, transient(err)
	}
	return c.obtain(ctx, csr, name)
}

func (l *lazyCA) shouldRenew(ctx context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error) {
	c, err := l.resolve()
	if err != nil {
		// The CA client is unavailable: fall back to the CONFIGURED fixed floor so renewal still fires
		// on the operator's schedule (defaults guard a zero config in tests).
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
