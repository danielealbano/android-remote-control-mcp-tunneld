package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// CA ids.
const (
	CALetsEncrypt = "letsencrypt"
	CAGTS         = "gts"
	CAZeroSSL     = "zerossl"
)

// Recorder is the consumer-side metrics surface the chain needs (satisfied by metrics.PromRecorder).
type Recorder interface {
	ACMECooldown(ca string)
	ACMEIssue(ca, result string)
	ACMERenew(ca, result string)
}

// nopRecorder is used when no recorder is injected.
type nopRecorder struct{}

func (nopRecorder) ACMECooldown(string)      {}
func (nopRecorder) ACMEIssue(string, string) {}
func (nopRecorder) ACMERenew(string, string) {}

// ChainConfig wires the chainIssuer.
type ChainConfig struct {
	Limiter            *limit.Limiter
	Recorder           Recorder
	CooldownDefault    time.Duration
	BackoffInitial     time.Duration
	BackoffMax         time.Duration
	RenewMargin        time.Duration
	ShortlivedLifetime time.Duration // 160h
}

// chainIssuer implements enroll.PublicIssuer with reactive per-CA cooldown/backoff (a rate-limited CA
// gets a Valkey retry-after; the spillover skips a cooling CA). Issue and renew use the SAME LE→GTS→
// ZeroSSL order, so every renewal opportunistically migrates the name to LE (an LE renewal costs nothing).
type chainIssuer struct {
	cfg ChainConfig
	cas []caIssuer // ordered [LE, GTS, ZeroSSL]
	now func() time.Time
}

// NewChainIssuer builds the chain. cas MUST be ordered [LE, GTS, ZeroSSL].
func NewChainIssuer(cfg ChainConfig, cas ...caIssuer) *chainIssuer {
	if cfg.Recorder == nil {
		cfg.Recorder = nopRecorder{}
	}
	return &chainIssuer{cfg: cfg, cas: cas, now: time.Now}
}

// SetClock overrides the clock (tests).
func (c *chainIssuer) SetClock(f func() time.Time) { c.now = f }

// Obtain runs the initial LE→GTS→ZeroSSL spillover, trying LE first.
func (c *chainIssuer) Obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	return c.run(ctx, csr, name, c.cas)
}

// Renew renews an existing name using the SAME LE→GTS→ZeroSSL order as initial issuance, so every
// renewal opportunistically migrates the name to LE (an LE renewal costs nothing). cur is unused: a
// name already on LE simply renews on LE first; a GTS/ZeroSSL name is retried on LE first.
func (c *chainIssuer) Renew(ctx context.Context, csr *x509.CertificateRequest, name string, _ store.CertInfo) ([]byte, store.CertInfo, error) {
	return c.run(ctx, csr, name, c.cas)
}

// run tries the CAs in order, skipping any that are cooling (an active Valkey retry-after) and applying
// reactive cooldown/backoff on failure. The first success wins; a rate-limited CA gets a retry-after
// honoring its Retry-After, other repeated failures get exponential backoff. When every CA is cooling or
// failing, the error is retryable ("quota exhausted, retry later") with the shortest remaining cooldown.
func (c *chainIssuer) run(ctx context.Context, csr *x509.CertificateRequest, name string, cas []caIssuer) ([]byte, store.CertInfo, error) {
	shortest := time.Duration(0)
	for _, ca := range cas {
		// Cooldown bookkeeping is best-effort: a Valkey error reads as "not cooling" (fail-open — try
		// the CA) rather than blocking issuance on the control plane.
		if cool, _ := c.cfg.Limiter.CACooldown(ctx, ca.id()); cool > 0 {
			if shortest == 0 || cool < shortest {
				shortest = cool
			}
			continue
		}
		pemChain, info, err := ca.obtain(ctx, csr, name)
		if err == nil {
			_ = c.cfg.Limiter.ResetCAFailures(ctx, ca.id()) // best-effort streak reset; a stale count self-expires at TTL
			c.cfg.Recorder.ACMEIssue(ca.id(), "ok")
			return pemChain, info, nil
		}
		c.cfg.Recorder.ACMEIssue(ca.id(), "fail")
		cool, permanent := c.handleFailure(ctx, ca.id(), err)
		if permanent {
			return nil, store.CertInfo{}, err // permanent (e.g. bad CSR) — stop
		}
		// Fold the cooldown this failure JUST set into the shortest-remaining computation, so the
		// Retry-After reflects when the chain would actually accept a retry (a run where every CA
		// fails transitively must not report the 1h default when a 1m backoff applies).
		if cool > 0 && (shortest == 0 || cool < shortest) {
			shortest = cool
		}
	}
	// Every CA was cooling or failed transiently: retryable with the shortest remaining cooldown.
	if shortest == 0 {
		shortest = c.cfg.CooldownDefault
	}
	return nil, store.CertInfo{}, rateLimited(shortest, fmt.Errorf("all issuance CAs are rate-limited; quota exhausted, retry later"))
}

// handleFailure applies the reactive cooldown/backoff for ca, returning the cooldown it set (0 for a
// permanent error) and whether the error is permanent.
func (c *chainIssuer) handleFailure(ctx context.Context, ca string, err error) (cooldown time.Duration, permanent bool) {
	var ie *IssuerError
	class := ClassTransient
	var retry time.Duration
	if asIssuerError(err, &ie) {
		class = ie.Class
		retry = ie.Retry
	}
	switch class {
	case ClassPermanent:
		return 0, true
	case ClassRateLimited:
		// The CA's explicit Retry-After is honored AS-IS (it is the authoritative statement of when a
		// retry will be accepted); --acme-cooldown-default applies only when the CA sent no hint.
		// Cooldown writes are best-effort: a Valkey error just means the CA is not skipped next time
		// (fail-open) — the spillover + retry still protect the account.
		d := retry
		if d <= 0 {
			d = c.cfg.CooldownDefault
		}
		_ = c.cfg.Limiter.SetCACooldown(ctx, ca, d)
		c.cfg.Recorder.ACMECooldown(ca)
		return d, false
	default: // transient / unknown → exponential backoff
		n, _ := c.cfg.Limiter.BumpCAFailures(ctx, ca, c.cfg.BackoffMax) // best-effort streak counter (see above)
		d := backoff(c.cfg.BackoffInitial, c.cfg.BackoffMax, n)
		_ = c.cfg.Limiter.SetCACooldown(ctx, ca, d)
		c.cfg.Recorder.ACMECooldown(ca)
		return d, false
	}
}

// ShouldRenew dispatches to the CA that issued cur (LE: NotAfter−margin floor; GTS/ZeroSSL: fixed cadence).
func (c *chainIssuer) ShouldRenew(ctx context.Context, cur store.CertInfo) (bool, time.Time, error) {
	ca := c.byID(cur.CA)
	if ca == nil {
		// Unknown issuer → renew at the fixed floor.
		at := cur.NotBefore.Add(c.cfg.ShortlivedLifetime - c.cfg.RenewMargin)
		return !c.now().Before(at), at, nil
	}
	return ca.shouldRenew(ctx, cur, c.now())
}

// ObtainSelf issues a cert for one of tunneld's OWN reserved hostnames using a SERVER-SIDE key + CSR,
// via the same spillover (subject to the per-CA cooldowns, but NOT the per-tunnel issuance cap — that
// lives in enroll and is keyed on tunnel names).
func (c *chainIssuer) ObtainSelf(ctx context.Context, host string) (certPEM, keyPEM []byte, info store.CertInfo, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, store.CertInfo{}, fmt.Errorf("acme: self key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
	}, key)
	if err != nil {
		return nil, nil, store.CertInfo{}, fmt.Errorf("acme: self csr: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, store.CertInfo{}, err
	}
	certPEM, info, err = c.run(ctx, csr, host, c.cas)
	if err != nil {
		return nil, nil, store.CertInfo{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, store.CertInfo{}, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, info, nil
}

func (c *chainIssuer) byID(id string) caIssuer {
	for _, ca := range c.cas {
		if ca.id() == id {
			return ca
		}
	}
	return nil
}

// backoff = min(initial * 2^(n-1), max) for a streak length n (n>=1).
func backoff(initial, maxDur time.Duration, n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := initial
	for i := 1; i < n; i++ {
		d *= 2
		if d >= maxDur {
			return maxDur
		}
	}
	if d > maxDur {
		return maxDur
	}
	return d
}

// asIssuerError extracts a *IssuerError from err (via Unwrap chain) without importing errors here.
func asIssuerError(err error, out **IssuerError) bool {
	for err != nil {
		if ie, ok := err.(*IssuerError); ok {
			*out = ie
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
