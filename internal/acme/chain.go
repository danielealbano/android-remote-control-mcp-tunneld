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
	LEWeeklyBudget     int
	CooldownDefault    time.Duration
	BackoffInitial     time.Duration
	BackoffMax         time.Duration
	RenewMargin        time.Duration
	ShortlivedLifetime time.Duration // 160h
}

// chainIssuer implements enroll.PublicIssuer with reactive per-CA cooldown/backoff, a reserve-then-
// refund weekly LE budget, and opportunistic LE-first migration at renewal.
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

// Obtain runs the initial LE→GTS→ZeroSSL spillover: every LE attempt is a NEW order (budget-gated,
// reserve-then-refund).
func (c *chainIssuer) Obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	return c.run(ctx, csr, name, c.cas, true)
}

// Renew renews an existing name. A NON-LE name tries LE FIRST when the weekly budget reserves
// (opportunistic migration); otherwise it renews on cur.CA (an LE renewal of an LE name is
// budget-EXEMPT) and falls through the remaining chain on failure.
func (c *chainIssuer) Renew(ctx context.Context, csr *x509.CertificateRequest, name string, cur store.CertInfo) ([]byte, store.CertInfo, error) {
	le := c.byID(CALetsEncrypt)
	// Opportunistic migration: a non-LE name tries LE first when the budget allows (a NEW LE order).
	if cur.CA != CALetsEncrypt && le != nil {
		if ok, _ := c.cfg.Limiter.ConsumeLEOrder(ctx, c.cfg.LEWeeklyBudget); ok {
			if cool, _ := c.cfg.Limiter.CACooldown(ctx, CALetsEncrypt); cool <= 0 {
				pemChain, info, err := le.obtain(ctx, csr, name)
				if err == nil {
					_ = c.cfg.Limiter.ResetCAFailures(ctx, CALetsEncrypt)
					c.cfg.Recorder.ACMERenew(CALetsEncrypt, "ok")
					return pemChain, info, nil
				}
				_ = c.cfg.Limiter.ReleaseLEOrder(ctx)
				c.handleFailure(ctx, CALetsEncrypt, err)
			} else {
				_ = c.cfg.Limiter.ReleaseLEOrder(ctx) // LE cooling — refund the reservation
			}
		}
	}
	// Renew on cur.CA (LE renewal of an LE name is budget-exempt), then fall through the remaining chain.
	order := c.orderFrom(cur.CA)
	// The first element (cur.CA) uses NEW-order budget semantics ONLY if it is LE AND cur was non-LE
	// (i.e. a migration) — but that path is handled above; here cur.CA==LE means an exempt renewal.
	leNewOrder := false
	return c.run(ctx, csr, name, order, leNewOrder)
}

// run tries the CAs in order, skipping any that are cooling, applying reserve-then-refund LE budget for
// LE NEW orders, and reactive cooldown/backoff on failure. leNewOrder marks whether an LE attempt in
// this run is a NEW order (budget-consuming) vs an exempt LE renewal.
func (c *chainIssuer) run(ctx context.Context, csr *x509.CertificateRequest, name string, cas []caIssuer, leNewOrder bool) ([]byte, store.CertInfo, error) {
	shortest := time.Duration(0)
	for _, ca := range cas {
		if cool, _ := c.cfg.Limiter.CACooldown(ctx, ca.id()); cool > 0 {
			if shortest == 0 || cool < shortest {
				shortest = cool
			}
			continue
		}
		reserved := false
		if ca.id() == CALetsEncrypt && leNewOrder {
			ok, _ := c.cfg.Limiter.ConsumeLEOrder(ctx, c.cfg.LEWeeklyBudget)
			if !ok {
				continue // no LE budget — skip LE without an attempt
			}
			reserved = true
		}
		pemChain, info, err := ca.obtain(ctx, csr, name)
		if err == nil {
			_ = c.cfg.Limiter.ResetCAFailures(ctx, ca.id())
			c.cfg.Recorder.ACMEIssue(ca.id(), "ok")
			return pemChain, info, nil
		}
		if reserved {
			_ = c.cfg.Limiter.ReleaseLEOrder(ctx) // failed order never burns budget
		}
		c.cfg.Recorder.ACMEIssue(ca.id(), "fail")
		if c.handleFailure(ctx, ca.id(), err) {
			return nil, store.CertInfo{}, err // permanent (e.g. bad CSR) — stop
		}
	}
	// Every CA was cooling or failed transiently: retryable with the shortest remaining cooldown.
	if shortest == 0 {
		shortest = c.cfg.CooldownDefault
	}
	return nil, store.CertInfo{}, rateLimited(shortest, fmt.Errorf("all CAs unavailable"))
}

// handleFailure applies the reactive cooldown/backoff for ca and reports whether the error is permanent.
func (c *chainIssuer) handleFailure(ctx context.Context, ca string, err error) (permanent bool) {
	var ie *IssuerError
	class := ClassTransient
	var retry time.Duration
	if asIssuerError(err, &ie) {
		class = ie.Class
		retry = ie.Retry
	}
	switch class {
	case ClassPermanent:
		return true
	case ClassRateLimited:
		d := max(retry, c.cfg.CooldownDefault)
		_ = c.cfg.Limiter.SetCACooldown(ctx, ca, d)
		c.cfg.Recorder.ACMECooldown(ca)
	default: // transient / unknown → exponential backoff
		n, _ := c.cfg.Limiter.BumpCAFailures(ctx, ca, c.cfg.BackoffMax)
		d := backoff(c.cfg.BackoffInitial, c.cfg.BackoffMax, n)
		_ = c.cfg.Limiter.SetCACooldown(ctx, ca, d)
		c.cfg.Recorder.ACMECooldown(ca)
	}
	return false
}

// ShouldRenew dispatches to the CA that issued cur (LE via ARI; GTS/ZeroSSL fixed cadence).
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
// via the same spillover (subject to the per-CA cooldowns + LE budget, but NOT the per-tunnel issuance
// cap — that lives in enroll and is keyed on tunnel names).
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
	certPEM, info, err = c.run(ctx, csr, host, c.cas, true)
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

// orderFrom returns the CA slice starting at the given id, then the rest in the canonical order.
func (c *chainIssuer) orderFrom(id string) []caIssuer {
	var head caIssuer
	var rest []caIssuer
	for _, ca := range c.cas {
		if ca.id() == id {
			head = ca
		} else {
			rest = append(rest, ca)
		}
	}
	if head == nil {
		return c.cas
	}
	return append([]caIssuer{head}, rest...)
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
