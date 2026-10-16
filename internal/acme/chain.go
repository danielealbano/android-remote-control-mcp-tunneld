package acme

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"slices"
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
	ACMERateLimited(ca string)
}

// nopRecorder is used when no recorder is injected.
type nopRecorder struct{}

func (nopRecorder) ACMECooldown(string)      {}
func (nopRecorder) ACMEIssue(string, string) {}
func (nopRecorder) ACMERenew(string, string) {}
func (nopRecorder) ACMERateLimited(string)   {}

// ChainConfig wires the chainIssuer.
type ChainConfig struct {
	Limiter            *limit.Limiter
	Recorder           Recorder
	Logger             *slog.Logger
	CooldownDefault    time.Duration
	BackoffInitial     time.Duration
	BackoffMax         time.Duration
	RenewMargin        time.Duration
	ShortlivedLifetime time.Duration // 160h

	NodeID    string
	Nodes     NodeLister
	Budgets   Budgets
	PollEvery time.Duration
	RunBudget time.Duration
	Rand      func(n int) int
}

const (
	settleTimeout    = 5 * time.Second
	defaultRunBudget = 290 * time.Second
)

// chainIssuer implements enroll.PublicIssuer. Issue and renew use the SAME LE→GTS→ZeroSSL order, so
// every renewal opportunistically migrates the name to LE.
type chainIssuer struct {
	cfg    ChainConfig
	groups [][]*account
	now    func() time.Time
}

// NewChainIssuer builds the chain.
func NewChainIssuer(cfg ChainConfig, accounts ...*account) (*chainIssuer, error) {
	if cfg.Nodes == nil {
		return nil, errNoNodeLister
	}
	if cfg.Recorder == nil {
		cfg.Recorder = nopRecorder{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Rand == nil {
		cfg.Rand = cryptoIntN
	}
	if cfg.RunBudget <= 0 {
		cfg.RunBudget = defaultRunBudget
	}
	c := &chainIssuer{cfg: cfg, now: time.Now}
	for _, ca := range []string{CALetsEncrypt, CAGTS, CAZeroSSL} {
		var g []*account
		for _, a := range accounts {
			if a.ca == ca {
				g = append(g, a)
			}
		}
		if len(g) > 0 {
			c.groups = append(c.groups, g)
		}
	}
	return c, nil
}

// SetClock overrides the clock (tests).
func (c *chainIssuer) SetClock(f func() time.Time) { c.now = f }

func cryptoIntN(n int) int {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int(binary.LittleEndian.Uint64(b[:]) % uint64(n))
}

// Obtain runs the initial LE→GTS→ZeroSSL spillover, trying LE first.
func (c *chainIssuer) Obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	return c.run(ctx, csr, name, "")
}

// Renew renews an existing name using the SAME LE→GTS→ZeroSSL order as initial issuance, so every
// renewal opportunistically migrates the name to LE.
func (c *chainIssuer) Renew(ctx context.Context, csr *x509.CertificateRequest, name string, cur store.CertInfo) ([]byte, store.CertInfo, error) {
	return c.run(ctx, csr, name, cur.CA)
}

// run tries the CAs in order. The first success wins. When every CA is cooling or failing, the error
// is retryable ("quota exhausted, retry later").
func (c *chainIssuer) run(ctx context.Context, csr *x509.CertificateRequest, name, curCA string) ([]byte, store.CertInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RunBudget)
	defer cancel()
	live := c.liveNodes(ctx)
	fqdn := name
	if csr != nil {
		switch {
		case len(csr.DNSNames) > 0:
			fqdn = csr.DNSNames[0]
		case csr.Subject.CommonName != "":
			fqdn = csr.Subject.CommonName
		}
	}
	shortest := time.Duration(0)
	note := func(d time.Duration) {
		if d > 0 && (shortest == 0 || d < shortest) {
			shortest = d
		}
	}
	for _, group := range c.groups {
		for _, a := range c.ordered(ctx, group, live) {
			if err := ctx.Err(); err != nil {
				return nil, store.CertInfo{}, transient(err)
			}
			// Cooldown bookkeeping is best-effort: a Valkey error reads as "not cooling" (fail-open — try
			// the CA) rather than blocking issuance on the control plane.
			cool, cerr := c.cfg.Limiter.CACooldown(ctx, a.id)
			if cerr != nil {
				c.cfg.Logger.Warn("acme CA cooldown check failed (trying the CA)", "ca", a.ca, "name", name, "err", cerr, "account", a.label)
			}
			if cool > 0 {
				note(cool)
				continue
			}
			pemChain, info, wait, err := c.attempt(ctx, a, csr, name, fqdn, curCA == CALetsEncrypt && a.ca == CALetsEncrypt, live)
			if wait > 0 {
				note(wait)
				continue
			}
			if err == nil {
				if rerr := c.cfg.Limiter.ResetCAFailures(ctx, a.id); rerr != nil { // best-effort streak reset; a stale count self-expires at TTL
					c.cfg.Logger.Warn("acme CA failure-streak reset failed", "ca", a.ca, "name", name, "err", rerr, "account", a.label)
				}
				c.cfg.Recorder.ACMEIssue(a.ca, "ok")
				c.cfg.Logger.Info("acme certificate issued", "ca", a.ca, "name", name, "serial", info.Serial, "not_after", info.NotAfter, "account", a.label)
				return pemChain, info, nil
			}
			if ctx.Err() != nil {
				return nil, store.CertInfo{}, transient(fmt.Errorf("%w (CA order: %v)", ctx.Err(), err))
			}
			class := ClassTransient
			var ie *IssuerError
			if asIssuerError(err, &ie) {
				class = ie.Class
			}
			c.cfg.Logger.Warn("acme CA order failed", "ca", a.ca, "name", name, "class", class, "err", err, "account", a.label)
			if class == ClassLocal {
				return nil, store.CertInfo{}, rateLimited(ie.Retry, err)
			}
			c.cfg.Recorder.ACMEIssue(a.ca, "fail")
			cool, permanent := c.handleFailure(ctx, a, err)
			if permanent {
				return nil, store.CertInfo{}, err // permanent (e.g. bad CSR) — stop
			}
			// Fold the cooldown this failure JUST set into the shortest-remaining computation, so the
			// Retry-After reflects when the chain would actually accept a retry (a run where every CA
			// fails transitively must not report the 1h default when a 1m backoff applies).
			note(cool)
		}
	}
	// Every CA was cooling or failed transiently: retryable.
	if shortest == 0 {
		shortest = c.cfg.CooldownDefault
	}
	jitter := time.Duration(1+c.cfg.Rand(10)) * time.Second
	return nil, store.CertInfo{}, rateLimited(shortest+jitter, fmt.Errorf("all issuance CAs are rate-limited; quota exhausted, retry later"))
}

func (c *chainIssuer) attempt(ctx context.Context, a *account, csr *x509.CertificateRequest, name, fqdn string, leRenewal bool, live []string) ([]byte, store.CertInfo, time.Duration, error) {
	onCreate, onSuccess := c.cfg.Budgets.orderBuckets(a, fqdn, leRenewal)
	member := mintMember()
	timeout := a.timeout
	if d, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(d))
	}
	ok, wait, err := c.cfg.Limiter.ReserveACME(ctx, a.ca, append(slices.Clone(onCreate), onSuccess...), c.cfg.NodeID, member, c.now().Add(timeout), live)
	switch {
	case err != nil:
		c.cfg.Logger.Warn("acme budget reservation failed (trying the account)", "ca", a.ca, "name", name, "err", err, "account", a.label)
	case !ok:
		c.cfg.Logger.Debug("acme account out of budget (skipped)", "ca", a.ca, "name", name, "retry_after", wait, "account", a.label)
		return nil, store.CertInfo{}, wait, nil
	}
	var nameBucket, domainBucket limit.Bucket
	if a.ca == CALetsEncrypt {
		nameBucket, domainBucket = c.cfg.Budgets.leName(fqdn), c.cfg.Budgets.leDomain(fqdn)
	}
	tr := newOrderTrack(nameBucket, domainBucket)
	actx, cancel := context.WithTimeout(withTrack(ctx, tr), timeout)
	pemChain, info, oerr := a.issuer.obtain(actx, csr, name)
	cancel()
	out := tr.outcome()
	tr.abandon()
	c.settle(ctx, a, member, onCreate, onSuccess, tr, out, oerr == nil)
	return pemChain, info, 0, oerr
}

func (c *chainIssuer) settle(ctx context.Context, a *account, member string, onCreate, onSuccess []limit.Bucket, tr *orderTrack, out orderOutcome, ok bool) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer cancel()
	var spend, release []limit.Bucket
	if ok || out.created {
		spend = append(spend, onCreate...)
	} else {
		release = append(release, onCreate...)
	}
	if ok || out.finalized {
		spend = append(spend, onSuccess...)
	} else {
		release = append(release, onSuccess...)
	}
	for _, b := range spend {
		if err := c.cfg.Limiter.CommitACME(sctx, a.ca, b, c.cfg.NodeID, member); err != nil {
			c.cfg.Logger.Warn("acme budget spend failed (the reservation expires at its deadline)", "ca", a.ca, "bucket", b.Key, "err", err, "account", a.label)
		}
	}
	if err := c.cfg.Limiter.ReleaseACME(sctx, release, c.cfg.NodeID, member); err != nil {
		c.cfg.Logger.Warn("acme budget release failed (the reservation expires at its deadline)", "ca", a.ca, "err", err, "account", a.label)
	}
	if out.abandoned {
		for _, f := range tr.takeCleanups() {
			if err := f(sctx); err != nil {
				c.cfg.Logger.Warn("abandoned order's challenge cleanup failed (it expires by TTL)", "ca", a.ca, "err", err, "account", a.label)
			}
		}
	}
}

func (c *chainIssuer) ordered(ctx context.Context, group []*account, live []string) []*account {
	out := slices.Clone(group)
	if len(out) < 2 {
		return out
	}
	for i := len(out) - 1; i > 0; i-- {
		j := c.cfg.Rand(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	levels := make(map[*account]float64, len(out))
	for _, a := range out {
		lv, err := c.cfg.Limiter.ACMEBudgetLevel(ctx, c.cfg.Budgets.ordersBucket(a), live)
		if err != nil {
			c.cfg.Logger.Warn("acme budget levels unavailable (accounts in random order)", "ca", a.ca, "err", err)
			return out
		}
		levels[a] = lv
	}
	slices.SortStableFunc(out, func(x, y *account) int { return cmp.Compare(levels[y], levels[x]) })
	return out
}

func (c *chainIssuer) liveNodes(ctx context.Context) []string {
	ids, err := c.cfg.Nodes.LiveNodeIDs(ctx)
	if err != nil {
		c.cfg.Logger.Warn("live node list unavailable (counting only this node's in-flight orders)", "err", err)
		ids = nil
	}
	if !slices.Contains(ids, c.cfg.NodeID) {
		ids = append(ids, c.cfg.NodeID)
	}
	return ids
}

func (c *chainIssuer) ACMEBudgetLevels(ctx context.Context) ([]BudgetLevel, error) {
	live, err := c.cfg.Nodes.LiveNodeIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("live node list: %w", err)
	}
	if !slices.Contains(live, c.cfg.NodeID) {
		live = append(live, c.cfg.NodeID)
	}
	var out []BudgetLevel
	for _, g := range c.groups {
		for _, a := range g {
			for _, nb := range c.cfg.Budgets.accountBuckets(a) {
				lv, err := c.cfg.Limiter.ACMEBudgetLevel(ctx, nb.b, live)
				if err != nil {
					return nil, err
				}
				out = append(out, BudgetLevel{CA: a.ca, Account: a.label, Budget: nb.name, Ratio: lv})
			}
		}
	}
	return out, nil
}

func mintMember() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// handleFailure applies the reactive cooldown/backoff, returning the cooldown (0 for a
// permanent error) and whether the error is permanent.
func (c *chainIssuer) handleFailure(ctx context.Context, a *account, err error) (cooldown time.Duration, permanent bool) {
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
		// --acme-cooldown-default applies only when the CA sent no hint.
		// Cooldown writes are best-effort: a Valkey error just means the CA is not skipped next time
		// (fail-open) — the spillover + retry still protect the account.
		d := retry
		if d <= 0 {
			d = c.cfg.CooldownDefault
		}
		return c.setCooldown(ctx, a, d), false
	default: // transient / unknown → exponential backoff
		cool, cerr := c.cfg.Limiter.CACooldown(ctx, a.id)
		if cerr != nil {
			c.cfg.Logger.Warn("acme CA cooldown check failed (backing off as for a new failure)", "ca", a.ca, "err", cerr, "account", a.label)
		}
		if cool > 0 {
			return cool, false
		}
		n, berr := c.cfg.Limiter.BumpCAFailures(ctx, a.id, c.cfg.BackoffMax) // best-effort streak counter (see above)
		if berr != nil {
			c.cfg.Logger.Warn("acme CA failure-streak bump failed", "ca", a.ca, "err", berr, "account", a.label)
		}
		d := backoff(c.cfg.BackoffInitial, c.cfg.BackoffMax, n)
		return c.setCooldown(ctx, a, d), false
	}
}

func (c *chainIssuer) setCooldown(ctx context.Context, a *account, d time.Duration) time.Duration {
	c.cfg.Recorder.ACMECooldown(a.ca)
	if err := c.cfg.Limiter.SetCACooldown(ctx, a.id, d); err != nil {
		c.cfg.Logger.Warn("acme CA cooldown write failed", "ca", a.ca, "cooldown", d, "err", err, "account", a.label)
		return d
	}
	cur, err := c.cfg.Limiter.CACooldown(ctx, a.id)
	if err != nil {
		c.cfg.Logger.Warn("acme CA cooldown read failed (reporting the requested cooldown)", "ca", a.ca, "cooldown", d, "err", err, "account", a.label)
		return d
	}
	return max(d, cur)
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
// via the same spillover (NOT the per-tunnel issuance cap — that lives in enroll and is keyed on tunnel
// names).
func (c *chainIssuer) ObtainSelf(ctx context.Context, host string, cur store.CertInfo) (certPEM, keyPEM []byte, info store.CertInfo, err error) {
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
	certPEM, info, err = c.run(ctx, csr, host, cur.CA)
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
	for _, g := range c.groups {
		if g[0].ca == id {
			return g[0].issuer
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
