package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/registration"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// acmeUser implements lego's registration.User for one operator ACME account per CA.
type acmeUser struct {
	email string
	reg   *legoacme.ExtendedAccount
	key   crypto.Signer
}

func (u *acmeUser) GetEmail() string                           { return u.email }
func (u *acmeUser) GetRegistration() *legoacme.ExtendedAccount { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.Signer               { return u.key }

// LegoConfig configures one per-CA lego client.
type LegoConfig struct {
	CAID         string
	DirectoryURL string
	Email        string
	AccountKey   crypto.Signer // persisted per-CA account key
	Profile      string        // LE "shortlived" ("" for GTS/ZeroSSL)
	Validity     time.Duration // requested validity (GTS); 0 = CA default
	RenewMargin  time.Duration
	Shortlived   time.Duration // 160h (fixed-cadence anchor for non-LE)
	UseARI       bool          // LE only: renew at the NotAfter−margin floor (vs the fixed non-LE cadence)
	EABKID       string
	EABHMAC      string
	DNS          DNSProvider        // our neutral seam (tests, or a raw-TXT publisher)
	RawDNS       challenge.Provider // a lego-native DNS-01 provider (production, selected by --acme-dns-provider); preferred over DNS when set

	// DNS-01 propagation pre-check tuning (--acme-dns-resolver / --acme-dns-skip-propagation-check).
	DNSResolvers            []string // recursive nameservers for the propagation pre-check (split-horizon / hermetic test CA)
	DNSSkipPropagationCheck bool     // drop the authoritative-NS propagation requirement

	Challenge string
	TLSALPN   TLSALPNChallenges
	HTTP      HTTPChallenges
	Logger    *slog.Logger
}

// dnsChallengeOpts builds the lego DNS-01 challenge options from the propagation-tuning config.
func (cfg LegoConfig) dnsChallengeOpts() []dns01.ChallengeOption {
	opts := []dns01.ChallengeOption{dns01.DisableRecursiveNSsPropagationRequirement()}
	if cfg.DNSSkipPropagationCheck {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}
	return opts
}

func (cfg LegoConfig) applyDNSResolvers() {
	if len(cfg.DNSResolvers) == 0 {
		return
	}
	opts := dns01.NewOptions()
	opts.RecursiveNameservers = cfg.DNSResolvers
	dns01.SetDefaultClient(dns01.NewClient(opts))
}

// legoClient implements caIssuer via lego.
type legoClient struct {
	cfg    LegoConfig
	client *lego.Client
	// obtainCSR is the lego call, seamed so a test can drive a blocking obtain against the
	// ctx-cancel path. Defaults to client.Certificate.ObtainForCSR.
	obtainCSR func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error)
}

var _ caIssuer = (*legoClient)(nil)

// NewLegoClient constructs and registers (or EAB-registers) the per-CA account. Network-touching;
// exercised by the Pebble-backed integration tier.
func NewLegoClient(ctx context.Context, cfg LegoConfig) (*legoClient, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	key := cfg.AccountKey
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		key = k
	}
	user := &acmeUser{email: cfg.Email, key: key}
	lc := lego.NewConfig(user)
	lc.CADirURL = cfg.DirectoryURL
	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, fmt.Errorf("acme: new lego client (%s): %w", cfg.CAID, err)
	}
	switch challenge.Type(cfg.Challenge) {
	case challenge.TLSALPN01:
		if cfg.TLSALPN == nil {
			return nil, fmt.Errorf("acme: %s: tls-alpn-01 needs a challenge store", cfg.CAID)
		}
		if err := client.Challenge.SetTLSALPN01Provider(&tlsALPNProvider{s: cfg.TLSALPN}); err != nil {
			return nil, fmt.Errorf("acme: set tls-alpn-01 (%s): %w", cfg.CAID, err)
		}
	case challenge.HTTP01:
		if cfg.HTTP == nil {
			return nil, fmt.Errorf("acme: %s: http-01 needs a challenge store", cfg.CAID)
		}
		if err := client.Challenge.SetHTTP01Provider(&httpProvider{s: cfg.HTTP}); err != nil {
			return nil, fmt.Errorf("acme: set http-01 (%s): %w", cfg.CAID, err)
		}
	case challenge.DNS01, "":
		cfg.applyDNSResolvers()
		dnsOpts := cfg.dnsChallengeOpts()
		switch {
		case cfg.RawDNS != nil:
			if err := client.Challenge.SetDNS01Provider(cfg.RawDNS, dnsOpts...); err != nil {
				return nil, fmt.Errorf("acme: set dns01 (%s): %w", cfg.CAID, err)
			}
		case cfg.DNS != nil:
			if err := client.Challenge.SetDNS01Provider(&legoDNSAdapter{p: cfg.DNS}, dnsOpts...); err != nil {
				return nil, fmt.Errorf("acme: set dns01 (%s): %w", cfg.CAID, err)
			}
		}
	default:
		return nil, fmt.Errorf("acme: %s: unsupported challenge %q", cfg.CAID, cfg.Challenge)
	}
	if cfg.EABKID != "" {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true, Kid: cfg.EABKID, HmacEncoded: cfg.EABHMAC,
		})
		if err != nil {
			return nil, fmt.Errorf("acme: EAB register (%s): %w", cfg.CAID, err)
		}
		user.reg = reg
	} else {
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("acme: register (%s): %w", cfg.CAID, err)
		}
		user.reg = reg
	}
	lc2 := &legoClient{cfg: cfg, client: client}
	lc2.obtainCSR = lc2.client.Certificate.ObtainForCSR
	return lc2, nil
}

func (l *legoClient) id() string { return l.cfg.CAID }

func (l *legoClient) obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	req := certificate.ObtainForCSRRequest{CSR: csr, Bundle: true, Profile: l.cfg.Profile}
	if l.cfg.Validity > 0 {
		req.NotAfter = time.Now().Add(l.cfg.Validity)
	}
	// Run it off-goroutine and honor the caller's ctx so a
	// shutdown / aborted /api/v1/issue stops waiting; the abandoned call completes and is discarded.
	type result struct {
		res *certificate.Resource
		err error
	}
	ch := make(chan result, 1)
	var mu sync.Mutex
	abandoned := false
	logAbandoned := func(r result) {
		if r.err != nil {
			l.cfg.Logger.Warn("abandoned ACME order failed", "ca", l.cfg.CAID, "name", name, "err", r.err)
			return
		}
		l.cfg.Logger.Warn("abandoned ACME order issued a certificate that was discarded", "ca", l.cfg.CAID, "name", name, "domains", r.res.Domains)
	}
	go func() {
		res, err := l.obtainCSR(context.WithoutCancel(ctx), req)
		mu.Lock()
		defer mu.Unlock()
		if abandoned {
			logAbandoned(result{res, err})
			return
		}
		ch <- result{res, err}
	}()
	select {
	case <-ctx.Done():
		mu.Lock()
		abandoned = true
		select {
		case r := <-ch:
			logAbandoned(r)
		default:
		}
		mu.Unlock()
		return nil, store.CertInfo{}, transient(ctx.Err())
	case r := <-ch:
		if r.err != nil {
			return nil, store.CertInfo{}, classifyLego(r.err)
		}
		info, err := certInfoFromPEM(l.cfg.CAID, r.res.Certificate)
		if err != nil {
			return nil, store.CertInfo{}, permanent(err)
		}
		return r.res.Certificate, info, nil
	}
}

func (l *legoClient) shouldRenew(_ context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error) {
	if l.cfg.UseARI {
		// LE renews at the NotAfter−margin floor. A live ARI window pull is NOT possible here: lego's
		// GetRenewalInfo requires the issued LEAF certificate, which the name registry must never store
		// (the phone holds it — see docs/ARCHITECTURE.md §3).
		at := cur.NotAfter.Add(-l.cfg.RenewMargin)
		return !now.Before(at), at, nil
	}
	// Fixed cadence: NotBefore + (shortlived - margin) ≈ 112h.
	at := cur.NotBefore.Add(l.cfg.Shortlived - l.cfg.RenewMargin)
	return !now.Before(at), at, nil
}

// dnsProviderTimeout bounds one TXT publish/cleanup against our neutral DNSProvider seam. The
// record publish/remove is a quick API call (propagation waiting is lego's own concern).
const dnsProviderTimeout = 2 * time.Minute

// legoDNSAdapter adapts our DNSProvider to lego's challenge.Provider (computing the record).
type legoDNSAdapter struct{ p DNSProvider }

func (a *legoDNSAdapter) Present(ctx context.Context, domain, _, keyAuth string) error {
	ctx, cancel := context.WithTimeout(ctx, dnsProviderTimeout)
	defer cancel()
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return a.p.Present(ctx, info.EffectiveFQDN, info.Value)
}

func (a *legoDNSAdapter) CleanUp(ctx context.Context, domain, _, keyAuth string) error {
	ctx, cancel := context.WithTimeout(ctx, dnsProviderTimeout)
	defer cancel()
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return a.p.CleanUp(ctx, info.EffectiveFQDN, info.Value)
}

// certInfoFromPEM parses the issued leaf for serial/validity metadata.
func certInfoFromPEM(caID string, pemChain []byte) (store.CertInfo, error) {
	block, _ := pem.Decode(pemChain)
	if block == nil {
		return store.CertInfo{}, errors.New("acme: no certificate in issued PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return store.CertInfo{}, err
	}
	return store.CertInfo{
		CA: caID, Serial: c.SerialNumber.Text(16), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
	}, nil
}

const localChallengeRetry = 30 * time.Second

// classifyLego maps a lego/ACME error to an IssuerError class. An official rate-limit answer arrives
// as *acme.RateLimitedError carrying the CA's Retry-After header — that value is HONORED
// (parsed per RFC 7231), so the chain and the phone are told exactly when the CA will accept a retry;
// the --acme-cooldown-default applies only when no header was sent.
func classifyLego(err error) *IssuerError {
	if errors.Is(err, ErrChallengeStore) {
		return local(localChallengeRetry, err)
	}
	if rle, ok := errors.AsType[*legoacme.RateLimitedError](err); ok {
		return rateLimited(rle.RetryAfter, err)
	}
	if pd, ok := errors.AsType[*legoacme.ProblemDetails](err); ok {
		switch {
		case pd.HTTPStatus == 429 || strings.Contains(pd.Type, "rateLimited"):
			return rateLimited(0, err)
		case pd.HTTPStatus >= 500:
			return transient(err)
		case strings.Contains(pd.Type, "badCSR") || strings.Contains(pd.Type, "malformed") ||
			strings.Contains(pd.Type, "rejectedIdentifier") || strings.Contains(pd.Type, "unsupportedIdentifier"):
			return permanent(err)
		default:
			return transient(err)
		}
	}
	// Non-ACME transport errors are transient.
	return transient(err)
}

func SetLogOutput(w io.Writer) {
	legolog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
}
