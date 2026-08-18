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
	"strings"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// acmeUser implements lego's registration.User for one operator ACME account per CA.
type acmeUser struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// LegoConfig configures one per-CA lego client.
type LegoConfig struct {
	CAID         string
	DirectoryURL string
	Email        string
	AccountKey   crypto.PrivateKey // persisted per-CA account key
	Profile      string            // LE "shortlived" ("" for GTS/ZeroSSL)
	Validity     time.Duration     // requested validity (GTS); 0 = CA default
	RenewMargin  time.Duration
	Shortlived   time.Duration // 160h (fixed-cadence anchor for non-LE)
	UseARI       bool          // LE only: renew at the NotAfter−margin floor (vs the fixed non-LE cadence)
	EABKID       string
	EABHMAC      string
	DNS          DNSProvider        // our neutral seam (tests, or a raw-TXT publisher)
	RawDNS       challenge.Provider // a lego-native DNS-01 provider (production, selected by --acme-dns-provider); preferred over DNS when set

	// DNS-01 propagation pre-check tuning (--acme-dns-resolver / --acme-dns-skip-propagation-check).
	// Empty/false preserve lego's defaults (system resolvers + authoritative-NS propagation required).
	DNSResolvers            []string // recursive nameservers for the propagation pre-check (split-horizon / hermetic test CA)
	DNSSkipPropagationCheck bool     // drop the authoritative-NS propagation requirement
}

// dnsChallengeOpts builds the lego DNS-01 challenge options from the propagation-tuning config.
func (cfg LegoConfig) dnsChallengeOpts() []dns01.ChallengeOption {
	var opts []dns01.ChallengeOption
	if len(cfg.DNSResolvers) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(cfg.DNSResolvers))
	}
	if cfg.DNSSkipPropagationCheck {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}
	return opts
}

// legoClient implements caIssuer via lego.
type legoClient struct {
	cfg    LegoConfig
	client *lego.Client
}

var _ caIssuer = (*legoClient)(nil)

// NewLegoClient constructs and registers (or EAB-registers) the per-CA account and wires the DNS-01
// provider. Network-touching; exercised by the Pebble-backed integration tier.
func NewLegoClient(cfg LegoConfig) (*legoClient, error) {
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
	if cfg.EABKID != "" {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true, Kid: cfg.EABKID, HmacEncoded: cfg.EABHMAC,
		})
		if err != nil {
			return nil, fmt.Errorf("acme: EAB register (%s): %w", cfg.CAID, err)
		}
		user.reg = reg
	} else {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("acme: register (%s): %w", cfg.CAID, err)
		}
		user.reg = reg
	}
	return &legoClient{cfg: cfg, client: client}, nil
}

func (l *legoClient) id() string { return l.cfg.CAID }

func (l *legoClient) obtain(_ context.Context, csr *x509.CertificateRequest, _ string) ([]byte, store.CertInfo, error) {
	req := certificate.ObtainForCSRRequest{CSR: csr, Bundle: true, Profile: l.cfg.Profile}
	if l.cfg.Validity > 0 {
		req.NotAfter = time.Now().Add(l.cfg.Validity)
	}
	res, err := l.client.Certificate.ObtainForCSR(req)
	if err != nil {
		return nil, store.CertInfo{}, classifyLego(err)
	}
	info, err := certInfoFromPEM(l.cfg.CAID, res.Certificate)
	if err != nil {
		return nil, store.CertInfo{}, permanent(err)
	}
	return res.Certificate, info, nil
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

// legoDNSAdapter adapts our DNSProvider to lego's challenge.Provider (computing the record).
type legoDNSAdapter struct{ p DNSProvider }

func (a *legoDNSAdapter) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return a.p.Present(context.Background(), info.EffectiveFQDN, info.Value)
}

func (a *legoDNSAdapter) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return a.p.CleanUp(context.Background(), info.EffectiveFQDN, info.Value)
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

// classifyLego maps a lego/ACME error to an IssuerError class. An official rate-limit answer arrives
// as *acme.RateLimitedError carrying the CA's literal Retry-After header — that value is HONORED
// (parsed per RFC 7231), so the chain and the phone are told exactly when the CA will accept a retry;
// the --acme-cooldown-default applies only when no header was sent.
func classifyLego(err error) *IssuerError {
	if rle, ok := errors.AsType[*legoacme.RateLimitedError](err); ok {
		retry, perr := api.ParseRetryAfter(rle.RetryAfter)
		if perr != nil {
			retry = 0 // absent/unparsable header → the chain falls back to --acme-cooldown-default
		}
		return rateLimited(retry, err)
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
