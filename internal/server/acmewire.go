package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/enroll"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// shortlivedLifetime is the fixed uniform rotation anchor (~4.7 days) for GTS/ZeroSSL and the LE
// shortlived profile — see docs/PROTOCOL.md and the config Validate floor.
const shortlivedLifetime = 160 * time.Hour

// acmeChain is the server-side view of the ACME chain: the enroll issuer plus the reserved-host self
// issuance and renewal-scheduling methods (implemented by acme.chainIssuer).
type acmeChain interface {
	enroll.PublicIssuer
	ShouldRenew(ctx context.Context, cur store.CertInfo) (bool, time.Time, error)
	ObtainSelf(ctx context.Context, host string) (certPEM, keyPEM []byte, info store.CertInfo, err error)
}

// buildACMEChain constructs the LE→GTS→ZeroSSL chain from config: the DNS-01 provider selected by
// --acme-dns-provider, per-CA accounts whose keys are persisted under --acme-account-dir/accounts, and
// lazy self-healing clients (startup never blocks on CA reachability).
func buildACMEChain(cfg config.ServeCmd, lim *limit.Limiter, rec acme.Recorder, logger *slog.Logger) acmeChain {
	dnsProvider, err := acme.DNSProviderByName(cfg.ACMEDNSProvider)
	if err != nil {
		logger.Warn("acme dns provider unavailable (issuance degraded until configured)",
			"provider", cfg.ACMEDNSProvider, "err", err)
	}
	accountsDir := filepath.Join(cfg.ACMEAccountDir, "accounts")

	chainCfg := acme.ChainConfig{
		Limiter: lim, Recorder: rec, LEWeeklyBudget: cfg.ACMELEWeeklyBudget,
		CooldownDefault: cfg.ACMECooldownDefault, BackoffInitial: cfg.ACMEBackoffInitial,
		BackoffMax: cfg.ACMEBackoffMax, RenewMargin: cfg.ACMERenewMargin, ShortlivedLifetime: shortlivedLifetime,
	}
	le := acme.LegoConfig{
		CAID: acme.CALetsEncrypt, DirectoryURL: cfg.ACMEDirLE, Email: cfg.ACMEEmail,
		AccountKey: loadAccountKey(accountsDir, acme.CALetsEncrypt, logger),
		Profile:    cfg.ACMELEProfile, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		UseARI: true, RawDNS: dnsProvider,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	gts := acme.LegoConfig{
		CAID: acme.CAGTS, DirectoryURL: cfg.ACMEDirGTS, Email: cfg.ACMEEmail,
		AccountKey: loadAccountKey(accountsDir, acme.CAGTS, logger),
		Validity:   cfg.ACMEGTSValidity, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		EABKID: cfg.ACMEEABGTSKID, EABHMAC: cfg.ACMEEABGTSHMAC, RawDNS: dnsProvider,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	zerossl := acme.LegoConfig{
		CAID: acme.CAZeroSSL, DirectoryURL: cfg.ACMEDirZeroSSL, Email: cfg.ACMEEmail,
		AccountKey: loadAccountKey(accountsDir, acme.CAZeroSSL, logger),
		RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		EABKID: cfg.ACMEEABZeroSSLKID, EABHMAC: cfg.ACMEEABZeroSSLHMAC, RawDNS: dnsProvider,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	return acme.NewChain(chainCfg, le, gts, zerossl)
}

// loadAccountKey loads (or generates + persists) the per-CA ACME account key under dir/<caid>.key. A
// persistence failure is non-fatal: lego generates an ephemeral key, at the cost of a fresh account.
func loadAccountKey(dir, caID string, logger *slog.Logger) crypto.PrivateKey {
	path := filepath.Join(dir, caID+".key")
	if raw, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(raw); block != nil {
			if key, perr := x509.ParseECPrivateKey(block.Bytes); perr == nil {
				return key
			}
		}
		logger.Warn("acme account key unreadable; generating a new one", "ca", caID)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Warn("acme account key generation failed", "ca", caID, "err", err)
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		logger.Warn("acme account dir create failed", "ca", caID, "err", err)
		return key
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err == nil {
		if werr := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); werr != nil {
			logger.Warn("acme account key persist failed", "ca", caID, "err", werr)
		}
	}
	return key
}
