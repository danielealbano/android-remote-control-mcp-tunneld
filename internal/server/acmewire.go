package server

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
	"io/fs"
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
func buildACMEChain(cfg config.ServeCmd, lim *limit.Limiter, rec acme.Recorder, logger *slog.Logger) (acmeChain, error) {
	dnsProvider, err := acme.DNSProviderByName(cfg.ACMEDNSProvider)
	if err != nil {
		logger.Warn("acme dns provider unavailable (issuance degraded until configured)",
			"provider", cfg.ACMEDNSProvider, "err", err)
	}
	accountsDir := filepath.Join(cfg.ACMEAccountDir, "accounts")

	leKey, err := loadAccountKey(accountsDir, acme.CALetsEncrypt, logger)
	if err != nil {
		return nil, err
	}
	gtsKey, err := loadAccountKey(accountsDir, acme.CAGTS, logger)
	if err != nil {
		return nil, err
	}
	zerosslKey, err := loadAccountKey(accountsDir, acme.CAZeroSSL, logger)
	if err != nil {
		return nil, err
	}

	chainCfg := acme.ChainConfig{
		Limiter: lim, Recorder: rec,
		CooldownDefault: cfg.ACMECooldownDefault, BackoffInitial: cfg.ACMEBackoffInitial,
		BackoffMax: cfg.ACMEBackoffMax, RenewMargin: cfg.ACMERenewMargin, ShortlivedLifetime: shortlivedLifetime,
	}
	le := acme.LegoConfig{
		CAID: acme.CALetsEncrypt, DirectoryURL: cfg.ACMEDirLE, Email: cfg.ACMEEmail,
		AccountKey: leKey,
		Profile:    cfg.ACMELEProfile, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		UseARI: true, RawDNS: dnsProvider,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	gts := acme.LegoConfig{
		CAID: acme.CAGTS, DirectoryURL: cfg.ACMEDirGTS, Email: cfg.ACMEEmail,
		AccountKey: gtsKey,
		Validity:   cfg.ACMEGTSValidity, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		EABKID: cfg.ACMEEABGTSKID, EABHMAC: cfg.ACMEEABGTSHMAC, RawDNS: dnsProvider,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	zerossl := acme.LegoConfig{
		CAID: acme.CAZeroSSL, DirectoryURL: cfg.ACMEDirZeroSSL, Email: cfg.ACMEEmail,
		AccountKey:  zerosslKey,
		RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		EABKID: cfg.ACMEEABZeroSSLKID, EABHMAC: cfg.ACMEEABZeroSSLHMAC, RawDNS: dnsProvider,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	return acme.NewChain(chainCfg, le, gts, zerossl), nil
}

// loadAccountKey loads the per-CA ACME account key under dir/<caid>.key. If the file EXISTS but cannot
// be read or parsed as an EC private key (SEC1 or PKCS#8), startup FAILS — an unreadable existing key
// means something is wrong (corruption / wrong file / bad permissions), and silently minting a new
// account would abandon the existing (EAB-bound) account. A new key is generated ONLY when the file is
// absent; generation/persistence there is best-effort (a failure costs a re-registered account).
func loadAccountKey(dir, caID string, logger *slog.Logger) (crypto.PrivateKey, error) {
	path := filepath.Join(dir, caID+".key")
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, perr := parseECPrivateKey(raw)
		if perr != nil {
			return nil, fmt.Errorf("acme account key %s exists but is unparseable (refusing to overwrite): %w", path, perr)
		}
		return key, nil
	case errors.Is(err, fs.ErrNotExist):
		// absent → generate + best-effort persist below
	default:
		return nil, fmt.Errorf("acme account key %s exists but could not be read (refusing to continue): %w", path, err)
	}
	key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if gerr != nil {
		// Absent-path generation failure stays NON-fatal: a nil key makes NewLegoClient self-generate an
		// ephemeral account key. Only an existing-but-unreadable/unparseable key is fatal (above).
		logger.Warn("acme account key generation failed; lego will use an ephemeral key", "ca", caID, "err", gerr)
		return nil, nil
	}
	if merr := os.MkdirAll(dir, 0o700); merr != nil {
		logger.Warn("acme account dir create failed; using an ephemeral account key", "ca", caID, "err", merr)
		return key, nil
	}
	if der, merr := x509.MarshalECPrivateKey(key); merr == nil {
		if werr := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); werr != nil {
			logger.Warn("acme account key persist failed; using an ephemeral account key", "ca", caID, "err", werr)
		}
	}
	return key, nil
}

// parseECPrivateKey accepts an EC key in SEC1 or PKCS#8 encoding.
func parseECPrivateKey(pemRaw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemRaw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("account key is %T, want *ecdsa.PrivateKey", k)
	}
	return ec, nil
}
