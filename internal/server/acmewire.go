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
	"strings"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
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
	ObtainSelf(ctx context.Context, host string, cur store.CertInfo) (certPEM, keyPEM []byte, info store.CertInfo, err error)
	ACMEBudgetLevels(ctx context.Context) ([]acme.BudgetLevel, error)
}

// buildACMEChain constructs the LE→GTS→ZeroSSL chain from config: accounts whose keys are
// persisted under --acme-account-dir/accounts, and lazy self-healing clients (startup never blocks on CA
// reachability).
func buildACMEChain(cfg config.ServeCmd, lim *limit.Limiter, chal *acme.ChallengeStore, rec acme.Recorder, logger *slog.Logger, nodeID string, nodes acme.NodeLister) (acmeChain, error) {
	acme.SetLogOutput(os.Stderr)
	budgets, err := budgetsFrom(cfg)
	if err != nil {
		return nil, err
	}
	legoCfgs, err := acmeLegoConfigs(cfg, chal, logger, nodeID)
	if err != nil {
		return nil, err
	}
	chainCfg := acme.ChainConfig{
		Limiter: lim, Recorder: rec, Logger: logger,
		CooldownDefault: cfg.ACMECooldownDefault, BackoffInitial: cfg.ACMEBackoffInitial,
		BackoffMax: cfg.ACMEBackoffMax, RenewMargin: cfg.ACMERenewMargin, ShortlivedLifetime: shortlivedLifetime,
		NodeID: nodeID, Nodes: nodes, Budgets: budgets, PollEvery: cfg.ACMEPollInterval,
	}
	chain, err := acme.NewChain(chainCfg, legoCfgs...)
	if err != nil {
		return nil, err
	}
	return chain, nil
}

func acmeLegoConfigs(cfg config.ServeCmd, chal *acme.ChallengeStore, logger *slog.Logger, nodeID string) ([]acme.LegoConfig, error) {
	accountsDir := filepath.Join(cfg.ACMEAccountDir, "accounts")
	var cfgs []acme.LegoConfig
	if cfg.LEEnabled() {
		key, err := loadAccountKey(accountsDir, acme.CALetsEncrypt, logger)
		if err != nil {
			return nil, err
		}
		id, err := accountID(acme.CALetsEncrypt, nodeID, key)
		if err != nil {
			return nil, err
		}
		cfgs = append(cfgs, acme.LegoConfig{
			CAID: acme.CALetsEncrypt, DirectoryURL: cfg.ACMEDirLE, Email: cfg.ACMEEmail,
			AccountKey: key, AccountID: id, Label: "local",
			AttemptTimeout: cfg.ACMEAttemptTimeoutLE, PollFirst: cfg.ACMEPollFirstLE,
			Profile: cfg.ACMELEProfile, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
			UseARI:    true,
			Challenge: cfg.ACMEChallengeLE, TLSALPN: chal, HTTP: chal, Logger: logger,
			DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
		})
	}
	for _, gtsName := range cfg.ACMEGTSAccounts {
		key, err := loadExistingAccountKey(accountsDir, gtsName)
		if err != nil {
			return nil, err
		}
		id, err := accountID(acme.CAGTS, nodeID, key)
		if err != nil {
			return nil, err
		}
		cfgs = append(cfgs, acme.LegoConfig{
			CAID: acme.CAGTS, DirectoryURL: cfg.ACMEDirGTS, Email: cfg.ACMEEmail,
			AccountKey: key, AccountID: id, Label: gtsName, ResolveOnly: true,
			AttemptTimeout: cfg.ACMEAttemptTimeoutGTS, PollFirst: cfg.ACMEPollFirstGTS,
			Validity: cfg.ACMEGTSValidity, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
			Challenge: cfg.ACMEChallengeGTS, TLSALPN: chal, HTTP: chal, Logger: logger,
			DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
		})
	}
	if cfg.ZeroSSLEnabled() {
		key, err := loadAccountKey(accountsDir, acme.CAZeroSSL, logger)
		if err != nil {
			return nil, err
		}
		id, err := accountID(acme.CAZeroSSL, nodeID, key)
		if err != nil {
			return nil, err
		}
		cfgs = append(cfgs, acme.LegoConfig{
			CAID: acme.CAZeroSSL, DirectoryURL: cfg.ACMEDirZeroSSL, Email: cfg.ACMEEmail,
			AccountKey: key, AccountID: id, Label: "local",
			AttemptTimeout: cfg.ACMEAttemptTimeoutZeroSSL, PollFirst: cfg.ACMEPollFirstZeroSSL,
			RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
			EABKID: cfg.ACMEEABZeroSSLKID, EABHMAC: cfg.ACMEEABZeroSSLHMAC,
			Challenge: cfg.ACMEChallengeZeroSSL, TLSALPN: chal, HTTP: chal, Logger: logger,
			DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
		})
	}
	if cfg.UsesChallenge(config.ChallengeDNS01) {
		dnsProvider, err := acme.DNSProviderByName(cfg.ACMEDNSProvider)
		if err != nil {
			logger.Warn("acme dns provider unavailable (issuance degraded until configured)",
				"provider", cfg.ACMEDNSProvider, "err", err)
		} else {
			for i := range cfgs {
				cfgs[i].RawDNS = dnsProvider
			}
		}
	}
	return cfgs, nil
}

func loadExistingAccountKey(dir, id string) (crypto.Signer, error) {
	path := filepath.Join(dir, id+".key")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gts account key %s (tunneld never creates GTS accounts; place the registered account's key here): %w", path, err)
	}
	key, err := parseECPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("gts account key %s exists but is unparseable: %w", path, err)
	}
	return key, nil
}

func accountID(caID, nodeID string, key crypto.Signer) (string, error) {
	if key == nil {
		return caID + "-ephemeral-" + nodeID, nil
	}
	fp, err := ca.KeyFingerprint(key.Public())
	if err != nil {
		return "", fmt.Errorf("acme account id (%s): %w", caID, err)
	}
	return caID + "-" + strings.TrimPrefix(fp, "sha256:")[:16], nil
}

func budgetsFrom(cfg config.ServeCmd) (acme.Budgets, error) {
	b := acme.Budgets{Domain: strings.ToLower(cfg.TunnelDomain)}
	for _, r := range []struct {
		name string
		v    string
		dst  *limit.Rate
	}{
		{"--acme-budget-le-domain", cfg.ACMEBudgetLEDomain, &b.LEDomain},
		{"--acme-budget-le-orders", cfg.ACMEBudgetLEOrders, &b.LEOrders},
		{"--acme-budget-le-name", cfg.ACMEBudgetLEName, &b.LEName},
		{"--acme-budget-gts-orders", cfg.ACMEBudgetGTSOrders, &b.GTSOrders},
		{"--acme-budget-gts-requests", cfg.ACMEBudgetGTSRequests, &b.GTSRequests},
		{"--acme-budget-gts-cert-polls", cfg.ACMEBudgetGTSCertPolls, &b.GTSCertPolls},
		{"--acme-budget-zerossl-orders", cfg.ACMEBudgetZeroSSLOrders, &b.ZeroSSLOrders},
		{"--acme-budget-zerossl-requests", cfg.ACMEBudgetZeroSSLRequests, &b.ZeroSSLRequests},
	} {
		p, err := config.ParseRate(r.v)
		if err != nil {
			return acme.Budgets{}, fmt.Errorf("%s: %w", r.name, err)
		}
		*r.dst = limit.Rate{Count: p.Count, Period: p.Period, Burst: p.Burst}
	}
	return b, nil
}

// loadAccountKey loads the per-CA ACME account key under dir/<caid>.key. If the file EXISTS but cannot
// be read or parsed as an EC private key (SEC1 or PKCS#8), startup FAILS — an unreadable existing key
// means something is wrong (corruption / wrong file / bad permissions), and silently minting a new
// account would abandon the existing (EAB-bound) account. A new key is generated ONLY when the file is
// absent; generation/persistence there is best-effort (a failure costs a re-registered account).
func loadAccountKey(dir, caID string, logger *slog.Logger) (crypto.Signer, error) {
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
	der, merr := x509.MarshalECPrivateKey(key)
	if merr != nil {
		logger.Warn("acme account key encode failed; using an ephemeral account key", "ca", caID, "err", merr)
		return key, nil
	}
	if werr := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); werr != nil {
		logger.Warn("acme account key persist failed; using an ephemeral account key", "ca", caID, "err", werr)
	}
	return key, nil
}

// parseECPrivateKey accepts an EC key in SEC1 or PKCS#8 encoding.
func parseECPrivateKey(pemRaw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemRaw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	k1, sec1Err := x509.ParseECPrivateKey(block.Bytes)
	if sec1Err == nil {
		return k1, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("parse as SEC1: %w", sec1Err), fmt.Errorf("parse as PKCS#8: %w", err))
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("account key is %T, want *ecdsa.PrivateKey", k)
	}
	return ec, nil
}
