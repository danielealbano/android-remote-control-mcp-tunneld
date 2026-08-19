package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// selfIssuer obtains a publicly-trusted cert for one of tunneld's OWN reserved hostnames (server-side
// key + CSR) via the ACME chain. Wired to acme.chainIssuer.ObtainSelf.
type selfIssuer func(ctx context.Context, host string) (certPEM, keyPEM []byte, info store.CertInfo, err error)

// shouldRenewFunc reports whether cur should renew now (chain.ShouldRenew, CA-dispatched).
type shouldRenewFunc func(ctx context.Context, cur store.CertInfo) (bool, time.Time, error)

var errNoReservedCert = errors.New("server: no reserved-host certificate yet")

// reservedHost holds one reserved hostname's hot-swappable cert + issuing metadata.
type reservedHost struct {
	host string
	cur  atomic.Pointer[tls.Certificate]

	mu   sync.Mutex
	info store.CertInfo
}

// reservedCerts manages the --enroll-host/--control-host server certs: on start it reuses a valid
// cached pair from disk (a restart orders nothing) or obtains one via the ACME chain; when no CA can
// issue AND no usable cache exists it starts DEGRADED (reserved-host TLS refused until a cert lands,
// tunnel splicing unaffected); and it renews on the chain's schedule, re-persisting each new pair.
type reservedCerts struct {
	dir         string // <acme-account-dir>/self
	obtain      selfIssuer
	shouldRenew shouldRenewFunc
	renewMargin time.Duration
	logger      *slog.Logger
	now         func() time.Time

	hosts map[string]*reservedHost
}

// newReservedCerts builds the manager and ensures each host's cert at startup (reuse cache or obtain;
// degraded on failure). It runs BEFORE any listener is bound, so a cold-start ACME issuance delays
// readiness but never leaves a socket bound-but-unserved; a failed obtain starts the host degraded.
func newReservedCerts(ctx context.Context, accountDir string, hosts []string, obtain selfIssuer,
	shouldRenew shouldRenewFunc, renewMargin time.Duration, logger *slog.Logger) *reservedCerts {
	rc := &reservedCerts{
		dir: filepath.Join(accountDir, "self"), obtain: obtain, shouldRenew: shouldRenew,
		renewMargin: renewMargin, logger: logger, now: time.Now, hosts: map[string]*reservedHost{},
	}
	for _, h := range hosts {
		rh := &reservedHost{host: h}
		rc.hosts[h] = rh
		rc.ensure(ctx, rh)
	}
	return rc
}

// getCertificateFor returns a tls.Config.GetCertificate bound to one host (the edge already routed by
// SNI, so each reserved listener serves exactly one host). It returns an error while degraded.
func (rc *reservedCerts) getCertificateFor(host string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	rh := rc.hosts[host]
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if rh == nil {
			return nil, errNoReservedCert
		}
		if c := rh.cur.Load(); c != nil {
			return c, nil
		}
		return nil, errNoReservedCert
	}
}

// ensure loads a valid cached pair (reuse), else obtains + persists one; on obtain failure it keeps any
// non-expired cache and otherwise leaves the host degraded.
func (rc *reservedCerts) ensure(ctx context.Context, rh *reservedHost) {
	cert, info, ok := rc.loadCached(rh.host)
	if ok {
		notAfter := info.NotAfter
		switch {
		case notAfter.Sub(rc.now()) > rc.renewMargin:
			rh.store(cert, info)
			return // valid cache — reuse, order nothing
		case rc.now().Before(notAfter):
			rh.store(cert, info) // still valid but expiring — serve it, then try to renew below
		}
	}
	certPEM, keyPEM, newInfo, err := rc.obtain(ctx, rh.host)
	if err != nil {
		if rh.cur.Load() == nil {
			rc.logger.Warn("reserved-host cert unavailable (degraded; will retry on schedule)", "host", rh.host, "err", err)
		}
		return
	}
	c, perr := tls.X509KeyPair(certPEM, keyPEM)
	if perr != nil {
		rc.logger.Warn("reserved-host cert parse failed", "host", rh.host, "err", perr)
		return
	}
	rh.store(&c, newInfo)
	rc.persist(rh.host, certPEM, keyPEM, newInfo)
}

func (rh *reservedHost) store(cert *tls.Certificate, info store.CertInfo) {
	rh.cur.Store(cert)
	rh.mu.Lock()
	rh.info = info
	rh.mu.Unlock()
}

func (rh *reservedHost) currentInfo() store.CertInfo {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	return rh.info
}

// runRenewal renews each reserved cert on the chain's schedule (or immediately when a host is still
// degraded), re-persisting each new pair. It runs until ctx is cancelled.
func (rc *reservedCerts) runRenewal(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			for _, rh := range rc.hosts {
				rc.maybeRenew(ctx, rh)
			}
		}
	}
}

func (rc *reservedCerts) maybeRenew(ctx context.Context, rh *reservedHost) {
	if rh.cur.Load() == nil {
		rc.ensure(ctx, rh) // still degraded — retry issuance
		return
	}
	due, _, err := rc.shouldRenew(ctx, rh.currentInfo())
	if err != nil {
		rc.logger.Warn("reserved-host renewal check failed (will retry next scan)", "host", rh.host, "err", err)
		return
	}
	if !due {
		return
	}
	certPEM, keyPEM, info, err := rc.obtain(ctx, rh.host)
	if err != nil {
		rc.logger.Warn("reserved-host cert renewal failed (keeping current)", "host", rh.host, "err", err)
		return
	}
	c, perr := tls.X509KeyPair(certPEM, keyPEM)
	if perr != nil {
		rc.logger.Warn("reserved-host renewed cert parse failed", "host", rh.host, "err", perr)
		return
	}
	rh.store(&c, info)
	rc.persist(rh.host, certPEM, keyPEM, info)
}

func (rc *reservedCerts) hostDir(host string) string { return filepath.Join(rc.dir, host) }

// certBundle is the single-file cache: one atomic rename replaces cert+key+meta together, so a crash
// mid-persist can never mix a new key with an old cert.
type certBundle struct {
	CertPEM string         `json:"cert_pem"`
	KeyPEM  string         `json:"key_pem"`
	Info    store.CertInfo `json:"info"`
}

// loadCached reads the persisted cert for host, preferring the atomic bundle.json and falling back to
// the legacy cert.pem/key.pem/meta.json triple (caches written before the bundle format — the next
// persist upgrades them). ok is false if no complete, parseable cache exists.
func (rc *reservedCerts) loadCached(host string) (*tls.Certificate, store.CertInfo, bool) {
	dir := rc.hostDir(host)
	if cert, info, ok := loadBundle(filepath.Join(dir, "bundle.json")); ok {
		return cert, info, true
	}
	return loadLegacyTriple(dir)
}

// loadBundle reads the atomic single-file cache. A missing, truncated, or unparseable bundle reports
// absent (ok=false) rather than erroring — the caller then tries the legacy triple / re-obtains.
func loadBundle(path string) (*tls.Certificate, store.CertInfo, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, store.CertInfo{}, false
	}
	var b certBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, store.CertInfo{}, false
	}
	cert, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	if err != nil {
		return nil, store.CertInfo{}, false
	}
	info := b.Info
	if info.NotAfter.IsZero() {
		na, ok := leafNotAfter([]byte(b.CertPEM))
		if !ok {
			return nil, store.CertInfo{}, false
		}
		info.NotAfter = na
	}
	return &cert, info, true
}

// loadLegacyTriple reads the pre-bundle cert.pem/key.pem/meta.json cache.
func loadLegacyTriple(dir string) (*tls.Certificate, store.CertInfo, bool) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, store.CertInfo{}, false
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, store.CertInfo{}, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, store.CertInfo{}, false
	}
	info := store.CertInfo{}
	if metaRaw, merr := os.ReadFile(filepath.Join(dir, "meta.json")); merr == nil {
		_ = json.Unmarshal(metaRaw, &info)
	}
	if info.NotAfter.IsZero() {
		if na, ok := leafNotAfter(certPEM); ok {
			info.NotAfter = na
		} else {
			return nil, store.CertInfo{}, false
		}
	}
	return &cert, info, true
}

// persist writes the cert/key/meta as ONE atomic bundle (temp write + rename), so a crash mid-persist
// leaves either the old complete bundle or the new one — never a torn key/cert mix. Best-effort: a write
// failure only costs a re-issue on the next restart.
func (rc *reservedCerts) persist(host string, certPEM, keyPEM []byte, info store.CertInfo) {
	dir := rc.hostDir(host)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		rc.logger.Warn("reserved-host cert dir create failed", "host", host, "err", err)
		return
	}
	raw, _ := json.Marshal(certBundle{CertPEM: string(certPEM), KeyPEM: string(keyPEM), Info: info})
	tmp := filepath.Join(dir, "bundle.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		rc.logger.Warn("reserved-host cert persist failed", "host", host, "err", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, "bundle.json")); err != nil {
		rc.logger.Warn("reserved-host cert persist rename failed", "host", host, "err", err)
	}
}

// leafNotAfter parses the first certificate block's NotAfter.
func leafNotAfter(certPEM []byte) (time.Time, bool) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return c.NotAfter, true
}
