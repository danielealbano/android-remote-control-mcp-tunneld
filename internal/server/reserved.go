package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
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

type selfLocker interface {
	LockSelf(ctx context.Context, host string) (unlock func() error, ok bool, err error)
}

const (
	reservedDegradedRetry = time.Minute
	selfLockWait          = 5 * time.Minute
	selfIssueTimeout      = 5 * time.Minute
	selfLockPoll          = 2 * time.Second
)

var errNoReservedCert = errors.New("server: no reserved-host certificate yet")

// reservedHost holds one reserved hostname's hot-swappable cert + issuing metadata.
type reservedHost struct {
	host string
	cur  atomic.Pointer[tls.Certificate]

	mu   sync.Mutex
	info store.CertInfo
}

// reservedCerts manages the --enroll-host/--control-host server certs: on start it reuses a valid
// cached pair from disk (a restart orders nothing) or obtains one via the ACME chain; when no usable
// cache exists it starts DEGRADED (reserved-host TLS refused until a cert lands, tunnel splicing
// unaffected); and it renews on the chain's schedule, re-persisting each new pair.
type reservedCerts struct {
	dir          string // <acme-account-dir>/self
	obtain       selfIssuer
	shouldRenew  shouldRenewFunc
	lock         selfLocker
	lockWait     time.Duration
	issueTimeout time.Duration
	lockPoll     time.Duration
	logger       *slog.Logger
	now          func() time.Time

	hosts map[string]*reservedHost
}

// newReservedCerts builds the manager.
func newReservedCerts(accountDir string, hosts []string, obtain selfIssuer, shouldRenew shouldRenewFunc,
	lock selfLocker, logger *slog.Logger) *reservedCerts {
	rc := &reservedCerts{
		dir: filepath.Join(accountDir, "self"), obtain: obtain, shouldRenew: shouldRenew, lock: lock,
		lockWait: selfLockWait, issueTimeout: selfIssueTimeout, lockPoll: selfLockPoll,
		logger: logger, now: time.Now, hosts: map[string]*reservedHost{},
	}
	for _, h := range hosts {
		rc.hosts[h] = &reservedHost{host: h}
	}
	return rc
}

func (rc *reservedCerts) loadCache() {
	for _, rh := range rc.hosts {
		if cert, info, ok := rc.loadCached(rh.host); ok && rc.now().Before(info.NotAfter) {
			rh.store(cert, info)
		}
	}
}

func (rc *reservedCerts) run(ctx context.Context, renewEvery, degradedEvery time.Duration) error {
	for {
		for _, rh := range rc.hosts {
			rc.maybeRenew(ctx, rh)
		}
		wait := renewEvery
		if rc.degraded() {
			wait = degradedEvery
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

func (rc *reservedCerts) degraded() bool {
	for _, rh := range rc.hosts {
		if rh.cur.Load() == nil {
			return true
		}
	}
	return false
}

func (rc *reservedCerts) maybeRenew(ctx context.Context, rh *reservedHost) {
	if rh.cur.Load() != nil {
		due, _, err := rc.shouldRenew(ctx, rh.currentInfo())
		if err != nil {
			rc.logger.Warn("reserved-host renewal check failed (will retry next scan)", "host", rh.host, "err", err)
			return
		}
		if !due {
			return
		}
	}
	rc.issue(ctx, rh)
}

func (rc *reservedCerts) issue(ctx context.Context, rh *reservedHost) {
	lockCtx, lockCancel := context.WithTimeout(ctx, rc.lockWait)
	unlock, locked, err := rc.acquire(lockCtx, rh.host)
	lockCancel()
	switch {
	case ctx.Err() != nil:
		if locked {
			rc.releaseLock(rh.host, unlock)
		}
		return
	case err != nil:
		rc.logger.Warn("reserved-host issuance lock unavailable (issuing without it)", "host", rh.host, "err", err)
	case !locked:
		rc.logger.Info("reserved-host issuance busy on another node (will retry)", "host", rh.host)
		return
	}
	issueCtx, cancel := context.WithTimeout(ctx, rc.issueTimeout)
	defer cancel()
	certPEM, keyPEM, info, err := rc.obtain(issueCtx, rh.host)
	abandoned := err != nil && ctx.Err() == nil && issueCtx.Err() != nil
	if locked {
		if abandoned {
			rc.logger.Warn("reserved-host issuance abandoned at its deadline (lock kept until its TTL)", "host", rh.host)
		} else {
			rc.releaseLock(rh.host, unlock)
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if rh.cur.Load() == nil {
			rc.logger.Warn("reserved-host cert unavailable (degraded; will retry)", "host", rh.host, "err", err)
		} else {
			rc.logger.Warn("reserved-host cert renewal failed (keeping current)", "host", rh.host, "err", err)
		}
		return
	}
	c, perr := tls.X509KeyPair(certPEM, keyPEM)
	if perr != nil {
		rc.logger.Warn("reserved-host cert parse failed", "host", rh.host, "err", perr)
		return
	}
	rh.store(&c, info)
	rc.persist(rh.host, certPEM, keyPEM, info)
}

func (rc *reservedCerts) releaseLock(host string, unlock func() error) {
	if err := unlock(); err != nil {
		rc.logger.Warn("reserved-host issuance lock release failed (expires by TTL)", "host", host, "err", err)
	}
}

func (rc *reservedCerts) acquire(ctx context.Context, host string) (func() error, bool, error) {
	for {
		unlock, ok, err := rc.lock.LockSelf(ctx, host)
		if err != nil && ctx.Err() != nil {
			return unlock, false, nil
		}
		if err != nil || ok {
			return unlock, ok, err
		}
		t := time.NewTimer(rc.lockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return unlock, false, nil
		case <-t.C:
		}
	}
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
	if cert, info, ok := rc.loadBundle(host, filepath.Join(dir, "bundle.json")); ok {
		return cert, info, true
	}
	return rc.loadLegacyTriple(host, dir)
}

// loadBundle reads the atomic single-file cache. A missing, truncated, or unparseable bundle reports
// absent (ok=false) rather than erroring — the caller then tries the legacy triple / re-obtains.
func (rc *reservedCerts) loadBundle(host, path string) (*tls.Certificate, store.CertInfo, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			rc.logger.Warn("reserved-host cert bundle unreadable", "host", host, "err", err)
		}
		return nil, store.CertInfo{}, false
	}
	var b certBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		rc.logger.Warn("reserved-host cert bundle unparseable", "host", host, "err", err)
		return nil, store.CertInfo{}, false
	}
	cert, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	if err != nil {
		rc.logger.Warn("reserved-host cert bundle holds no usable key pair", "host", host, "err", err)
		return nil, store.CertInfo{}, false
	}
	info := b.Info
	if info.NotAfter.IsZero() {
		na, err := leafNotAfter([]byte(b.CertPEM))
		if err != nil {
			rc.logger.Warn("reserved-host cert bundle leaf unparseable", "host", host, "err", err)
			return nil, store.CertInfo{}, false
		}
		info.NotAfter = na
	}
	return &cert, info, true
}

// loadLegacyTriple reads the pre-bundle cert.pem/key.pem/meta.json cache.
func (rc *reservedCerts) loadLegacyTriple(host, dir string) (*tls.Certificate, store.CertInfo, bool) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			rc.logger.Warn("reserved-host legacy cert unreadable", "host", host, "err", err)
		}
		return nil, store.CertInfo{}, false
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		rc.logger.Warn("reserved-host legacy key unreadable", "host", host, "err", err)
		return nil, store.CertInfo{}, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		rc.logger.Warn("reserved-host legacy cache holds no usable key pair", "host", host, "err", err)
		return nil, store.CertInfo{}, false
	}
	info := store.CertInfo{}
	metaRaw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	switch {
	case err == nil:
		if err := json.Unmarshal(metaRaw, &info); err != nil {
			rc.logger.Warn("reserved-host legacy meta unparseable (using the leaf's NotAfter)", "host", host, "err", err)
			info = store.CertInfo{}
		}
	case !errors.Is(err, fs.ErrNotExist):
		rc.logger.Warn("reserved-host legacy meta unreadable (using the leaf's NotAfter)", "host", host, "err", err)
	}
	if info.NotAfter.IsZero() {
		na, err := leafNotAfter(certPEM)
		if err != nil {
			rc.logger.Warn("reserved-host legacy leaf unparseable", "host", host, "err", err)
			return nil, store.CertInfo{}, false
		}
		info.NotAfter = na
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
	raw, err := json.Marshal(certBundle{CertPEM: string(certPEM), KeyPEM: string(keyPEM), Info: info})
	if err != nil {
		rc.logger.Warn("reserved-host cert bundle encode failed", "host", host, "err", err)
		return
	}
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
func leafNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("no PEM certificate block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}
