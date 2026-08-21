package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// buildVerifier constructs the attestation verifier and returns its refreshable components so Run can
// start their background refreshers. A root/status INITIAL fetch failure is non-fatal: the returned
// objects are non-nil and fail closed (rejecting everything) until a refresher self-heals. A signer-
// allowlist load failure is FATAL — the file is local operator configuration, so a bad file fails fast.
func buildVerifier(ctx context.Context, cfg config.ServeCmd, logger *slog.Logger) (*attest.Verifier, *attest.RootSet, *attest.StatusList, *attest.SignerAllowlist, error) {
	signers, err := attest.LoadSignerAllowlist(cfg.AttestSignerDigestFile, logger)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("attestation signer allowlist: %w", err)
	}
	// A hard per-request timeout: a black-holed root/status URL must never wedge a refresher tick —
	// a stuck fetch would let the status snapshot exceed --attest-status-max-stale with no self-heal.
	fetchClient := &http.Client{Timeout: 30 * time.Second}
	roots, err := attest.NewRootSet(ctx, cfg.AttestRootURL, fetchClient, logger)
	if err != nil {
		logger.Warn("attestation root fetch failed (fail-closed until refresh)", "err", err)
	}
	status, err := attest.NewStatusList(ctx, cfg.AttestStatusURL, fetchClient, logger)
	if err != nil {
		logger.Warn("attestation status fetch failed (fail-closed until refresh)", "err", err)
	}
	return attest.NewVerifier(roots, status, signers, cfg.AttestStatusMaxStale), roots, status, signers, nil
}

// meshRotateRetry is the short backoff between a FAILED mesh-cert rotation and the next attempt (so a
// transient CA-signing blip does not leave a dead :9443 until the next 2/3-TTL tick).
const meshRotateRetry = 5 * time.Minute

// meshSigner mints one mesh-role cert/key PEM pair (default ca.CA.SignMesh; a seam so tests can drive a
// mint failure / rotation retry without a real signing failure).
type meshSigner func(nodeID string, ttl time.Duration) (certPEM, keyPEM []byte, err error)

// meshCertHolder holds this node's hot-swappable mesh-role cert, re-minted before --mesh-cert-ttl.
type meshCertHolder struct {
	nodeID string
	ttl    time.Duration
	logger *slog.Logger
	sign   meshSigner
	cur    atomic.Pointer[tls.Certificate]
	after  func(time.Duration) <-chan time.Time // seam: default time.After; overridden in tests
}

// newMeshCertHolder mints the first mesh cert; a failure is FATAL — the caller must not bind :9443 with
// no servable cert (docs/ARCHITECTURE.md §1: a socket is never bound while it cannot be served).
// signOverride is a test-only seam to drive a mint failure through the constructor; production passes none
// and uses caObj.SignMesh.
func newMeshCertHolder(caObj *ca.CA, nodeID string, ttl time.Duration, logger *slog.Logger, signOverride ...meshSigner) (*meshCertHolder, error) {
	sign := caObj.SignMesh
	if len(signOverride) > 0 {
		sign = signOverride[0]
	}
	h := &meshCertHolder{nodeID: nodeID, ttl: ttl, logger: logger, sign: sign, after: time.After}
	if err := h.mint(); err != nil {
		return nil, fmt.Errorf("mesh cert initial mint: %w", err)
	}
	return h, nil
}

func (h *meshCertHolder) mint() error {
	certPEM, keyPEM, err := h.sign(h.nodeID, h.ttl)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	h.cur.Store(&cert)
	return nil
}

// getCert is the mesh listener's tls.Config.GetCertificate.
func (h *meshCertHolder) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return h.cur.Load(), nil
}

// clientTLS returns the mesh client's tls.Config factory (hot cert via GetClientCertificate; peer mesh
// certs are verified by chain-to-CA + mesh-role, NOT by hostname — see meshVerifyConnection).
func (h *meshCertHolder) clientTLS(caObj *ca.CA) func() *tls.Config {
	pool := caObj.Pool()
	return func() *tls.Config {
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2"},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if c := h.cur.Load(); c != nil {
					return c, nil
				}
				return &tls.Certificate{}, nil
			},
			// A mesh cert's identity is the node id (its SAN/CN), NOT the dial address — a node dials a peer
			// at the advertise address held in the trusted node registry, so standard hostname verification
			// does not apply. Instead verify the peer cert chains to the internal CA AND carries the
			// mesh-role marker: only a node holding a CA-signed mesh-role cert may serve the mesh.
			// VerifyConnection (NOT VerifyPeerCertificate) also runs on RESUMED sessions, so a resumed
			// handshake cannot bypass the custom check.
			InsecureSkipVerify: true,
			VerifyConnection:   meshVerifyConnection(pool),
		}
	}
}

// meshVerifyConnection verifies a mesh peer's certificate chains to the internal CA and carries the
// mesh-role marker. Hostname verification is intentionally skipped (the cert identity is the node id, and
// the dial address comes from the trusted node registry). It runs on full AND resumed handshakes.
func meshVerifyConnection(roots *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("mesh: peer presented no certificate")
		}
		leaf := cs.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("mesh: peer cert not trusted: %w", err)
		}
		if !ca.HasMeshRole(leaf) {
			return errors.New("mesh: peer cert lacks the mesh-role marker")
		}
		return nil
	}
}

// rotateLoop re-mints the mesh cert at 2/3 of its TTL so a fresh cert is always available before expiry.
// A FAILED rotation retries after meshRotateRetry (not a full interval), so a transient signing blip does
// not leave the current cert to expire.
func (h *meshCertHolder) rotateLoop(ctx context.Context) {
	interval := h.ttl * 2 / 3
	if interval <= 0 {
		interval = time.Hour
	}
	d := interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.after(d):
		}
		if err := h.mint(); err != nil {
			h.logger.Warn("mesh cert rotation failed (retrying on backoff)", "err", err)
			d = meshRotateRetry
		} else {
			d = interval
		}
	}
}

// heartbeatNode registers this node in the node registry and refreshes it at route-ttl/3 (matching the
// route-entry TTL), until ctx is cancelled. It stamps the NodeInfo (incl. a fresh last_heartbeat) on every
// write. A refresh error is transient (RefreshNode is a plain SET, so the next tick re-registers): log and
// keep going — exiting would let node:{id} expire and break cross-node routing to this node until restart.
func heartbeatNode(ctx context.Context, reg *router.Registry, nodeID, advertise, nodeHost, version, startedAt string, routeTTL time.Duration, logger *slog.Logger) error {
	info := func() router.NodeInfo {
		return router.NodeInfo{
			Advertise:     advertise,
			Hostname:      nodeHost,
			Version:       version,
			StartedAt:     startedAt,
			LastHeartbeat: time.Now().UTC().Format(time.RFC3339),
		}
	}
	if err := reg.RegisterNode(ctx, nodeID, info(), routeTTL); err != nil {
		logger.Warn("node register failed (retrying at heartbeat cadence)", "err", err)
	}
	interval := routeTTL / 3
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := reg.RefreshNode(ctx, nodeID, info(), routeTTL); err != nil {
				logger.Warn("node heartbeat refresh failed (will retry)", "err", err)
			}
		}
	}
}

// ensureLifecyclesRetry applies the S3 retention lifecycle rules (conn logs 90d, rejected-enroll 30d),
// retrying every 5 minutes until they land or ctx ends — retention is a documented compliance property
// and must not be skipped for the whole process lifetime on one transient boot-time S3 error.
func ensureLifecyclesRetry(ctx context.Context, st *store.S3Store, logger *slog.Logger) error {
	for {
		err := st.EnsureLifecycles(ctx, 90, 30)
		if err == nil {
			return nil
		}
		logger.Warn("ensure lifecycles failed (retrying in 5m)", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Minute):
		}
	}
}

// renewalWatcher periodically scans this node's connected tunnels and nudges the phone to renew any cert
// the chain says is due (NotAfter−margin floor for LE, fixed cadence otherwise). The nudge carries a fresh single-use
// challenge nonce and is best-effort: the phone drives the actual renewal by calling the mTLS POST /api/v1/issue
// endpoint with a fresh attestation over that nonce.
type renewalWatcher struct {
	mgr    *phoneconn.Manager
	names  store.NameStore
	chain  acmeChain
	nonce  func(ctx context.Context) (string, error) // mints the single-use renewal challenge nonce
	logger *slog.Logger
}

func (w *renewalWatcher) run(ctx context.Context, interval time.Duration) error {
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
			w.tick(ctx)
		}
	}
}

func (w *renewalWatcher) tick(ctx context.Context) {
	for _, name := range w.mgr.ConnectedNames() {
		rec, err := w.names.GetName(ctx, name)
		if err != nil {
			// Never silent: a persistent store failure would otherwise stop all renewal nudges (and
			// eventually expire certs) with zero operator signal.
			w.logger.Warn("renewal watcher: name record read failed", "tunnel", name, "err", err)
			continue
		}
		due, at, err := w.chain.ShouldRenew(ctx, rec.CertInfo())
		if err != nil {
			w.logger.Warn("renewal watcher: ShouldRenew failed", "tunnel", name, "err", err)
			continue
		}
		if !due {
			continue
		}
		nonceHex, err := w.nonce(ctx)
		if err != nil {
			w.logger.Warn("renewal nonce mint failed", "tunnel", name, "err", err)
			continue
		}
		w.mgr.SendRenewNudge(name, nonceHex, at.UTC().Format(time.RFC3339))
	}
}
