package server

import (
	"context"
	"crypto/tls"
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

// buildVerifier constructs the attestation verifier. A root/status fetch failure is non-fatal: the
// verifier fails closed (rejecting everything) until a refresher self-heals; the signer allowlist is
// hot-reloaded from disk.
func buildVerifier(ctx context.Context, cfg config.ServeCmd, logger *slog.Logger) *attest.Verifier {
	signers, err := attest.LoadSignerAllowlist(cfg.AttestSignerDigestFile)
	if err != nil {
		logger.Warn("attestation signer allowlist load failed", "err", err)
	}
	roots, err := attest.NewRootSet(ctx, cfg.AttestRootURL, http.DefaultClient)
	if err != nil {
		logger.Warn("attestation root fetch failed (fail-closed until refresh)", "err", err)
	}
	status, err := attest.NewStatusList(ctx, cfg.AttestStatusURL, http.DefaultClient)
	if err != nil {
		logger.Warn("attestation status fetch failed (fail-closed until refresh)", "err", err)
	}
	return attest.NewVerifier(roots, status, signers, cfg.AttestStatusMaxStale)
}

// meshCertHolder holds this node's hot-swappable mesh-role cert, re-minted before --mesh-cert-ttl.
type meshCertHolder struct {
	nodeID string
	ttl    time.Duration
	logger *slog.Logger
	cur    atomic.Pointer[tls.Certificate]
}

func newMeshCertHolder(caObj *ca.CA, nodeID string, ttl time.Duration, logger *slog.Logger) *meshCertHolder {
	h := &meshCertHolder{nodeID: nodeID, ttl: ttl, logger: logger}
	h.mint(caObj)
	return h
}

func (h *meshCertHolder) mint(caObj *ca.CA) {
	certPEM, keyPEM, err := caObj.SignMesh(h.nodeID, h.ttl)
	if err != nil {
		h.logger.Warn("mesh cert mint failed", "err", err)
		return
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		h.logger.Warn("mesh cert parse failed", "err", err)
		return
	}
	h.cur.Store(&cert)
}

// getCert is the mesh listener's tls.Config.GetCertificate.
func (h *meshCertHolder) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) { return h.cur.Load(), nil }

// clientTLS returns the mesh client's tls.Config factory (hot cert via GetClientCertificate, internal-CA
// roots for verifying peer mesh certs).
func (h *meshCertHolder) clientTLS(caObj *ca.CA) func() *tls.Config {
	pool := caObj.Pool()
	return func() *tls.Config {
		return &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2"},
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if c := h.cur.Load(); c != nil {
					return c, nil
				}
				return &tls.Certificate{}, nil
			},
		}
	}
}

// rotateLoop re-mints the mesh cert at 2/3 of its TTL so a fresh cert is always available before expiry.
func (h *meshCertHolder) rotateLoop(ctx context.Context, caObj *ca.CA) {
	interval := h.ttl * 2 / 3
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.mint(caObj)
		}
	}
}

// heartbeatNode registers this node in the node registry and refreshes it at route-ttl/3 (matching the
// route-entry TTL), until ctx is cancelled.
func heartbeatNode(ctx context.Context, reg *router.Registry, nodeID, advertise string, routeTTL time.Duration) error {
	_ = reg.RegisterNode(ctx, nodeID, advertise, routeTTL)
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
			if err := reg.RefreshNode(ctx, nodeID, advertise, routeTTL); err != nil {
				return nil
			}
		}
	}
}

// renewalWatcher periodically scans this node's connected tunnels and nudges the phone to renew any cert
// the chain says is due (ARI-driven for LE, fixed cadence otherwise). The nudge is best-effort: the
// phone drives the actual renewal exchange (RENEW_REQUEST → challenge → submit).
type renewalWatcher struct {
	mgr    *phoneconn.Manager
	names  store.NameStore
	chain  acmeChain
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
			continue
		}
		due, at, err := w.chain.ShouldRenew(ctx, rec.Cert)
		if err != nil || !due {
			continue
		}
		w.mgr.SendRenewNudge(name, at.UTC().Format(time.RFC3339))
	}
}
