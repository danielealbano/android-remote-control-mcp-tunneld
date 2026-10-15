package client

import (
	"context"
	"encoding/json"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// renew answers a RENEW_NUDGE by delegating to Renew with the nudge's challenge nonce (best-effort; the
// connection stays on the current certs on failure).
func (c *Client) renew(ctx context.Context, payload []byte) {
	if !c.renewing.CompareAndSwap(false, true) {
		c.logger.Debug("renewal already in progress; RENEW_NUDGE ignored")
		return
	}
	defer c.renewing.Store(false)
	var nudge wire.RenewNudgePayload
	if err := json.Unmarshal(payload, &nudge); err != nil {
		c.logger.Warn("malformed RENEW_NUDGE payload from the server (ignored)", "err", err)
		return
	}
	if nudge.Nonce == "" {
		c.logger.Warn("RENEW_NUDGE without a nonce from the server (ignored)")
		return
	}
	if err := c.Renew(ctx, nudge.Nonce); err != nil {
		c.logger.Warn("renew after a RENEW_NUDGE failed (keeping the current certs)", "err", err)
	}
}

// Renew regenerates the identity + public certs via the mTLS POST /api/v1/issue endpoint (a fresh attestation
// over nonceHex + rotated CSRs) and atomically swaps in the new identity, so subsequent reconnects and
// dial-back data streams present the rotated certs. It is the programmatic form of answering a
// RENEW_NUDGE and is used directly by the integration/e2e tiers.
func (c *Client) Renew(ctx context.Context, nonceHex string) error {
	c.mu.Lock()
	name := c.ident.Name
	caID := c.ident.CA
	c.mu.Unlock()

	next, err := issueWithRetries(ctx, c.sleep, nonceHex,
		func(n string) (*Identity, error) {
			return issueCerts(ctx, c.hc, c.controlHost, name, c.tunnelDomain, caID, n)
		},
		func() (string, error) { return FetchIssueNonce(ctx, c.dialAddr, c.enrollHost, c.caPool) })
	if err != nil {
		return err
	}
	cert, err := next.tlsCertificate()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.ident = next
	c.cert = &cert
	c.mu.Unlock()
	return nil
}
