package client

import (
	"context"
	"encoding/json"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// renew answers a RENEW_NUDGE by delegating to Renew with the nudge's challenge nonce (best-effort; the
// connection stays on the current certs on failure).
func (c *Client) renew(ctx context.Context, payload []byte) {
	var nudge wire.RenewNudgePayload
	if err := json.Unmarshal(payload, &nudge); err != nil || nudge.Nonce == "" {
		return
	}
	_ = c.Renew(ctx, nudge.Nonce)
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

	next, err := issueCerts(ctx, c.hc, c.controlHost, name, c.tunnelDomain, caID, nonceHex)
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
