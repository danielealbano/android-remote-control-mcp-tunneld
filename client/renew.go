package client

import (
	"context"
	"encoding/json"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// renew answers a RENEW_NUDGE by calling the mTLS POST /issue endpoint over the live control client to
// regenerate the identity + public certs (a fresh attestation over the nudge nonce + rotated CSRs), then
// atomically swaps in the new identity so subsequent reconnects and dial-back data streams present the
// rotated certs. On any failure the connection stays on the current certs.
func (c *Client) renew(ctx context.Context, payload []byte) {
	var nudge wire.RenewNudgePayload
	if err := json.Unmarshal(payload, &nudge); err != nil || nudge.Nonce == "" {
		return
	}
	c.mu.Lock()
	name := c.ident.Name
	caID := c.ident.CA
	c.mu.Unlock()

	next, err := issueCerts(ctx, c.hc, c.controlHost, name, c.tunnelDomain, caID, nudge.Nonce)
	if err != nil {
		return
	}
	cert, err := next.tlsCertificate()
	if err != nil {
		return
	}
	c.mu.Lock()
	c.ident = next
	c.cert = &cert
	c.mu.Unlock()
}
