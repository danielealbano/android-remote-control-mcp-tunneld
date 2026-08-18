package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// submitRenewal answers a RENEW_CHALLENGE by generating fresh identity + public keys and CSRs and a
// throwaway attestation (accepted in --attestation-optional mode), retaining the fresh keys to pair with
// the certs the server will push. The server already holds the challenge nonce, so the submission need
// not echo it.
func (c *Client) submitRenewal(payload []byte) {
	var ch wire.RenewChallengePayload
	if err := json.Unmarshal(payload, &ch); err != nil {
		return
	}
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	pubKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	idCSR, err := csrPEM(idKey)
	if err != nil {
		return
	}
	tlsCSR, err := csrPEM(pubKey)
	if err != nil {
		return
	}
	attest, err := dummyAttestationPEM(idKey)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.pendingID = idKey
	c.pendingTL = pubKey
	c.mu.Unlock()
	c.sendControl(wire.CtrlRenewSubmit, wire.RenewSubmitPayload{
		AttestationChainPEM: string(attest), IdentityCSR: string(idCSR), TLSCSR: string(tlsCSR),
	})
}

// installCerts swaps in the certs the server pushed (initial issuance echo or renewal), pairing them with
// the pending renewal keys when present. Subsequent connections present the new identity cert.
func (c *Client) installCerts(payload []byte) {
	var cp wire.CertPushPayload
	if err := json.Unmarshal(payload, &cp); err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ident == nil {
		return
	}
	next := &Identity{
		Name:            c.ident.Name,
		IdentityCertPEM: []byte(cp.IdentityCertPEM),
		PublicCertPEM:   []byte(cp.PublicCertPEM),
		CA:              c.ident.CA,
		IdentityKey:     c.ident.IdentityKey,
		PublicKey:       c.ident.PublicKey,
	}
	if c.pendingID != nil {
		next.IdentityKey = c.pendingID
	}
	if c.pendingTL != nil {
		next.PublicKey = c.pendingTL
	}
	c.pendingID, c.pendingTL = nil, nil
	c.ident = next
	if cert, err := next.tlsCertificate(); err == nil {
		c.cert = &cert
	}
}
