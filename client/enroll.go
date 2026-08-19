// Package client is the Go HTTP/2 tunnel client: the reference (non-attesting) phone implementation used
// by the integration/e2e tiers. It speaks wire v2 over HTTP/2 — the identity-mTLS control connection,
// dial-back data streams (full-duplex opaque splice), PING/PONG liveness, and the RENEW_NUDGE → mTLS
// POST /issue renewal — plus a two-phase attestation-optional enrollment path (Phase 1 /enroll → Phase 2
// /issue) so tests enroll without a real device.
package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"
)

// Identity is an enrolled tunnel identity: the server-assigned name plus the identity (control-plane
// mTLS) cert/key and the public (edge TLS) cert.
type Identity struct {
	Name            string
	IdentityCertPEM []byte
	IdentityKey     *ecdsa.PrivateKey
	PublicCertPEM   []byte
	PublicCertKey   *ecdsa.PrivateKey // the TLS private key behind PublicCertPEM (never leaves the phone)
	CA              string
}

// tlsCertificate builds the mTLS client certificate from the identity cert + key.
func (id *Identity) tlsCertificate() (tls.Certificate, error) {
	keyDER, err := x509.MarshalECPrivateKey(id.IdentityKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(id.IdentityCertPEM, keyPEM)
}

type nonceResponse struct {
	Nonce string `json:"nonce"`
}

// enrollRequestBody is the Phase-1 POST /enroll body (identity only — no TLS CSR).
type enrollRequestBody struct {
	Nonce          string `json:"nonce"`
	AttestChainPEM string `json:"attestation_chain"`
	IdentityCSR    string `json:"identity_csr"`
}

// enrollResponse is the Phase-1 reply: name + bootstrap identity cert + the follow-up issue nonce.
type enrollResponse struct {
	Name         string `json:"name"`
	IdentityCert string `json:"identity_cert"`
	IssueNonce   string `json:"issue_nonce"`
}

// issueRequestBody is the Phase-2 (and renewal) POST /issue body (mTLS).
type issueRequestBody struct {
	Nonce          string `json:"nonce"`
	AttestChainPEM string `json:"attestation_chain"`
	IdentityCSR    string `json:"identity_csr"`
	TLSCSR         string `json:"tls_csr"`
}

// issueResponseBody is the POST /issue reply: the regenerated identity + public certs.
type issueResponseBody struct {
	IdentityCert string `json:"identity_cert"`
	PublicCert   string `json:"public_cert"`
	CA           string `json:"ca"`
}

type errorResponse struct {
	Reason     string `json:"reason"`
	Retryable  bool   `json:"retryable"`
	RetryAfter int64  `json:"retry_after_seconds,omitempty"`
}

// EnrollError is a structured enrollment failure returned by the server.
type EnrollError struct {
	Status     int
	Reason     string
	Retryable  bool
	RetryAfter time.Duration
}

func (e *EnrollError) Error() string {
	return fmt.Sprintf("enroll: %s (status %d)", e.Reason, e.Status)
}

// Enroll performs the two-phase attestation-optional enrollment: Phase 1 (server-TLS POST /enroll on
// enrollHost) attests the identity key and returns the assigned name + bootstrap identity cert + a
// follow-up issue nonce; Phase 2 (mTLS POST /issue on controlHost) regenerates the identity cert and
// obtains the public WebPKI cert for <name>.<tunnelDomain> together. It uses a throwaway self-signed
// "attestation" chain (accepted because the server runs --attestation-optional). dialAddr is the shared
// raw :443 edge (SNI routes enrollHost/controlHost to their listeners).
func Enroll(ctx context.Context, dialAddr, enrollHost, controlHost, tunnelDomain string, caPool *x509.CertPool) (*Identity, error) {
	// --- Phase 1: identity enrollment (server-TLS) ---
	tr := serverTLSTransport(dialAddr, enrollHost, caPool)
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr}
	nonce, err := fetchNonce(ctx, hc, enrollHost)
	if err != nil {
		return nil, err
	}
	bootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	idCSR, err := csrPEM(bootKey)
	if err != nil {
		return nil, err
	}
	attest, err := dummyAttestationPEM(bootKey)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(enrollRequestBody{Nonce: nonce, AttestChainPEM: string(attest), IdentityCSR: string(idCSR)}) // string-only fields cannot fail
	resp, err := post(ctx, hc, "https://"+enrollHost+"/enroll", body)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("enroll: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var er errorResponse
		_ = json.Unmarshal(raw, &er)
		return nil, &EnrollError{Status: resp.StatusCode, Reason: er.Reason, Retryable: er.Retryable,
			RetryAfter: time.Duration(er.RetryAfter) * time.Second}
	}
	var er enrollResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return nil, fmt.Errorf("enroll: decode response: %w", err)
	}

	// --- Phase 2: cert generation (mTLS POST /issue) ---
	bootIdent := &Identity{Name: er.Name, IdentityCertPEM: []byte(er.IdentityCert), IdentityKey: bootKey}
	bootCert, err := bootIdent.tlsCertificate()
	if err != nil {
		return nil, err
	}
	mtlsTr := newMTLSTransport(dialAddr, controlHost, caPool, func() *tls.Certificate { return &bootCert })
	defer mtlsTr.CloseIdleConnections()
	mtls := &http.Client{Transport: mtlsTr}
	id, err := issueCerts(ctx, mtls, controlHost, er.Name, tunnelDomain, "", er.IssueNonce)
	if err != nil {
		// Preserve the Phase-1 bootstrap identity (name + identity cert + key, no public cert yet) so the
		// caller can execute the documented retry path (fresh nonce → Renew over the SAME mTLS identity)
		// WITHOUT re-enrolling — re-enrolling would orphan this name in the registry (PROTOCOL §2: the name
		// is never rolled back). See docs/PROTOCOL.md §3.
		return bootIdent, err
	}
	return id, nil
}

// issueCerts performs the mTLS POST /issue exchange over hc: it generates a FRESH identity + TLS keypair,
// builds the CSRs (TLS SAN = <name>.<tunnelDomain>) and a throwaway attestation over nonceHex, and
// returns a new Identity carrying the regenerated identity + public certs and their fresh keys. It backs
// both Phase 2 of enrollment and every renewal. caFallback is used when the server omits the CA field.
func issueCerts(ctx context.Context, hc *http.Client, controlHost, name, tunnelDomain, caFallback, nonceHex string) (*Identity, error) {
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	idCSR, err := csrPEM(idKey)
	if err != nil {
		return nil, err
	}
	tlsCSR, err := tlsCSRForTunnel(tlsKey, name, tunnelDomain)
	if err != nil {
		return nil, err
	}
	attest, err := dummyAttestationPEM(idKey)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(issueRequestBody{ // string-only fields cannot fail
		Nonce: nonceHex, AttestChainPEM: string(attest), IdentityCSR: string(idCSR), TLSCSR: string(tlsCSR),
	})
	resp, err := post(ctx, hc, "https://"+controlHost+"/issue", body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("issue: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var er errorResponse
		_ = json.Unmarshal(raw, &er)
		return nil, &EnrollError{Status: resp.StatusCode, Reason: er.Reason, Retryable: er.Retryable,
			RetryAfter: time.Duration(er.RetryAfter) * time.Second}
	}
	var ir issueResponseBody
	if err := json.Unmarshal(raw, &ir); err != nil {
		return nil, fmt.Errorf("issue: decode response: %w", err)
	}
	caID := ir.CA
	if caID == "" {
		caID = caFallback
	}
	return &Identity{
		Name: name, IdentityCertPEM: []byte(ir.IdentityCert), IdentityKey: idKey,
		PublicCertPEM: []byte(ir.PublicCert), PublicCertKey: tlsKey, CA: caID,
	}, nil
}

// tlsCSRForTunnel builds a PKCS#10 CSR for the public cert requesting exactly <name>.<tunnelDomain>
// (CN + SAN), signed by key.
func tlsCSRForTunnel(key *ecdsa.PrivateKey, name, tunnelDomain string) ([]byte, error) {
	fqdn := name + "." + tunnelDomain
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{fqdn},
	}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func fetchNonce(ctx context.Context, hc *http.Client, enrollHost string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+enrollHost+"/enroll/nonce", nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", fmt.Errorf("enroll: read nonce response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("enroll: nonce status %d", resp.StatusCode)
	}
	var nr nonceResponse
	if err := json.Unmarshal(raw, &nr); err != nil {
		return "", err
	}
	return nr.Nonce, nil
}

func post(ctx context.Context, hc *http.Client, url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return hc.Do(req)
}

// csrPEM builds a PKCS#10 CSR PEM signed by key (the server ignores the subject and assigns the name).
func csrPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "phone"},
	}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// dummyAttestationPEM builds a throwaway self-signed cert to stand in for the Android attestation chain
// in --attestation-optional mode (the server does not verify it in that mode).
func dummyAttestationPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "attestation-optional"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// serverTLSTransport dials dialAddr but negotiates TLS with ServerName=host (so SNI routing at the edge
// works while the test dials a loopback port). Server-TLS only (enrollment precedes any identity).
func serverTLSTransport(dialAddr, host string, caPool *x509.CertPool) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{ServerName: host, RootCAs: caPool, MinVersion: tls.VersionTLS12}}
			return d.DialContext(ctx, network, dialAddr)
		},
	}
}

// FetchIssueNonce mints a fresh single-use challenge nonce from GET /enroll/nonce (per-IP
// rate-limited). The enroll and issue nonces share one namespace, so this is the documented retry
// path after a RETRYABLE POST /issue failure (which consumed the previous nonce): fetch a fresh
// nonce, wait retry_after_seconds, then call Client.Renew with it. See docs/PROTOCOL.md §3.
func FetchIssueNonce(ctx context.Context, dialAddr, enrollHost string, caPool *x509.CertPool) (string, error) {
	tr := serverTLSTransport(dialAddr, enrollHost, caPool)
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr}
	return fetchNonce(ctx, hc, enrollHost)
}
