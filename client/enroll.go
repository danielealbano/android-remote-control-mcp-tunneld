// Package client is the Go HTTP/2 tunnel client: the reference (non-attesting) phone implementation used
// by the integration/e2e tiers. It speaks wire v2 over HTTP/2 — the identity-mTLS control connection,
// dial-back data streams (full-duplex opaque splice), PING/PONG liveness, CERT_PUSH, and the
// RENEW_NUDGE → RENEW_REQUEST → RENEW_CHALLENGE → RENEW_SUBMIT → CERT_PUSH renewal exchange — plus an
// attestation-optional enrollment path so tests enroll without a real device.
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
	PublicKey       *ecdsa.PrivateKey
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

type enrollRequestBody struct {
	Nonce          string `json:"nonce"`
	AttestChainPEM string `json:"attestation_chain"`
	IdentityCSR    string `json:"identity_csr"`
	TLSCSR         string `json:"tls_csr"`
}

type enrollResponse struct {
	Name         string `json:"name"`
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

func (e *EnrollError) Error() string { return fmt.Sprintf("enroll: %s (status %d)", e.Reason, e.Status) }

// Enroll performs attestation-optional enrollment against the enroll host reachable at dialAddr with
// SNI/Host enrollHost, trusting caPool. It generates the identity + public keys and CSRs and a throwaway
// self-signed "attestation" chain (accepted because the server also runs --attestation-optional).
func Enroll(ctx context.Context, dialAddr, enrollHost string, caPool *x509.CertPool) (*Identity, error) {
	hc := &http.Client{Transport: serverTLSTransport(dialAddr, enrollHost, caPool)}

	nonce, err := fetchNonce(ctx, hc, enrollHost)
	if err != nil {
		return nil, err
	}

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pubKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	idCSR, err := csrPEM(idKey)
	if err != nil {
		return nil, err
	}
	tlsCSR, err := csrPEM(pubKey)
	if err != nil {
		return nil, err
	}
	attest, err := dummyAttestationPEM(idKey)
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(enrollRequestBody{
		Nonce: nonce, AttestChainPEM: string(attest), IdentityCSR: string(idCSR), TLSCSR: string(tlsCSR),
	})
	resp, err := post(ctx, hc, "https://"+enrollHost+"/enroll", body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
	return &Identity{
		Name: er.Name, IdentityCertPEM: []byte(er.IdentityCert), IdentityKey: idKey,
		PublicCertPEM: []byte(er.PublicCert), PublicKey: pubKey, CA: er.CA,
	}, nil
}

func fetchNonce(ctx context.Context, hc *http.Client, enrollHost string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+enrollHost+"/enroll/nonce", nil)
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
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
