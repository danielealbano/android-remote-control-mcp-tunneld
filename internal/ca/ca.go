// Package ca implements the internal tunnel CA: loading the signing material and issuing the phone's
// identity + mesh-role certificates (see e2e.go), plus the stable cert fingerprint (verify.go). Pure
// crypto; no HTTP.
package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrUnsupportedKeyType is returned by SignIdentity for a CSR whose public key is not ECDSA P-256. The
// enroll handler maps this to 400 unsupported_key_type (docs/PROTOCOL.md §1).
var ErrUnsupportedKeyType = errors.New("ca: unsupported CSR key type (only ECDSA P-256 accepted)")

// CA holds the loaded signing material.
type CA struct {
	cert     *x509.Certificate
	key      crypto.Signer
	validity time.Duration
}

// Load reads the CA certificate + private key (PEM), verifies the certificate is a CA, and returns
// an in-memory signer. Bad/unreadable/non-CA material fails fast.
func Load(certPath, keyPath string, validity time.Duration) (*CA, error) {
	certPEM, err := os.ReadFile(certPath) // #nosec G304 -- operator-configured --ca-cert path (deployment trust boundary, not request-derived)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- operator-configured --ca-key path (deployment trust boundary, not request-derived)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, errors.New("ca: certificate is not a CA (basicConstraints CA:TRUE required)")
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	if !publicKeyMatches(cert.PublicKey, key.Public()) {
		return nil, errors.New("ca: private key does not match certificate public key")
	}
	return &CA{cert: cert, key: key, validity: validity}, nil
}

// Pool returns a CA-only pool for verifying enrolled certificates.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}


func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block in key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca key is not a crypto.Signer")
	}
	return signer, nil
}

func publicKeyMatches(a, b any) bool {
	type equalable interface{ Equal(x crypto.PublicKey) bool }
	ea, ok := a.(equalable)
	if !ok {
		return false
	}
	return ea.Equal(b.(crypto.PublicKey))
}
