package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// Fingerprint returns "sha256:" + hex(sha256(cert.Raw)) — the stable per-cert identifier used for
// ban/route bookkeeping.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
