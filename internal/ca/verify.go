package ca

import (
	"crypto"
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

// KeyFingerprint returns "sha256:" + hex(sha256(PKIX SPKI)) — the stable per-KEY identifier shared by
// the name registry and the phone connection-log events (a rotated cert keeps its key fingerprint as
// long as the key is unchanged, so the two durable artifacts correlate). Returns "" for an
// unmarshalable key.
func KeyFingerprint(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}
