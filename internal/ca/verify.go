package ca

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// KeyFingerprint returns "sha256:" + hex(sha256(PKIX SPKI)) — the stable per-KEY identifier shared by
// the name registry and the phone connection-log events (a rotated cert keeps its key fingerprint as
// long as the key is unchanged, so the two durable artifacts correlate).
func KeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("ca: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
