package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// RejectedEnrollment is the forensic evidence persisted for a REJECTED/suspicious enrollment (30-day
// lifecycle). It is the ONLY place a submitted attestation chain is retained, and only for rejections
// — accepted enrollments never store a chain (privacy). Best-effort: a store error is logged, never
// masks the rejection.
type RejectedEnrollment struct {
	TS              time.Time `json:"ts"`
	SrcIP           string    `json:"src_ip"`
	Reason          string    `json:"reason"`
	AttestChainPEM  string    `json:"attest_chain_pem"`
	ClaimedPackage  string    `json:"claimed_package,omitempty"`
	SignerDigestHex string    `json:"signer_digest_hex,omitempty"`
	NonceHex        string    `json:"nonce_hex,omitempty"`
}

// RejectedKey is the S3 key: rejected-enroll/<yyyy>/<mm>/<dd>/<tsNanos>-<rand4>.json.
func RejectedKey(ev RejectedEnrollment) string {
	ts := ev.TS.UTC()
	var r [2]byte
	// crypto/rand.Read never returns a short read; on the impossible error a zero suffix is harmless
	// (the timestamp already disambiguates) and this helper stays error-free for call sites.
	_, _ = rand.Read(r[:])
	return fmt.Sprintf("rejected-enroll/%04d/%02d/%02d/%s-%s.json",
		ts.Year(), ts.Month(), ts.Day(), ts.Format(tsNanosLayout), hex.EncodeToString(r[:]))
}
