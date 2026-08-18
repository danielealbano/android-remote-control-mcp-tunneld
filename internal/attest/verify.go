package attest

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

// Distinct typed failures — each maps to a rejection label + a user-facing reason.
var (
	ErrChainUntrusted    = errors.New("attest: chain does not root at a Google attestation root")
	ErrChallengeMismatch = errors.New("attest: attestation challenge != server nonce")
	ErrSignerNotAllowed  = errors.New("attest: app signing digest not in the allowlist")
	ErrSecurityLevel     = errors.New("attest: security level below TrustedEnvironment")
	ErrBootState         = errors.New("attest: verifiedBootState != Verified")
	ErrDeviceUnlocked    = errors.New("attest: device is not locked")
	ErrRevoked           = errors.New("attest: attestation key is revoked")
	ErrStatusStale       = errors.New("attest: revocation status list is too stale")
	ErrEmptyChain        = errors.New("attest: empty chain")
)

// Result is returned on a passing verification.
type Result struct {
	Package       string
	Device        store.DeviceInfo
	LeafPublicKey crypto.PublicKey // the attested TEE key — the enroll service binds the identity CSR to it
}

// Verifier enforces the seven-point predicate against the current root pool, revocation status, and
// signer allowlist. It performs NO I/O in Verify (it reads only in-memory atomic snapshots), so Verify
// takes no ctx; the verification time is injectable via the `now` argument (frozen in tests).
type Verifier struct {
	roots    *RootSet
	status   *StatusList
	signers  *SignerAllowlist
	maxStale time.Duration
}

// NewVerifier wires the verifier.
func NewVerifier(roots *RootSet, status *StatusList, signers *SignerAllowlist, maxStale time.Duration) *Verifier {
	return &Verifier{roots: roots, status: status, signers: signers, maxStale: maxStale}
}

// Verify enforces ALL seven predicate points, in order. chain[0] is the leaf; chain[1:] are the
// intermediates (the root is matched from the pool). now is the injectable verification clock.
func (v *Verifier) Verify(chain []*x509.Certificate, nonce []byte, now time.Time) (Result, error) {
	if len(chain) == 0 {
		return Result{}, ErrEmptyChain
	}
	leaf := chain[0]

	// A well-formed attestation chain is a strict path with no repeated certificates; a duplicated
	// cert is malformed and rejected (defends the parse/verify surface).
	seen := make(map[string]struct{}, len(chain))
	for _, c := range chain {
		k := string(c.Raw)
		if _, dup := seen[k]; dup {
			return Result{}, ErrChainUntrusted
		}
		seen[k] = struct{}{}
	}

	// (1) Chain roots at a Google attestation root, valid at `now`.
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots.Pool(),
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return Result{}, ErrChainUntrusted
	}

	kd, err := ParseKeyDescription(leaf)
	if err != nil {
		return Result{}, ErrChainUntrusted
	}

	// (2) Challenge equals the server-issued nonce.
	if !bytesEqualConst(kd.Challenge, nonce) {
		return Result{}, ErrChallengeMismatch
	}

	// (3) A signature digest is in the allowlist.
	if !v.signerAllowed(kd.SignatureDigests) {
		return Result{}, ErrSignerNotAllowed
	}

	// (4) securityLevel ≥ TrustedEnvironment (Software rejected; StrongBox NOT required).
	if kd.SecurityLevel < SecurityTrustedEnvironment {
		return Result{}, ErrSecurityLevel
	}

	// (5) verifiedBootState == Verified.
	if kd.VerifiedBootState != BootVerified {
		return Result{}, ErrBootState
	}

	// (6) deviceLocked == true.
	if !kd.DeviceLocked {
		return Result{}, ErrDeviceUnlocked
	}

	// (7) Not revoked AND the status list is not too stale.
	if v.status.FetchedAt().IsZero() || now.Sub(v.status.FetchedAt()) > v.maxStale {
		return Result{}, ErrStatusStale
	}
	for _, c := range chain {
		if v.status.Revoked(c.SerialNumber.Text(16)) {
			return Result{}, ErrRevoked
		}
	}

	return Result{
		Package:       kd.Package,
		LeafPublicKey: leaf.PublicKey,
		Device: store.DeviceInfo{
			OSVersion:          kd.OSVersion,
			OSPatch:            kd.OSPatch,
			VendorPatch:        kd.VendorPatch,
			BootPatch:          kd.BootPatch,
			AttestationVersion: kd.AttestationVersion,
			KeymintVersion:     kd.KeymasterVersion,
			SecurityLevel:      securityLevelString(kd.SecurityLevel),
		},
	}, nil
}

func (v *Verifier) signerAllowed(digests [][]byte) bool {
	for _, d := range digests {
		if v.signers.Allowed(hex.EncodeToString(d)) {
			return true
		}
	}
	return false
}

func securityLevelString(level int) string {
	switch level {
	case SecurityStrongBox:
		return "strongbox"
	case SecurityTrustedEnvironment:
		return "tee"
	default:
		return "software"
	}
}

// bytesEqualConst is a constant-time compare (both empty → false: a real challenge is never empty).
func bytesEqualConst(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
