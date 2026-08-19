// Package attest implements the Android hardware key-attestation verifier: the KeyDescription ASN.1
// parser, the seven-point predicate, background root-set + revocation-status refreshers (last-known-
// good), and a hot-reloadable signer-digest allowlist. Enrollment and every renewal require a valid
// attestation; this package makes generic hosting/abuse structurally impossible rather than merely
// policy-forbidden. See docs/PROTOCOL.md §2.
package attest

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// attestOID is the Android Key Attestation extension OID (KeyDescription).
var attestOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// SecurityLevel enum (KeyDescription attestationSecurityLevel / keymintSecurityLevel).
const (
	SecuritySoftware           = 0
	SecurityTrustedEnvironment = 1
	SecurityStrongBox          = 2
)

// VerifiedBootState enum (rootOfTrust.verifiedBootState).
const (
	BootVerified   = 0
	BootSelfSigned = 1
	BootUnverified = 2
	BootFailed     = 3
)

// Context tag numbers inside an authorization list.
const (
	tagOSVersion        = 705
	tagPatchLevel       = 706
	tagAttestationAppID = 709
	tagRootOfTrust      = 704
	tagVendorPatch      = 718
	tagBootPatch        = 719
)

// keyDescription is the top-level KeyDescription SEQUENCE.
type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

type attestationPackageInfo struct {
	PackageName []byte
	Version     int64
}

type attestationApplicationID struct {
	PackageInfos     []attestationPackageInfo `asn1:"set"`
	SignatureDigests []asn1.RawValue          `asn1:"set"`
}

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

// KeyDescription is the decoded, semantically-meaningful subset the verifier needs.
type KeyDescription struct {
	AttestationVersion int
	KeymasterVersion   int
	SecurityLevel      int // attestationSecurityLevel
	Challenge          []byte
	Package            string
	SignatureDigests   [][]byte
	DeviceLocked       bool
	VerifiedBootState  int
	HasRootOfTrust     bool // rootOfTrust was present in the TEE-enforced authorization list
	OSVersion          int
	OSPatch            int
	VendorPatch        int
	BootPatch          int
}

// ParseKeyDescription locates the attestation extension on the leaf and decodes the fields the
// seven-point predicate needs. attestationApplicationId and the OS/patch levels are read from whichever
// list carries them, but rootOfTrust is read ONLY from the TEE-enforced list (a copy in softwareEnforced
// is platform-supplied and ignored); its ABSENCE from teeEnforced is a hard failure at Verify (see
// verify.go point 5) — the zero-value boot state would otherwise read as Verified+unlocked.
func ParseKeyDescription(leaf *x509.Certificate) (*KeyDescription, error) {
	var raw []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(attestOID) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("attest: no KeyDescription extension on the leaf")
	}
	var kd keyDescription
	if _, err := asn1.Unmarshal(raw, &kd); err != nil {
		return nil, fmt.Errorf("attest: decode KeyDescription: %w", err)
	}
	out := &KeyDescription{
		AttestationVersion: kd.AttestationVersion,
		KeymasterVersion:   kd.KeymasterVersion,
		SecurityLevel:      int(kd.AttestationSecurityLevel),
		Challenge:          kd.AttestationChallenge,
	}
	if err := walkAuthList(kd.SoftwareEnforced.Bytes, out, false); err != nil {
		return nil, fmt.Errorf("attest: softwareEnforced: %w", err)
	}
	if err := walkAuthList(kd.TeeEnforced.Bytes, out, true); err != nil {
		return nil, fmt.Errorf("attest: teeEnforced: %w", err)
	}
	return out, nil
}

// walkAuthList decodes the context-tagged entries of an authorization list into out. tee reports whether
// this is the TEE-enforced list: rootOfTrust is honored ONLY from it.
func walkAuthList(raw []byte, out *KeyDescription, tee bool) error {
	rest := raw
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rv)
		if err != nil {
			return err
		}
		switch rv.Tag {
		case tagRootOfTrust:
			if !tee {
				continue // rootOfTrust is only trustworthy from the TEE-enforced list
			}
			var rot rootOfTrust
			if _, err := asn1.Unmarshal(rv.Bytes, &rot); err != nil {
				return fmt.Errorf("rootOfTrust: %w", err)
			}
			out.HasRootOfTrust = true
			out.DeviceLocked = rot.DeviceLocked
			out.VerifiedBootState = int(rot.VerifiedBootState)
		case tagAttestationAppID:
			// The value is an OCTET STRING wrapping the AttestationApplicationId DER.
			var inner asn1.RawValue
			if _, err := asn1.Unmarshal(rv.Bytes, &inner); err != nil {
				return fmt.Errorf("attestationApplicationId unwrap: %w", err)
			}
			var aaid attestationApplicationID
			if _, err := asn1.Unmarshal(inner.Bytes, &aaid); err != nil {
				return fmt.Errorf("attestationApplicationId: %w", err)
			}
			if len(aaid.PackageInfos) > 0 {
				out.Package = string(aaid.PackageInfos[0].PackageName)
			}
			for _, d := range aaid.SignatureDigests {
				out.SignatureDigests = append(out.SignatureDigests, d.Bytes)
			}
		case tagOSVersion:
			out.OSVersion = decodeInt(rv.Bytes)
		case tagPatchLevel:
			out.OSPatch = decodeInt(rv.Bytes)
		case tagVendorPatch:
			out.VendorPatch = decodeInt(rv.Bytes)
		case tagBootPatch:
			out.BootPatch = decodeInt(rv.Bytes)
		}
	}
	return nil
}

// decodeInt decodes a context-tagged INTEGER's contents (best-effort; 0 on failure).
func decodeInt(b []byte) int {
	var v int
	if _, err := asn1.Unmarshal(b, &v); err != nil {
		return 0
	}
	return v
}
