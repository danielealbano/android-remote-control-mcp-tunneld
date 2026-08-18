package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// chainParams tunes a synthetic attestation chain so the full seven-point predicate can be exercised
// positively and (one field at a time) negatively — WITHOUT depending on Google's short-lived
// intermediates. A REAL Realme T70 chain fixture, when captured on-device, is validated separately by
// the adb-gated e2e test (US14); the predicate LOGIC is covered here in full.
type chainParams struct {
	challenge     []byte
	signerDigest  []byte // the SHA-256 the allowlist will contain (unless overridden)
	packageName   string
	securityLevel int
	bootState     int
	deviceLocked  bool
	notBefore     time.Time
	notAfter      time.Time
	// mutators for negative cases:
	tamperExtension  bool
	breakSignature   bool
	duplicateLeaf    bool
	leafOnly         bool
	dropIntermediate bool
}

func defaultParams() chainParams {
	return chainParams{
		challenge:     []byte("server-nonce-123"),
		signerDigest:  sha256sum([]byte("release-signing-cert")),
		packageName:   "dev.example.app",
		securityLevel: SecurityTrustedEnvironment,
		bootState:     BootVerified,
		deviceLocked:  true,
		notBefore:     time.Unix(1_700_000_000, 0),
		notAfter:      time.Unix(1_700_000_000, 0).Add(14 * 24 * time.Hour),
	}
}

func sha256sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// fakeCA builds a self-signed root plus an intermediate; buildChain signs a leaf carrying the
// KeyDescription extension. leafKey is the attested EC key surfaced as Result.LeafPublicKey.
type fakeCA struct {
	rootCert  *x509.Certificate
	rootKey   *ecdsa.PrivateKey
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Attestation Root"},
		NotBefore:             time.Unix(1_600_000_000, 0),
		NotAfter:              time.Unix(2_000_000_000, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Fake Attestation Intermediate"},
		NotBefore:             time.Unix(1_600_000_000, 0),
		NotAfter:              time.Unix(2_000_000_000, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interDER)

	return &fakeCA{rootCert: rootCert, rootKey: rootKey, interCert: interCert, interKey: interKey}
}

// rootPool returns a pool trusting this CA's root.
func (ca *fakeCA) rootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.rootCert)
	return p
}

// buildChain returns [leaf, intermediate] and the attested leaf key.
func (ca *fakeCA) buildChain(t *testing.T, p chainParams) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ext := keyDescriptionExtension(t, p)
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1234),
		Subject:         pkix.Name{CommonName: "attested key"},
		NotBefore:       p.notBefore,
		NotAfter:        p.notAfter,
		ExtraExtensions: []pkix.Extension{ext},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca.interCert, &leafKey.PublicKey, ca.interKey)
	if err != nil {
		t.Fatal(err)
	}
	if p.breakSignature {
		leafDER[len(leafDER)-1] ^= 0xFF // corrupt the trailing signature bytes
	}
	if p.tamperExtension {
		// Flip a byte INSIDE the (signed, but x509-opaque) KeyDescription extension value — located via
		// the embedded challenge so the cert still parses, but the leaf signature no longer validates:
		// the chain is untrusted, modelling an attacker editing a signed KeyDescription field.
		if i := bytes.Index(leafDER, p.challenge); i >= 0 {
			leafDER[i] ^= 0xFF
		} else {
			t.Fatal("could not locate the KeyDescription challenge to tamper")
		}
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		// A broken-signature DER may still parse (the signature is verified at chain-verify time); if it
		// does not parse, surface an already-untrusted leaf via a minimal re-parse of the intermediate.
		if p.breakSignature {
			return []*x509.Certificate{ca.interCert, ca.interCert}, leafKey
		}
		t.Fatal(err)
	}
	switch {
	case p.leafOnly:
		return []*x509.Certificate{leaf}, leafKey
	case p.dropIntermediate:
		return []*x509.Certificate{leaf}, leafKey
	case p.duplicateLeaf:
		return []*x509.Certificate{leaf, leaf, ca.interCert}, leafKey
	default:
		return []*x509.Certificate{leaf, ca.interCert}, leafKey
	}
}

// --- KeyDescription DER assembly (test-only) ---

func keyDescriptionExtension(t *testing.T, p chainParams) pkix.Extension {
	t.Helper()
	// attestationApplicationId → OCTET STRING wrapper → context [709].
	aaid := attestationApplicationID{
		PackageInfos:     []attestationPackageInfo{{PackageName: []byte(p.packageName), Version: 1}},
		SignatureDigests: []asn1.RawValue{{FullBytes: mustMarshal(t, p.signerDigest)}},
	}
	aaidDER := mustMarshal(t, aaid)
	octetWrapped := mustMarshal(t, aaidDER) // OCTET STRING containing aaidDER
	field709 := ctxTag(t, 709, octetWrapped)

	software := sequence(t, field709)

	rot := rootOfTrust{
		VerifiedBootKey:   []byte{1, 2, 3, 4},
		DeviceLocked:      p.deviceLocked,
		VerifiedBootState: asn1.Enumerated(p.bootState),
		VerifiedBootHash:  []byte{5, 6, 7, 8},
	}
	field704 := ctxTag(t, 704, mustMarshal(t, rot))
	field705 := ctxTag(t, 705, mustMarshal(t, 160000))
	field706 := ctxTag(t, 706, mustMarshal(t, 202607))
	field718 := ctxTag(t, 718, mustMarshal(t, 202607))
	field719 := ctxTag(t, 719, mustMarshal(t, 202607))
	tee := sequence(t, field705, field706, field704, field718, field719)

	kd := keyDescription{
		AttestationVersion:       200,
		AttestationSecurityLevel: asn1.Enumerated(p.securityLevel),
		KeymasterVersion:         200,
		KeymasterSecurityLevel:   asn1.Enumerated(p.securityLevel),
		AttestationChallenge:     p.challenge,
		UniqueID:                 []byte{},
		SoftwareEnforced:         asn1.RawValue{FullBytes: software},
		TeeEnforced:              asn1.RawValue{FullBytes: tee},
	}
	kdDER := mustMarshal(t, kd)
	return pkix.Extension{Id: attestOID, Value: kdDER}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1 marshal: %v", err)
	}
	return b
}

// ctxTag wraps innerDER in an EXPLICIT context-specific [tag] (compound).
func ctxTag(t *testing.T, tag int, innerDER []byte) []byte {
	t.Helper()
	return mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: innerDER,
	})
}

// sequence concatenates the pre-marshaled elements and wraps them in a SEQUENCE.
func sequence(t *testing.T, elems ...[]byte) []byte {
	t.Helper()
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}
