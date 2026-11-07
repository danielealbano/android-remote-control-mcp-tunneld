package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/attest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

var attestOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

type chainSpec struct {
	app           string
	version       int64
	digest        []byte
	securityLevel int
	bootState     int
	locked        bool
	rootInTEE     bool
	leafSerial    int64
}

func goodChain() chainSpec {
	return chainSpec{
		app:           "dev.example.copy",
		version:       20011770,
		digest:        []byte("0123456789abcdef0123456789abcdef"),
		securityLevel: attest.SecurityTrustedEnvironment,
		bootState:     attest.BootVerified,
		locked:        true,
		rootInTEE:     true,
		leafSerial:    0x1234,
	}
}

type packageInfo struct {
	PackageName []byte
	Version     int64
}

type applicationID struct {
	PackageInfos     []packageInfo   `asn1:"set"`
	SignatureDigests []asn1.RawValue `asn1:"set"`
}

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte
}

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

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1 marshal: %v", err)
	}
	return b
}

func tagged(t *testing.T, tag int, inner []byte) []byte {
	t.Helper()
	return marshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
}

func sequenceOf(t *testing.T, elems ...[]byte) []byte {
	t.Helper()
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	return marshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

func chainPEM(t *testing.T, s chainSpec) string {
	t.Helper()
	aaid := marshal(t, applicationID{
		PackageInfos:     []packageInfo{{PackageName: []byte(s.app), Version: s.version}},
		SignatureDigests: []asn1.RawValue{{FullBytes: marshal(t, s.digest)}},
	})
	appField := tagged(t, 709, marshal(t, aaid))
	rotField := tagged(t, 704, marshal(t, rootOfTrust{
		VerifiedBootKey: []byte{1}, DeviceLocked: s.locked, VerifiedBootState: asn1.Enumerated(s.bootState), VerifiedBootHash: []byte{2},
	}))
	software := [][]byte{appField}
	var tee [][]byte
	if s.rootInTEE {
		tee = append(tee, rotField)
	} else {
		software = append(software, rotField)
	}
	kd := marshal(t, keyDescription{
		AttestationVersion:       200,
		AttestationSecurityLevel: asn1.Enumerated(s.securityLevel),
		KeymasterVersion:         200,
		KeymasterSecurityLevel:   asn1.Enumerated(s.securityLevel),
		AttestationChallenge:     []byte("nonce"),
		UniqueID:                 []byte{},
		SoftwareEnforced:         asn1.RawValue{FullBytes: sequenceOf(t, software...)},
		TeeEnforced:              asn1.RawValue{FullBytes: sequenceOf(t, tee...)},
	})
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test attestation intermediate"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(s.leafSerial), Subject: pkix.Name{CommonName: "attested key"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0),
		ExtraExtensions: []pkix.Extension{{Id: attestOID, Value: kd}},
	}, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, der := range [][]byte{leafDER, caDER} {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatal(err)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func evidence(t *testing.T, at time.Time, ip, reason string, s chainSpec) store.RejectedEnrollment {
	t.Helper()
	return store.RejectedEnrollment{
		TS:              at,
		SrcIP:           ip,
		Reason:          reason,
		AttestChainPEM:  chainPEM(t, s),
		ClaimedPackage:  s.app,
		SignerDigestHex: hex.EncodeToString(s.digest),
	}
}

func evidenceJSON(t *testing.T, ev store.RejectedEnrollment) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type revokedSerials map[string]bool

func (r revokedSerials) Revoked(serialHex string) bool { return r[serialHex] }
