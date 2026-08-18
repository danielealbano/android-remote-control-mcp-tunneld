package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// MeshRoleOU marks a mesh-role certificate (in the subject OU). The phone listener REJECTS any cert
// carrying it (identity role only); the mesh listener REQUIRES it (mesh role only). One CA machinery
// signs both, but cross-use is impossible because each listener accepts only its role.
const MeshRoleOU = "tunneld-mesh"

// SignIdentity issues a 6-month (--cert-validity) internal identity cert for a phone identity CSR. The
// server-assigned `name` is passed EXPLICITLY and sets CN = name, IGNORING all CSR subject fields
// (SACRED invariant: the server assigns the name; it is generated after attestation and is not in the
// phone CSR). TLS client-auth EKU (the phone's mTLS control-connection credential).
func (c *CA) SignIdentity(csr *x509.CertificateRequest, name string) (certPEM []byte, err error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: identity csr signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrUnsupportedKeyType
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name}, // server-assigned; CSR subject ignored
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(c.validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: create identity cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SignMesh mints a short-lived mesh-role cert for nodeID (server-side key). SAN = nodeID (a DNS name),
// subject OU = MeshRoleOU, TLS client+server auth (a node both dials and accepts), validity ttl
// (--mesh-cert-ttl). Returns the cert PEM + the freshly-generated key PEM (the mesh key stays on the
// node). ttl is passed explicitly (server.Run knows --mesh-cert-ttl) rather than held on the CA, so
// the shared Load signature stays additive.
func (c *CA) SignMesh(nodeID string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: mesh key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("ca: mesh serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID, OrganizationalUnit: []string{MeshRoleOU}},
		DNSNames:              []string{nodeID},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: create mesh cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: marshal mesh key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// HasMeshRole reports whether a parsed peer certificate carries the mesh-role OU marker.
func HasMeshRole(cert *x509.Certificate) bool {
	return slices.Contains(cert.Subject.OrganizationalUnit, MeshRoleOU)
}
