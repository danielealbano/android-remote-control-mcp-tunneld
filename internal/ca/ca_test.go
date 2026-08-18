package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

const testValidity = 10 * 365 * 24 * time.Hour

func genCAMaterial(t *testing.T, isCA bool) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tunneld-ca-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(testValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		MaxPathLenZero:        isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func writeCAFiles(t *testing.T, certDER []byte, key *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "ca-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func newTestCA(t *testing.T) *CA {
	t.Helper()
	der, key := genCAMaterial(t, true)
	cp, kp := writeCAFiles(t, der, key)
	ca, err := Load(cp, kp, testValidity)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// csrFor builds a parsed CSR (with an attacker-controlled subject/SAN, to prove the CA discards them).
func csrFor(t *testing.T, key crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	der := csrDER(t, key)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func csrDER(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "attacker-controlled-cn"},
		DNSNames: []string{"evil.example.test"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestLoadRejectsBadCAMaterial(t *testing.T) {
	if _, err := Load("/nope/ca.pem", "/nope/ca-key.pem", testValidity); err == nil {
		t.Error("missing files must error")
	}
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(badCert, []byte("not a pem"), 0o600)
	_, key := genCAMaterial(t, true)
	_, keyPath := writeCAFiles(t, mustDER(t, key, true), key)
	if _, err := Load(badCert, keyPath, testValidity); err == nil {
		t.Error("corrupt cert must error")
	}
	der, k := genCAMaterial(t, false)
	cp, kp := writeCAFiles(t, der, k)
	if _, err := Load(cp, kp, testValidity); err == nil {
		t.Error("non-CA cert must error")
	}
}

func mustDER(t *testing.T, key *ecdsa.PrivateKey, isCA bool) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(testValidity),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSignIdentityRoundTripsAndChainsToCA(t *testing.T) {
	ca := newTestCA(t)
	leafPEM, err := ca.SignIdentity(csrFor(t, p256Key(t)), "abc2345678")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "abc2345678" {
		t.Errorf("CN = %q, want abc2345678", cert.Subject.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("identity cert must chain to the CA: %v", err)
	}
	if Fingerprint(cert) == "" {
		t.Error("fingerprint empty")
	}
}

func TestSignIdentityRejectsBadCSRSignature(t *testing.T) {
	ca := newTestCA(t)
	der := csrDER(t, p256Key(t))
	der[len(der)-1] ^= 0xff // tamper the signature tail
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err) // structurally still parses; the signature check is what must fail
	}
	if _, err := ca.SignIdentity(csr, "name123456"); err == nil {
		t.Error("tampered CSR must be rejected")
	}
}

func TestSignIdentityIgnoresCSRSubject(t *testing.T) {
	ca := newTestCA(t)
	leafPEM, err := ca.SignIdentity(csrFor(t, p256Key(t)), "servername")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if cert.Subject.CommonName != "servername" {
		t.Errorf("CN = %q, want servername (CSR CN discarded)", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("SANs = %v, want none (CSR SAN discarded)", cert.DNSNames)
	}
}

func TestSignIdentityRejectsNonP256Key(t *testing.T) {
	ca := newTestCA(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ca.SignIdentity(csrFor(t, rsaKey), "n123456789"); err != ErrUnsupportedKeyType {
		t.Errorf("RSA CSR: err = %v, want ErrUnsupportedKeyType", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := ca.SignIdentity(csrFor(t, p384), "n123456789"); err != ErrUnsupportedKeyType {
		t.Errorf("P-384 CSR: err = %v, want ErrUnsupportedKeyType", err)
	}
}

func TestFingerprintStableAndPrefixed(t *testing.T) {
	ca := newTestCA(t)
	leafPEM, _ := ca.SignIdentity(csrFor(t, p256Key(t)), "fp12345678")
	block, _ := pem.Decode(leafPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	f1 := Fingerprint(cert)
	f2 := Fingerprint(cert)
	if f1 != f2 {
		t.Error("fingerprint not stable")
	}
	if len(f1) != len("sha256:")+64 || f1[:7] != "sha256:" {
		t.Errorf("fingerprint shape wrong: %q", f1)
	}
}

// constReader fills every read with a constant byte, so generateName produces the SAME name each
// attempt — used to force reserved-label collisions and the attempt-exhaustion path deterministically.
type constReader byte

func (c constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

func TestGenerateName_ReservesEnrollLabel(t *testing.T) {
	produced, err := generateName("", 10, constReader(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generateName("", 10, constReader(0), produced); err == nil {
		t.Error("the extra-reserved (enroll host) label must never be produced")
	}
}

func TestGenerateName_ReservedSkipAndExhaustion(t *testing.T) {
	produced, _ := generateName("", 10, constReader(0))
	if _, err := generateName("", 10, constReader(0), produced); err == nil {
		t.Fatal("when the only producible name is reserved, all attempts collide → exhaustion error")
	}
	if _, err := generateName("", 10, constReader(0)); err != nil {
		t.Errorf("a non-reserved deterministic name must succeed: %v", err)
	}
}

func TestGenerateNameShapeAndReservedSkip(t *testing.T) {
	re := regexp.MustCompile(`^[a-z2-7]{10}$`)
	for range 200 {
		name, err := GenerateName("", 10)
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(name) {
			t.Fatalf("name %q not 10 chars of [a-z2-7]", name)
		}
		if _, bad := reserved[name]; bad {
			t.Fatalf("generated a reserved name %q", name)
		}
	}
}
