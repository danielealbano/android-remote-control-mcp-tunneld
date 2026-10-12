package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"slices"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func parseChallengeLeaf(t *testing.T, cert *tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse challenge certificate: %v", err)
	}
	return leaf
}

func TestChallengeCertificate_KeyUsage(t *testing.T) {
	t.Parallel()
	cert, err := challengeCertificate("a.example.test", "token.thumbprint")
	if err != nil {
		t.Fatal(err)
	}
	if got := parseChallengeLeaf(t, cert).KeyUsage; got != x509.KeyUsageDigitalSignature {
		t.Fatalf("KeyUsage = %v, want exactly KeyUsageDigitalSignature", got)
	}
}

func TestChallengeCertificate_Shape(t *testing.T) {
	t.Parallel()
	const domain, keyAuth = "a.example.test", "token.thumbprint"
	cert, err := challengeCertificate(domain, keyAuth)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseChallengeLeaf(t, cert)
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("public key = %T, want ECDSA P-256", leaf.PublicKey)
	}
	if !slices.Equal(leaf.DNSNames, []string{domain}) {
		t.Fatalf("DNSNames = %v, want exactly [%s]", leaf.DNSNames, domain)
	}
	sum := sha256.Sum256([]byte(keyAuth))
	want, err := asn1.Marshal(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(idPeAcmeIdentifier) {
			continue
		}
		found = true
		if !ext.Critical {
			t.Error("acmeIdentifier extension must be critical")
		}
		if string(ext.Value) != string(want) {
			t.Errorf("acmeIdentifier value = %x, want %x", ext.Value, want)
		}
	}
	if !found {
		t.Fatal("acmeIdentifier extension missing")
	}
}

func TestChallengeCertificate_TLS13Handshake(t *testing.T) {
	t.Parallel()
	cert, err := challengeCertificate("a.example.test", "token.thumbprint")
	if err != nil {
		t.Fatal(err)
	}
	srvConn, cliConn := net.Pipe()
	defer tunneltest.CloseOrLog(t, srvConn)
	defer tunneltest.CloseOrLog(t, cliConn)
	srvErr := make(chan error, 1)
	go func() {
		srv := tls.Server(srvConn, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"acme-tls/1"}, MinVersion: tls.VersionTLS12})
		srvErr <- srv.Handshake()
	}()
	cli := tls.Client(cliConn, &tls.Config{
		ServerName: "a.example.test", NextProtos: []string{"acme-tls/1"},
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	cs := cli.ConnectionState()
	if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != "acme-tls/1" {
		t.Fatalf("version %x protocol %q, want TLS 1.3 + acme-tls/1", cs.Version, cs.NegotiatedProtocol)
	}
	var found bool
	for _, ext := range cs.PeerCertificates[0].Extensions {
		if ext.Id.Equal(idPeAcmeIdentifier) {
			found = true
		}
	}
	if !found {
		t.Fatal("client did not see the acmeIdentifier extension")
	}
}
