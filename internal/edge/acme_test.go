package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type ipConn struct {
	net.Conn
	peer string
}

func (c ipConn) RemoteAddr() net.Addr { return tcpAddr(c.peer) }

type levelRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *levelRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r)
	h.mu.Unlock()
	return nil
}

func (h *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *levelRecorder) WithGroup(string) slog.Handler { return h }

func (h *levelRecorder) aboveDebug() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		if r.Level > slog.LevelDebug {
			out = append(out, r.Message)
		}
	}
	return out
}

type rejectArgs struct{ reason, tunnel, ip string }

type argRecorder struct {
	*recRecorder
	amu  sync.Mutex
	args []rejectArgs
}

func (r *argRecorder) Reject(reason, tunnel, ip string) {
	r.amu.Lock()
	r.args = append(r.args, rejectArgs{reason: reason, tunnel: tunnel, ip: ip})
	r.amu.Unlock()
	r.recRecorder.Reject(reason, tunnel, ip)
}

func (r *argRecorder) rejected() []rejectArgs {
	r.amu.Lock()
	defer r.amu.Unlock()
	return append([]rejectArgs(nil), r.args...)
}

func selfSignedChallengeCert(t *testing.T, domain string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func captureClientHello(t *testing.T, sni string, alpn ...string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer tunneltest.CloseOrLog(t, c1)
	handshake := make(chan error, 1)
	go func() {
		handshake <- tls.Client(c1, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatalf("read ClientHello record header: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatalf("read ClientHello record: %v", err)
	}
	tunneltest.CloseOrLog(t, c2)
	if err := <-handshake; err == nil {
		t.Fatal("the ClientHello capture handshake must not complete")
	}
	return append(hdr, body...)
}

func runHandleConn(te *testEdge, conn net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		te.e.handleConn(context.Background(), conn)
		close(done)
	}()
	return done
}

func waitDone(t *testing.T, done <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("handleConn did not return within %s", d)
	}
}

func acmeClient(conn net.Conn, sni string, verify bool) *tls.Conn {
	return tls.Client(conn, &tls.Config{
		ServerName: sni, NextProtos: []string{acmeTLS1Protocol}, InsecureSkipVerify: !verify,
		RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12,
	})
}

func TestEdge_ACMETLSALPN_Serves(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	logs := &levelRecorder{}
	te.e.cfg.Logger = slog.New(logs)
	te.chal.cert = selfSignedChallengeCert(t, "a.example.test")
	client, server := net.Pipe()
	done := runHandleConn(te, ipConn{Conn: server, peer: "198.51.100.20"})
	cli := acmeClient(client, "A.Example.Test", false)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("acme-tls/1 handshake: %v", err)
	}
	cs := cli.ConnectionState()
	if cs.NegotiatedProtocol != acmeTLS1Protocol || string(cs.PeerCertificates[0].Raw) != string(te.chal.cert.Certificate[0]) {
		t.Fatalf("protocol %q / unexpected certificate", cs.NegotiatedProtocol)
	}
	tunneltest.CloseOrLog(t, cli)
	waitDone(t, done, 5*time.Second)
	if got := te.chal.lookups(); len(got) != 1 || got[0] != "a.example.test" {
		t.Fatalf("challenge lookups = %v, want [a.example.test]", got)
	}
	if te.rtr.lookups != 0 || te.local.opened != 0 || te.mesh.opened != 0 {
		t.Fatalf("an ACME validation must never be routed: router=%d local=%d mesh=%d", te.rtr.lookups, te.local.opened, te.mesh.opened)
	}
	if above := logs.aboveDebug(); len(above) != 0 {
		t.Fatalf("records above Debug: %v", above)
	}
	if n := te.e.clients.Load(); n != 0 {
		t.Fatalf("max-clients slot leaked: %d", n)
	}
}

func TestEdge_ACMETLSALPN_NoChallenge(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "no pending challenge"},
		{name: "store error", err: errors.New("valkey down")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			te := newTestEdge(t, baseConfig(), nil, nil)
			logs := &levelRecorder{}
			te.e.cfg.Logger = slog.New(logs)
			rec := &argRecorder{recRecorder: te.rec}
			te.e.rec = rec
			te.chal.err = tc.err
			client, server := net.Pipe()
			done := runHandleConn(te, ipConn{Conn: server, peer: "198.51.100.21"})
			if err := acmeClient(client, "a.example.test", false).Handshake(); err == nil {
				t.Fatal("handshake must fail without a pending challenge")
			}
			waitDone(t, done, 5*time.Second)
			want := rejectArgs{reason: "no-route", tunnel: "a.example.test", ip: "198.51.100.21"}
			if got := rec.rejected(); len(got) != 1 || got[0] != want {
				t.Fatalf("rejects = %+v, want [%+v]", got, want)
			}
			if above := logs.aboveDebug(); len(above) != 0 {
				t.Fatalf("records above Debug: %v", above)
			}
		})
	}
}

func TestEdge_ACMETLSALPN_HandshakeFailure(t *testing.T) {
	tests := []struct {
		name    string
		bounded bool
		drive   func(t *testing.T, client net.Conn)
	}{
		{name: "client aborts", drive: func(t *testing.T, client net.Conn) {
			if err := acmeClient(client, "a.example.test", true).Handshake(); err == nil {
				t.Error("a verifying client must reject the self-signed challenge certificate")
			}
			tunneltest.CloseOrLog(t, client)
		}},
		{name: "client stalls", bounded: true, drive: func(t *testing.T, client net.Conn) {
			if _, err := client.Write(captureClientHello(t, "a.example.test", acmeTLS1Protocol)); err != nil {
				t.Errorf("write ClientHello: %v", err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.MaxClients = 1
			cfg.HandshakeTimeout = 300 * time.Millisecond
			te := newTestEdge(t, cfg, nil, nil)
			logs := &levelRecorder{}
			te.e.cfg.Logger = slog.New(logs)
			te.chal.cert = selfSignedChallengeCert(t, "a.example.test")
			client, server := net.Pipe()
			t.Cleanup(func() { tunneltest.CloseOrLog(t, client) })
			done := runHandleConn(te, ipConn{Conn: server, peer: "198.51.100.22"})
			tc.drive(t, client)
			wait := 5 * time.Second
			if tc.bounded {
				wait = cfg.HandshakeTimeout + 500*time.Millisecond
			}
			waitDone(t, done, wait)
			if !te.e.Admit() {
				t.Fatal("the max-clients slot must be released after a failed challenge handshake")
			}
			te.e.Release()
			if above := logs.aboveDebug(); len(above) != 0 {
				t.Fatalf("records above Debug: %v", above)
			}
		})
	}
}

func TestEdge_ACMETLSALPN_ReservedHost(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	te.chal.cert = selfSignedChallengeCert(t, "enroll.example.test")
	client, server := net.Pipe()
	done := runHandleConn(te, ipConn{Conn: server, peer: "198.51.100.23"})
	cli := acmeClient(client, "enroll.example.test", false)
	if err := cli.Handshake(); err != nil {
		t.Fatalf("acme-tls/1 handshake for the enroll host: %v", err)
	}
	tunneltest.CloseOrLog(t, cli)
	waitDone(t, done, 5*time.Second)
	if n := len(te.e.enrollLn.ch); n != 0 {
		t.Fatalf("an ACME validation for the enroll host was pushed to the enroll listener (%d queued)", n)
	}
}

func TestEdge_ACMETLSALPN_BanFirst(t *testing.T) {
	banned := netip.MustParseAddr("198.51.100.24")
	te := newTestEdge(t, baseConfig(), func(ip netip.Addr) bool { return ip == banned }, nil)
	te.chal.cert = selfSignedChallengeCert(t, "a.example.test")
	conn := newScriptConn("198.51.100.24", captureClientHello(t, "a.example.test", acmeTLS1Protocol))
	te.e.handleConn(context.Background(), conn)
	if !conn.isClosed() || len(te.rec.rejects) != 1 || te.rec.rejects[0] != "ban" {
		t.Fatalf("closed=%v rejects=%v, want closed + [ban]", conn.isClosed(), te.rec.rejects)
	}
	if got := te.chal.lookups(); len(got) != 0 {
		t.Fatalf("a banned IP must never reach the challenge lookup, got %v", got)
	}
}

func TestEdge_NonACMEALPNUnchanged(t *testing.T) {
	t.Run("h2 for the enroll host", func(t *testing.T) {
		te := newTestEdge(t, baseConfig(), nil, nil)
		conn := newScriptConn("198.51.100.25", captureClientHello(t, "enroll.example.test", "h2", "http/1.1"))
		te.e.handleConn(context.Background(), conn)
		if n := len(te.e.enrollLn.ch); n != 1 {
			t.Fatalf("enroll listener queued %d conns, want 1", n)
		}
		if got := te.chal.lookups(); len(got) != 0 {
			t.Fatalf("non-ACME ALPN consulted the challenge store: %v", got)
		}
	})
	t.Run("http/1.1 for a tunnel", func(t *testing.T) {
		te := newTestEdge(t, baseConfig(), nil, nil)
		conn := newScriptConn("198.51.100.26", captureClientHello(t, "abcdefghij.example.test", "http/1.1"))
		te.e.handleConn(context.Background(), conn)
		if te.rtr.lookups == 0 && !containsStr(te.rec.rejects, "no-route") {
			t.Fatalf("a tunnel SNI must go through the tunnel dispatch (router=%d rejects=%v)", te.rtr.lookups, te.rec.rejects)
		}
		if got := te.chal.lookups(); len(got) != 0 {
			t.Fatalf("non-ACME ALPN consulted the challenge store: %v", got)
		}
	})
}

func TestEdge_AdmitRelease(t *testing.T) {
	cfg := baseConfig()
	cfg.MaxClients = 1
	te := newTestEdge(t, cfg, nil, nil)
	if !te.e.Admit() {
		t.Fatal("first Admit must succeed")
	}
	if te.e.Admit() {
		t.Fatal("Admit past MaxClients must fail")
	}
	te.e.Release()
	if !te.e.Admit() {
		t.Fatal("Release must free the slot")
	}
	te.e.Release()
}
