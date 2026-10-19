package phoneconn

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

type dbTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newDBTestCA(t *testing.T) *dbTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dialback-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &dbTestCA{cert: cert, key: key, pool: pool}
}

func (c *dbTestCA) leaf(t *testing.T, cn string, server, meshRole bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eku := x509.ExtKeyUsageClientAuth
	var dns []string
	if server {
		eku = x509.ExtKeyUsageServerAuth
		dns = []string{cn}
	}
	subj := pkix.Name{CommonName: cn}
	if meshRole {
		subj.OrganizationalUnit = []string{ca.MeshRoleOU}
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: subj,
		DNSNames: dns, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type dialBackEnv struct {
	addr      string
	useTLS    bool
	dialBacks *DialBacks
	ca        *dbTestCA
	rejects   chan string
	mgr       *Manager
}

func startDialBackEnv(t *testing.T, useTLS bool, auth tls.ClientAuthType, mtls bool, banned string) *dialBackEnv {
	t.Helper()
	m, _, _, _ := newMgr(t)
	env := &dialBackEnv{useTLS: useTLS, dialBacks: NewDialBacks(tunneltest.Logger()), ca: newDBTestCA(t), rejects: make(chan string, 16), mgr: m}
	h := NewHandler(HandlerConfig{
		Manager: m, PingInterval: time.Hour, StreamPending: 4,
		ValidName: func(n string) bool { return strings.HasPrefix(n, "tun") },
		BanTunnel: func(n string) bool { return n == banned },
		Reject:    func(reason, _, _ string) { env.rejects <- reason },
		DialBacks: env.dialBacks, DialBackMTLS: mtls,
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 200 * time.Millisecond, ReadTimeout: 200 * time.Millisecond}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.addr = ln.Addr().String()
	if useTLS {
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{env.ca.leaf(t, "connect.example.test", true, false)},
			ClientAuth: auth, ClientCAs: env.ca.pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
		ln = tls.NewListener(ln, srv.TLSConfig)
	}
	tunneltest.ServeHTTP(t, srv, ln)
	return env
}

func (env *dialBackEnv) dial(t *testing.T, cert *tls.Certificate) net.Conn {
	t.Helper()
	if !env.useTLS {
		c, err := net.Dial("tcp", env.addr)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cfg := &tls.Config{ServerName: "connect.example.test", RootCAs: env.ca.pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	c, err := tls.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sendDialBackRequest(t *testing.T, c net.Conn, method, token, upgrade string, extra []byte) (*bufio.Reader, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(method, "http://connect.example.test"+wire.DialBackPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	if upgrade != "" {
		req.Header.Set("Upgrade", upgrade)
	}
	if token != "" {
		req.Header.Set(wire.DialBackHeader, token)
	}
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	if len(extra) > 0 {
		if _, err := c.Write(extra); err != nil {
			t.Fatal(err)
		}
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	return br, resp
}

type awaitResult struct {
	conn net.Conn
	err  error
}

func (env *dialBackEnv) await(t *testing.T, token, tunnel string) <-chan awaitResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	registered := make(chan struct{})
	out := make(chan awaitResult, 1)
	go func() {
		c, err := env.dialBacks.Await(ctx, token, tunnel, func(context.Context) error { close(registered); return nil })
		out <- awaitResult{conn: c, err: err}
	}()
	<-registered
	return out
}

func delivered(t *testing.T, res <-chan awaitResult) net.Conn {
	t.Helper()
	var r awaitResult
	select {
	case r = <-res:
	case <-time.After(3 * time.Second):
		t.Fatal("the dial-back was not delivered")
	}
	if r.err != nil {
		t.Fatalf("Await = %v, want a delivered dial-back", r.err)
	}
	t.Cleanup(func() { tunneltest.CloseOrLog(t, r.conn) })
	return r.conn
}

func readExactly(t *testing.T, r io.Reader, want string) {
	t.Helper()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read %q: %v", want, err)
	}
	if string(buf) != want {
		t.Fatalf("read %q, want %q", buf, want)
	}
}

func TestDialBacks_AwaitDelivers(t *testing.T) {
	d := NewDialBacks(tunneltest.Logger())
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "wait-ctx")
	edgeSide, phoneSide := net.Pipe()
	defer tunneltest.CloseOrLog(t, edgeSide)
	defer tunneltest.CloseOrLog(t, phoneSide)
	got, err := d.Await(ctx, "TOKEN", "tun1", func(octx context.Context) error {
		if octx.Value(key{}) != "wait-ctx" {
			t.Error("the open callback must run with the wait ctx")
		}
		if !d.deliver("TOKEN", "tun1", phoneSide) {
			t.Error("deliver to a registered waiter must succeed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != phoneSide {
		t.Fatal("Await must return the delivered connection")
	}
}

func TestDialBacks_OpenErrorUnregisters(t *testing.T) {
	d := NewDialBacks(tunneltest.Logger())
	errOpen := errors.New("owner unreachable")
	_, err := d.Await(context.Background(), "TOKEN", "tun1", func(context.Context) error { return errOpen })
	if !errors.Is(err, errOpen) {
		t.Fatalf("Await = %v, want it to wrap the open error", err)
	}
	if d.expects("TOKEN", "") {
		t.Fatal("a failed open must unregister the token")
	}
}

func TestDialBacks_TimeoutRefusesLateDelivery(t *testing.T) {
	d := NewDialBacks(tunneltest.Logger())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.Await(ctx, "TOKEN", "tun1", func(context.Context) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Await = %v, want the deadline", err)
	}
	edgeSide, phoneSide := net.Pipe()
	defer tunneltest.CloseOrLog(t, edgeSide)
	defer tunneltest.CloseOrLog(t, phoneSide)
	if d.deliver("TOKEN", "tun1", phoneSide) {
		t.Fatal("a delivery after the wait ended must be refused")
	}
}

func TestDialBacks_AbandonClosesRacedDelivery(t *testing.T) {
	d := NewDialBacks(tunneltest.Logger())
	w := &dialWaiter{tunnel: "tun1", conn: make(chan net.Conn, 1)}
	d.waiting["TOKEN"] = w
	edgeSide, phoneSide := net.Pipe()
	defer tunneltest.CloseOrLog(t, edgeSide)
	if !d.deliver("TOKEN", "tun1", phoneSide) {
		t.Fatal("deliver to a registered waiter must succeed")
	}
	d.abandon("TOKEN", w)
	if _, err := edgeSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read from the peer of an abandoned delivery = %v, want EOF (closed)", err)
	}
}

func TestDialBacks_DuplicateTokenRefused(t *testing.T) {
	d := NewDialBacks(tunneltest.Logger())
	errDone := errors.New("done")
	_, err := d.Await(context.Background(), "TOKEN", "tun1", func(ctx context.Context) error {
		if _, derr := d.Await(ctx, "TOKEN", "tun1", func(context.Context) error { return nil }); !errors.Is(derr, ErrDuplicateToken) {
			t.Errorf("a second Await with a live token = %v, want ErrDuplicateToken", derr)
		}
		return errDone
	})
	if !errors.Is(err, errDone) {
		t.Fatalf("Await = %v", err)
	}
}

func TestDialBacks_TunnelMismatchRefused(t *testing.T) {
	d := NewDialBacks(tunneltest.Logger())
	errDone := errors.New("done")
	_, err := d.Await(context.Background(), "TOKEN", "tun1", func(context.Context) error {
		if d.expects("TOKEN", "tun2") {
			t.Error("expects must refuse another tunnel")
		}
		edgeSide, phoneSide := net.Pipe()
		defer tunneltest.CloseOrLog(t, edgeSide)
		defer tunneltest.CloseOrLog(t, phoneSide)
		if d.deliver("TOKEN", "tun2", phoneSide) {
			t.Error("deliver must refuse another tunnel")
		}
		if !d.expects("TOKEN", "tun1") || !d.expects("TOKEN", "") {
			t.Error("the waiter must still expect its own tunnel and an unauthenticated dial-back")
		}
		return errDone
	})
	if !errors.Is(err, errDone) {
		t.Fatalf("Await = %v", err)
	}
}

func TestServeDialBack_UpgradesAndSplices(t *testing.T) {
	env := startDialBackEnv(t, true, tls.RequireAndVerifyClientCert, true, "")
	res := env.await(t, "TOKEN", "tun1")
	cert := env.ca.leaf(t, "tun1", false, false)
	c := env.dial(t, &cert)
	defer tunneltest.CloseOrLog(t, c)
	br, resp := sendDialBackRequest(t, c, http.MethodGet, "TOKEN", wire.DialUpgrade, nil)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Connection"), "Upgrade") || resp.Header.Get("Upgrade") != wire.DialUpgrade {
		t.Fatalf("101 headers = %v", resp.Header)
	}
	srv := delivered(t, res)
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, srv, "ping")
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, br, "pong")
}

func TestServeDialBack_PreservesBytesSentWithTheRequest(t *testing.T) {
	env := startDialBackEnv(t, false, tls.NoClientCert, false, "")
	res := env.await(t, "TOKEN", "tun1")
	c := env.dial(t, nil)
	defer tunneltest.CloseOrLog(t, c)
	_, resp := sendDialBackRequest(t, c, http.MethodGet, "TOKEN", wire.DialUpgrade, []byte("early"))
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	readExactly(t, delivered(t, res), "early")
}

func TestServeDialBack_ClearsServerDeadlines(t *testing.T) {
	env := startDialBackEnv(t, true, tls.RequireAndVerifyClientCert, true, "")
	res := env.await(t, "TOKEN", "tun1")
	cert := env.ca.leaf(t, "tun1", false, false)
	c := env.dial(t, &cert)
	defer tunneltest.CloseOrLog(t, c)
	br, resp := sendDialBackRequest(t, c, http.MethodGet, "TOKEN", wire.DialUpgrade, nil)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	srv := delivered(t, res)
	time.Sleep(time.Second)
	if _, err := c.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, srv, "late")
	if _, err := srv.Write([]byte("still")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, br, "still")
}

func TestServeDialBack_RequiresCertWhenMTLS(t *testing.T) {
	env := startDialBackEnv(t, true, tls.VerifyClientCertIfGiven, true, "")
	env.await(t, "TOKEN", "tun1")
	c := env.dial(t, nil)
	defer tunneltest.CloseOrLog(t, c)
	_, resp := sendDialBackRequest(t, c, http.MethodGet, "TOKEN", wire.DialUpgrade, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without a client cert", resp.StatusCode)
	}
}

func TestServeDialBack_TokenOnlyWhenMTLSOff(t *testing.T) {
	env := startDialBackEnv(t, false, tls.NoClientCert, false, "")
	res := env.await(t, "TOKEN", "tun1")
	c := env.dial(t, nil)
	defer tunneltest.CloseOrLog(t, c)
	br, resp := sendDialBackRequest(t, c, http.MethodGet, "TOKEN", wire.DialUpgrade, nil)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	srv := delivered(t, res)
	if _, err := srv.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	readExactly(t, br, "hi")
}

func TestServeDialBack_StatusTable(t *testing.T) {
	env := startDialBackEnv(t, true, tls.RequireAndVerifyClientCert, true, "tunbanned")
	env.await(t, "TOKEN", "tun1")
	tests := []struct {
		name       string
		cn         string
		mesh       bool
		method     string
		token      string
		upgrade    string
		http10     bool
		want       int
		wantReject string
	}{
		{name: "non-GET", cn: "tun1", method: http.MethodPost, token: "TOKEN", upgrade: wire.DialUpgrade, want: http.StatusMethodNotAllowed},
		{name: "missing token", cn: "tun1", method: http.MethodGet, upgrade: wire.DialUpgrade, want: http.StatusBadRequest},
		{name: "missing Upgrade", cn: "tun1", method: http.MethodGet, token: "TOKEN", want: http.StatusBadRequest},
		{name: "HTTP/1.0", cn: "tun1", http10: true, want: http.StatusBadRequest},
		{name: "unknown token", cn: "tun1", method: http.MethodGet, token: "NOSUCH", upgrade: wire.DialUpgrade, want: http.StatusNotFound},
		{name: "cert of another tunnel", cn: "tun2", method: http.MethodGet, token: "TOKEN", upgrade: wire.DialUpgrade, want: http.StatusNotFound},
		{name: "banned tunnel cert", cn: "tunbanned", method: http.MethodGet, token: "TOKEN", upgrade: wire.DialUpgrade, want: http.StatusForbidden, wantReject: "ban"},
		{name: "mesh-role cert", cn: "tun1", mesh: true, method: http.MethodGet, token: "TOKEN", upgrade: wire.DialUpgrade, want: http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := env.ca.leaf(t, tc.cn, false, tc.mesh)
			c := env.dial(t, &cert)
			defer tunneltest.CloseOrLog(t, c)
			var br *bufio.Reader
			var resp *http.Response
			if tc.http10 {
				raw := "GET " + wire.DialBackPath + " HTTP/1.0\r\nHost: connect.example.test\r\nConnection: Upgrade\r\nUpgrade: " +
					wire.DialUpgrade + "\r\n" + wire.DialBackHeader + ": TOKEN\r\n\r\n"
				if _, err := c.Write([]byte(raw)); err != nil {
					t.Fatal(err)
				}
				br = bufio.NewReader(c)
				var err error
				if resp, err = http.ReadResponse(br, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				br, resp = sendDialBackRequest(t, c, tc.method, tc.token, tc.upgrade, nil)
			}
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			if !tc.http10 && !resp.Close {
				t.Fatalf("an error response must carry Connection: close, got %v", resp.Header)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
				t.Fatalf("after an error response the server must close the connection, read = %v", err)
			}
			select {
			case got := <-env.rejects:
				if got != tc.wantReject {
					t.Fatalf("rejection = %q, want %q", got, tc.wantReject)
				}
			default:
				if tc.wantReject != "" {
					t.Fatalf("missing %q rejection", tc.wantReject)
				}
			}
		})
	}
	t.Run("h2 request", func(t *testing.T) {
		cert := env.ca.leaf(t, "tun1", false, false)
		tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{ServerName: "connect.example.test",
			RootCAs: env.ca.pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
		defer tr.CloseIdleConnections()
		req, err := http.NewRequest(http.MethodGet, "https://"+env.addr+wire.DialBackPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(wire.DialBackHeader, "TOKEN")
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer tunneltest.CloseOrLog(t, resp.Body)
		if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("h2 dial-back = HTTP/%d %d, want HTTP/2 400", resp.ProtoMajor, resp.StatusCode)
		}
	})
}

func TestServeHTTP_IdentityRequiredWhenTLSClientCertOptional(t *testing.T) {
	env := startDialBackEnv(t, true, tls.VerifyClientCertIfGiven, false, "")
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "connect.example.test", RootCAs: env.ca.pool, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	for _, path := range []string{"/api/v1/control", "/api/v1/issue"} {
		resp, err := client.Post("https://"+env.addr+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Reason string `json:"reason"`
		}
		derr := json.NewDecoder(resp.Body).Decode(&body)
		tunneltest.CloseOrLog(t, resp.Body)
		if derr != nil {
			t.Fatal(derr)
		}
		if resp.StatusCode != http.StatusForbidden || body.Reason != "forbidden" {
			t.Fatalf("POST %s without a client cert = %d %q, want 403 forbidden", path, resp.StatusCode, body.Reason)
		}
	}
	if names := env.mgr.ConnectedNames(); len(names) != 0 {
		t.Fatalf("no route may be bound without an identity, got %v", names)
	}
}
