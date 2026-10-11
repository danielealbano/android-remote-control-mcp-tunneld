//go:build integration

package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
)

const (
	alpnServedLog = "acme tls-alpn-01 challenge served"
	httpServedLog = "acme http-01 challenge served"
)

func bindEchoPhone(t *testing.T, env *itEnv) (string, *atomic.Int32) {
	t.Helper()
	ctx := context.Background()
	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	fqdn := ident.Name + "." + itTunnelDomain
	phoneTLS := phoneServerTLS(t, ident)
	var streams atomic.Int32
	backend := func(s io.ReadWriteCloser) {
		streams.Add(1)
		conn := tls.Server(&rwcConn{rwc: s}, phoneTLS)
		defer func() { _ = conn.Close() }()
		if err := conn.Handshake(); err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	}
	c, err := client.New(env.edgeAddr, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident, backend)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if err := c.Run(runCtx); err != nil && runCtx.Err() == nil {
			t.Errorf("tunnel client run: %v", err)
		}
	}()
	t.Cleanup(func() {
		runCancel()
		<-runDone
		c.Close()
	})
	var lastErr error
	if !waitBool(30*time.Second, func() bool {
		lastErr = frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots)
		return lastErr == nil
	}) {
		t.Fatalf("frontend TLS roundtrip never succeeded: %v", lastErr)
	}
	return fqdn, &streams
}

func TestIntegration_ChallengeRoundtrip(t *testing.T) {
	tests := []struct {
		method         string
		served, unused string
	}{
		{method: config.ChallengeTLSALPN01, served: alpnServedLog, unused: httpServedLog},
		{method: config.ChallengeHTTP01, served: httpServedLog, unused: alpnServedLog},
	}
	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			env, logs := startChallengeServer(t, tc.method)
			bindEchoPhone(t, env)
			if logs.Count(tc.served) < 1 {
				t.Fatalf("no %q record: the configured method did not answer", tc.served)
			}
			if n := logs.Count(tc.unused); n != 0 {
				t.Fatalf("%d %q records: the other method answered", n, tc.unused)
			}
		})
	}
}

func TestIntegration_TLSALPNNeverSpliced(t *testing.T) {
	env, _ := startChallengeServer(t, config.ChallengeTLSALPN01)
	fqdn, streams := bindEchoPhone(t, env)
	before := streams.Load()
	noRouteBefore := metricLineValue(env.internalAddr, `tunneld_rejections_total{reason="no-route"}`)

	raw, err := net.DialTimeout("tcp", env.edgeAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: fqdn, NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err == nil {
		t.Fatal("an acme-tls/1 handshake with no pending challenge must be closed")
	}
	_ = raw.Close()

	if !waitBool(10*time.Second, func() bool {
		return metricLineValue(env.internalAddr, `tunneld_rejections_total{reason="no-route"}`) > noRouteBefore
	}) {
		t.Fatal("the acme-tls/1 attempt must be recorded as no-route")
	}
	if got := streams.Load(); got != before {
		t.Fatalf("the acme-tls/1 attempt reached the phone (%d new streams)", got-before)
	}
}

func rawHTTP(t *testing.T, conn net.Conn, br *bufio.Reader, requestLine, host string) (*http.Response, error) {
	t.Helper()
	if _, err := io.WriteString(conn, requestLine+"\r\nHost: "+host+"\r\n\r\n"); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return nil, err
	}
	if err := resp.Body.Close(); err != nil {
		return nil, err
	}
	return resp, nil
}

func TestIntegration_ACMEHTTPNoKeepAlive(t *testing.T) {
	env, _ := startChallengeServer(t, config.ChallengeHTTP01)
	conn, err := net.DialTimeout("tcp", env.acmeHTTPAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := rawHTTP(t, conn, br, "GET /.well-known/acme-challenge/unknown HTTP/1.1", itEnrollHost)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if !resp.Close {
		t.Fatal("the response must carry Connection: close")
	}
	if _, err := rawHTTP(t, conn, br, "GET /.well-known/acme-challenge/unknown HTTP/1.1", itEnrollHost); err == nil {
		t.Fatal("a second request on the same connection must fail (keep-alives are off)")
	}
}

func TestIntegration_ACMEHTTPMissCounted(t *testing.T) {
	env, _ := startChallengeServer(t, config.ChallengeHTTP01)
	for _, requestLine := range []string{"GET /index.html HTTP/1.1", "OPTIONS * HTTP/1.1"} {
		conn, err := net.DialTimeout("tcp", env.acmeHTTPAddr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		resp, err := rawHTTP(t, conn, bufio.NewReader(conn), requestLine, itEnrollHost)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("%s: %v", requestLine, err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: status %d, want 404", requestLine, resp.StatusCode)
		}
	}
	if !waitBool(10*time.Second, func() bool {
		return metricLineValue(env.internalAddr, `tunneld_rejections_total{reason="acme-http-miss"}`) == 2
	}) {
		t.Fatalf("acme-http-miss = %v, want 2", metricLineValue(env.internalAddr, `tunneld_rejections_total{reason="acme-http-miss"}`))
	}
}

func TestIntegration_ACMEHTTPListenerDrains(t *testing.T) {
	env, _ := startChallengeServer(t, config.ChallengeHTTP01)
	if err := env.drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if c, err := net.DialTimeout("tcp", env.acmeHTTPAddr, 2*time.Second); err == nil {
		_ = c.Close()
		t.Fatal("the HTTP-01 listener must be closed after the drain")
	}
}
