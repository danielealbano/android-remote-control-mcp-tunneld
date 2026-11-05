//go:build integration

package server

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type sentryIngest struct {
	mu        sync.Mutex
	envelopes []string
}

func startSentryIngest(t *testing.T) (*sentryIngest, string) {
	t.Helper()
	in := &sentryIngest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read sentry envelope: %v", err)
			return
		}
		in.mu.Lock()
		in.envelopes = append(in.envelopes, string(body))
		in.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return in, "http://public@" + u.Host + "/1"
}

func (in *sentryIngest) received(parts ...string) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, e := range in.envelopes {
		all := true
		for _, p := range parts {
			all = all && strings.Contains(e, p)
		}
		if all {
			return true
		}
	}
	return false
}

func (in *sentryIngest) summary() string {
	in.mu.Lock()
	defer in.mu.Unlock()
	var b strings.Builder
	for _, e := range in.envelopes {
		for _, line := range strings.Split(e, "\n") {
			if len(line) > 300 {
				line = line[:300]
			}
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func TestIntegration_SentryReceivesTheRunsTracesAndLogs(t *testing.T) {
	in, dsn := startSentryIngest(t)
	env := startIntegrationServer(t, func(cfg *config.ServeCmd) {
		cfg.SentryDSN, cfg.SentryEnvironment, cfg.SentryTracesSampleRate = dsn, "integration", 1
		cfg.AttestRefresh = 200 * time.Millisecond
	})
	ctx := context.Background()

	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	phoneTLS := phoneServerTLS(t, ident)
	backend := func(_ string, s io.ReadWriteCloser) {
		conn := tls.Server(&rwcConn{rwc: s}, phoneTLS)
		defer tunneltest.CloseLogged(conn)
		if err := conn.Handshake(); err != nil {
			testLogger().Warn("echo phone handshake failed", "err", err)
			return
		}
		if _, err := io.Copy(conn, conn); err != nil {
			testLogger().Debug("echo phone stream ended with an error", "err", err)
		}
	}
	c, err := client.New(env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident, backend)
	if err != nil {
		t.Fatal(err)
	}
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	go func() {
		if err := c.Run(runCtx); err != nil && runCtx.Err() == nil {
			testLogger().Warn("tunnel client run failed", "err", err)
		}
	}()
	fqdn := ident.Name + "." + itTunnelDomain
	var lastErr error
	if !waitBool(30*time.Second, func() bool {
		lastErr = frontendRoundtrip(env.edgeAddr, fqdn, env.pebble.IssuingRoots)
		return lastErr == nil
	}) {
		t.Fatalf("frontend TLS roundtrip never succeeded: %v", lastErr)
	}

	runCancel()
	if err := env.drain(); err != nil {
		t.Fatal(err)
	}
	release := `"release":"tunneld@it"`
	for _, tx := range []string{"GET /api/v1/enroll/nonce", "POST /api/v1/enroll", "POST /api/v1/issue", "public connection"} {
		if !in.received(`"type":"transaction"`, `"transaction":"`+tx+`"`, release, `"environment":"integration"`) {
			t.Errorf("no %q transaction reached Sentry; received:\n%s", tx, in.summary())
		}
	}
	if !in.received(`"type":"log"`, "attestation root certificates; keeping the ones fetched before, if any") {
		t.Error("the refresher's Warn line never reached Sentry as a log")
	}
}
