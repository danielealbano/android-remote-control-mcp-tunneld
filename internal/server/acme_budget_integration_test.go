//go:build integration

package server

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/client"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

func TestIntegration_ACMEBudgetExhaustedRetryAfter(t *testing.T) {
	env := startIntegrationServer(t, func(c *config.ServeCmd) {
		c.ACMEBudgetLEName = "1/1h"
		c.ACMEGTSAccounts = nil
	})
	ctx := context.Background()
	start := time.Now()
	ident, err := client.Enroll(ctx, env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if ident.CA != "letsencrypt" {
		t.Fatalf("enrollment issued on %q, want letsencrypt", ident.CA)
	}
	const okSeries, failSeries = `tunneld_acme_issue_total{ca="letsencrypt",result="ok"}`, `tunneld_acme_issue_total{ca="letsencrypt",result="fail"}`
	okBefore, okErr := metricLineValue(env.internalAddr, okSeries)
	failBefore, failErr := metricLineValue(env.internalAddr, failSeries)
	if err := errors.Join(okErr, failErr); err != nil {
		t.Fatal(err)
	}

	c, err := client.New(env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots, ident,
		func(s io.ReadWriteCloser) { tunneltest.CloseLogged(s) })
	if err != nil {
		t.Fatal(err)
	}
	nonceHex := randomHex(t)
	if err := env.rdb.Set(ctx, "enroll-nonce:"+nonceHex, "1", 5*time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	renewCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = c.Renew(renewCtx, nonceHex)
	elapsed := time.Since(start)
	ee, ok := errors.AsType[*client.EnrollError](err)
	if !ok || !errors.Is(err, context.DeadlineExceeded) || ee.Reason != "acme_rate_limited" {
		t.Fatalf("Renew = %v, want acme_rate_limited joined with the ctx deadline", err)
	}
	if low, high := time.Hour-elapsed, 3610*time.Second; ee.RetryAfter < low.Truncate(time.Second) || ee.RetryAfter > high {
		t.Fatalf("retry after %s, want within [%s, %s] (the name bucket's wait plus 1-10 s)", ee.RetryAfter, low, high)
	}

	okAfter, okErr := metricLineValue(env.internalAddr, okSeries)
	failAfter, failErr := metricLineValue(env.internalAddr, failSeries)
	if err := errors.Join(okErr, failErr); err != nil {
		t.Fatal(err)
	}
	if okAfter != okBefore || failAfter != failBefore {
		t.Fatalf("LE issue counters ok %v→%v fail %v→%v, want unchanged (the LE account was never asked)", okBefore, okAfter, failBefore, failAfter)
	}
	if v, err := metricLineValue(env.internalAddr, `tunneld_acme_budget_ratio{account="local",budget="orders",ca="letsencrypt"}`); err != nil || v <= 0 {
		t.Fatalf("the LE orders budget series must be exported, got %v (%v)", v, err)
	}
}

func TestIntegration_GTSOnlyIssues(t *testing.T) {
	env := startIntegrationServer(t, func(c *config.ServeCmd) { c.ACMEDirLE = "" })
	ident, err := client.Enroll(context.Background(), env.edgeAddr, itEnrollHost, itControlHost, itTunnelDomain, env.pebble.IssuingRoots)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if ident.CA != "gts" {
		t.Fatalf("enrollment issued on %q, want gts", ident.CA)
	}
}
