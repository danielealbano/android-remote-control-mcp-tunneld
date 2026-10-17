//go:build integration

package acme

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type chainRecorder struct {
	base     http.RoundTripper
	mu       sync.Mutex
	certURLs []string
	offered  []int
}

func (r *chainRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/pem-certificate-chain") {
		r.mu.Lock()
		r.certURLs = append(r.certURLs, req.URL.String())
		alternates := 0
		for _, v := range resp.Header.Values("Link") {
			alternates += len(alternateRel.FindAllString(v, -1))
		}
		r.offered = append(r.offered, alternates)
		r.mu.Unlock()
	}
	return resp, nil
}

type pebbleDNS struct{ env *tunneltest.PebbleEnv }

func (d pebbleDNS) Present(_ context.Context, fqdn, value string) error {
	return d.env.PublishTXT(fqdn, value)
}

func (d pebbleDNS) CleanUp(_ context.Context, fqdn, _ string) error { return d.env.ClearTXT(fqdn) }

func TestIntegration_CertificateDownloadSkipsAlternateChains(t *testing.T) {
	env := tunneltest.StartPebble(t, tunneltest.WithAlternateRoots(2))
	t.Setenv("LEGO_CA_CERTIFICATES", env.MinicaFile)
	opt, err := redis.ParseURL(tunneltest.StartValkey(t))
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	lim := limit.NewLimiter(rdb, 1, 1, 1, time.Hour)
	b := testBudgets()
	acct := &account{ca: CALetsEncrypt, id: "le-acct", label: "local"}
	rec := &chainRecorder{}
	ctx := context.Background()
	lc, err := NewLegoClient(ctx, LegoConfig{
		CAID: CALetsEncrypt, DirectoryURL: env.DirectoryURL, Email: "ops@example.test", Logger: testLogger(),
		Challenge: "dns-01", DNS: pebbleDNS{env: env}, DNSResolvers: []string{env.DNSResolver}, DNSSkipPropagationCheck: true,
		Wrap: func(base http.RoundTripper) http.RoundTripper {
			rec.base = base
			return &budgetTransport{base: rec, acct: acct, budgets: b, requests: lim, cooldowns: lim, recorder: nopRecorder{},
				cooldown: time.Minute, firstPoll: 100 * time.Millisecond, pollEvery: 200 * time.Millisecond,
				logger: testLogger(), now: time.Now}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const fqdn = "alt.example.test"
	tr := newOrderTrack(b.leName(fqdn), b.leDomain(fqdn))
	pemChain, info, err := lc.obtain(withTrack(ctx, tr), tlsCSR(t, fqdn, fqdn), "alt")
	if err != nil {
		t.Fatal(err)
	}
	if len(pemChain) == 0 || info.Serial == "" {
		t.Fatalf("want an issued certificate, got %d bytes, %+v", len(pemChain), info)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.certURLs) != 1 {
		t.Fatalf("only the default chain may be downloaded, got %d downloads: %q", len(rec.certURLs), rec.certURLs)
	}
	if rec.offered[0] != 2 {
		t.Fatalf("Pebble must offer the 2 alternate chains it was started with on the download, saw %d", rec.offered[0])
	}
}
