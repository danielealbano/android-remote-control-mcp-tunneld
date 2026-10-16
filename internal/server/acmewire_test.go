package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/acme"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/ca"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

type fakeNodes struct{}

func (fakeNodes) LiveNodeIDs(context.Context) ([]string, error) { return []string{"node-test"}, nil }

func TestBuildACMEChain_LegoLogsToStderr(t *testing.T) {
	prevLog := legolog.Default()
	prevStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Stderr = prevStderr
		legolog.SetDefault(prevLog)
		tunneltest.CloseOrLog(t, r)
		tunneltest.CloseOrLog(t, w)
	})
	os.Stderr = w
	cfg := config.ServeCmd{ACMEAccountDir: t.TempDir()}
	tunneltest.LooseACMEBudgets(&cfg)
	tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts")
	if _, err := buildACMEChain(cfg, nil, testChallengeStore(t), nil, testLogger(), "node-test", fakeNodes{}); err != nil {
		t.Fatal(err)
	}
	legolog.Info("probe")
	tunneltest.CloseOrLog(t, w)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "probe") {
		t.Fatalf("lego log line must go to stderr, got %q", out)
	}
}

func TestLoadAccountKey_AbsentGenerates(t *testing.T) {
	dir := t.TempDir()
	key, err := loadAccountKey(dir, acme.CALetsEncrypt, testLogger())
	if err != nil {
		t.Fatalf("absent key must generate, got err: %v", err)
	}
	if key == nil {
		t.Fatal("generated key must be non-nil")
	}
	fi, serr := os.Stat(filepath.Join(dir, acme.CALetsEncrypt+".key"))
	if serr != nil {
		t.Fatalf("key must be persisted: %v", serr)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perm = %v, want 0600", fi.Mode().Perm())
	}
}

func TestLoadAccountKey_SEC1RoundTrip(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadAccountKey(dir, acme.CAGTS, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadAccountKey(dir, acme.CAGTS, testLogger())
	if err != nil {
		t.Fatalf("reload of a SEC1 key must succeed: %v", err)
	}
	if !k1.(*ecdsa.PrivateKey).Equal(k2) {
		t.Error("reloaded key must equal the persisted key")
	}
}

func TestLoadAccountKey_PKCS8Accepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, acme.CAZeroSSL+".key")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	key, err := loadAccountKey(dir, acme.CAZeroSSL, testLogger())
	if err != nil {
		t.Fatalf("a PKCS#8 EC key must load: %v", err)
	}
	if !priv.Equal(key) {
		t.Error("loaded PKCS#8 key must equal the written key")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a valid existing key must NOT be overwritten")
	}
}

func TestLoadAccountKey_UnparseableIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, acme.CALetsEncrypt+".key")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	junk := []byte("this is not a key")
	if err := os.WriteFile(path, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAccountKey(dir, acme.CALetsEncrypt, testLogger()); err == nil {
		t.Fatal("an unparseable existing key must be fatal")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(junk) {
		t.Error("an unparseable existing key must be left untouched (never overwritten)")
	}
}

func TestBuildACMEChain_CorruptAccountKeyAborts(t *testing.T) {
	dir := t.TempDir()
	accounts := filepath.Join(dir, "accounts")
	if err := os.MkdirAll(accounts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(accounts, acme.CALetsEncrypt+".key"), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.ServeCmd{ACMEAccountDir: dir, ACMEDirLE: "https://le.example.test/dir"}
	tunneltest.LooseACMEBudgets(&cfg)
	tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts")
	if _, err := buildACMEChain(cfg, nil, testChallengeStore(t), nil, testLogger(), "node-test", fakeNodes{}); err == nil {
		t.Fatal("a corrupt existing account key must abort buildACMEChain")
	}
}

func testChallengeStore(t *testing.T) *acme.ChallengeStore {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	return acme.NewChallengeStore(rdb, acme.ChallengeTTL)
}

func TestBuildACMEChain_DNSProviderOnlyWhenUsed(t *testing.T) {
	tests := []struct {
		name     string
		le       string
		wantWarn bool
	}{
		{name: "no dns-01", le: config.ChallengeTLSALPN01, wantWarn: false},
		{name: "le dns-01", le: config.ChallengeDNS01, wantWarn: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			cfg := config.ServeCmd{
				ACMEAccountDir: t.TempDir(), ACMEDNSProvider: "no-such-provider", ACMEDirLE: "https://le.example.test/dir",
				ACMEChallengeLE: tc.le, ACMEChallengeGTS: config.ChallengeTLSALPN01, ACMEChallengeZeroSSL: config.ChallengeHTTP01,
			}
			tunneltest.LooseACMEBudgets(&cfg)
			tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts")
			if _, err := buildACMEChain(cfg, nil, testChallengeStore(t), nil, logger, "node-test", fakeNodes{}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(buf.String(), "acme dns provider unavailable"); got != tc.wantWarn {
				t.Fatalf("dns provider warning logged = %v, want %v; log = %q", got, tc.wantWarn, buf.String())
			}
		})
	}
}

func TestParseECPrivateKey_ReportsBothEncodings(t *testing.T) {
	_, err := parseECPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")}))
	if err == nil || !strings.Contains(err.Error(), "parse as SEC1") || !strings.Contains(err.Error(), "parse as PKCS#8") {
		t.Fatalf("an unparseable key must report both decode attempts, got %v", err)
	}
}

func enabledCAsConfig(t *testing.T) config.ServeCmd {
	t.Helper()
	cfg := config.ServeCmd{ACMEAccountDir: t.TempDir(), ACMEDirLE: "https://le.example.test/dir",
		ACMEGTSAccounts: []string{"gts-1", "gts-2"}, ACMEEABZeroSSLKID: "k", ACMEEABZeroSSLHMAC: "h"}
	tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts-1")
	tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts-2")
	return cfg
}

func TestACMELegoConfigs_EnabledCAs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.ServeCmd)
		want   []string
	}{
		{name: "every CA enabled", mutate: func(*config.ServeCmd) {},
			want: []string{"letsencrypt/local/false", "gts/gts-1/true", "gts/gts-2/true", "zerossl/local/false"}},
		{name: "empty LE directory", mutate: func(c *config.ServeCmd) { c.ACMEDirLE = "" },
			want: []string{"gts/gts-1/true", "gts/gts-2/true", "zerossl/local/false"}},
		{name: "no GTS account", mutate: func(c *config.ServeCmd) { c.ACMEGTSAccounts = nil },
			want: []string{"letsencrypt/local/false", "zerossl/local/false"}},
		{name: "no ZeroSSL EAB", mutate: func(c *config.ServeCmd) { c.ACMEEABZeroSSLKID, c.ACMEEABZeroSSLHMAC = "", "" },
			want: []string{"letsencrypt/local/false", "gts/gts-1/true", "gts/gts-2/true"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := enabledCAsConfig(t)
			tc.mutate(&cfg)
			cfgs, err := acmeLegoConfigs(cfg, testChallengeStore(t), testLogger(), "node-test")
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(cfgs))
			ids := map[string]bool{}
			for _, lc := range cfgs {
				got = append(got, fmt.Sprintf("%s/%s/%v", lc.CAID, lc.Label, lc.ResolveOnly))
				ids[lc.AccountID] = true
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("lego configs %v, want %v", got, tc.want)
			}
			if len(ids) != len(cfgs) {
				t.Fatalf("every account must have a distinct id, got %d ids for %d accounts", len(ids), len(cfgs))
			}
		})
	}
	t.Run("missing GTS key", func(t *testing.T) {
		cfg := enabledCAsConfig(t)
		path := filepath.Join(cfg.ACMEAccountDir, "accounts", "gts-2.key")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := acmeLegoConfigs(cfg, testChallengeStore(t), testLogger(), "node-test"); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("a missing GTS key must fail naming %s, got %v", path, err)
		}
	})
	t.Run("unparseable GTS key", func(t *testing.T) {
		cfg := enabledCAsConfig(t)
		path := filepath.Join(cfg.ACMEAccountDir, "accounts", "gts-2.key")
		junk := []byte("not a key")
		if err := os.WriteFile(path, junk, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := acmeLegoConfigs(cfg, testChallengeStore(t), testLogger(), "node-test")
		if err == nil || !strings.Contains(err.Error(), "exists but is unparseable") || !strings.Contains(err.Error(), path) {
			t.Fatalf("an unparseable GTS key must fail naming %s, got %v", path, err)
		}
		if after, rerr := os.ReadFile(path); rerr != nil || !bytes.Equal(after, junk) {
			t.Fatalf("an unparseable GTS key must be left untouched (read err %v)", rerr)
		}
	})
}

func TestAccountID(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := ca.KeyFingerprint(key1.Public())
	if err != nil {
		t.Fatal(err)
	}
	id1, err := accountID(acme.CAGTS, "node-a", key1)
	if err != nil {
		t.Fatal(err)
	}
	if want := "gts-" + strings.TrimPrefix(fp, "sha256:")[:16]; id1 != want {
		t.Fatalf("accountID = %q, want the fingerprint-derived %q", id1, want)
	}
	again, err := accountID(acme.CAGTS, "node-b", key1)
	if err != nil || again != id1 {
		t.Fatalf("the same key must give the same id on every node: %q vs %q (%v)", again, id1, err)
	}
	other, err := accountID(acme.CAGTS, "node-a", key2)
	if err != nil || other == id1 {
		t.Fatalf("a different key must give a different id: %q (%v)", other, err)
	}
	if eph, err := accountID(acme.CALetsEncrypt, "node-a", nil); err != nil || eph != "letsencrypt-ephemeral-node-a" {
		t.Fatalf("a nil key must give the node's ephemeral id, got %q (%v)", eph, err)
	}
}

func TestBudgetsFrom(t *testing.T) {
	cfg := config.ServeCmd{TunnelDomain: "Free.Example.Test"}
	tunneltest.LooseACMEBudgets(&cfg)
	cfg.ACMEBudgetLEDomain = "50/168h"
	cfg.ACMEBudgetZeroSSLOrders = "200/1h:40"
	b, err := budgetsFrom(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if b.Domain != "free.example.test" {
		t.Fatalf("Domain = %q, want the lower-cased tunnel domain", b.Domain)
	}
	if b.LEDomain != (limit.Rate{Count: 50, Period: 168 * time.Hour, Burst: 50}) ||
		b.ZeroSSLOrders != (limit.Rate{Count: 200, Period: time.Hour, Burst: 40}) ||
		b.GTSRequests != (limit.Rate{Count: 100000, Period: time.Minute, Burst: 100000}) {
		t.Fatalf("budgets = %+v, want the parsed flag rates", b)
	}
	for _, tc := range []struct {
		flag string
		dst  func(*config.ServeCmd) *string
	}{
		{"--acme-budget-le-domain", func(c *config.ServeCmd) *string { return &c.ACMEBudgetLEDomain }},
		{"--acme-budget-le-orders", func(c *config.ServeCmd) *string { return &c.ACMEBudgetLEOrders }},
		{"--acme-budget-le-name", func(c *config.ServeCmd) *string { return &c.ACMEBudgetLEName }},
		{"--acme-budget-gts-orders", func(c *config.ServeCmd) *string { return &c.ACMEBudgetGTSOrders }},
		{"--acme-budget-gts-requests", func(c *config.ServeCmd) *string { return &c.ACMEBudgetGTSRequests }},
		{"--acme-budget-gts-cert-polls", func(c *config.ServeCmd) *string { return &c.ACMEBudgetGTSCertPolls }},
		{"--acme-budget-zerossl-orders", func(c *config.ServeCmd) *string { return &c.ACMEBudgetZeroSSLOrders }},
		{"--acme-budget-zerossl-requests", func(c *config.ServeCmd) *string { return &c.ACMEBudgetZeroSSLRequests }},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			bad := cfg
			*tc.dst(&bad) = "bad"
			if _, err := budgetsFrom(bad); err == nil || !strings.HasPrefix(err.Error(), tc.flag+":") {
				t.Fatalf("a bad rate must name %s, got %v", tc.flag, err)
			}
		})
	}
}
