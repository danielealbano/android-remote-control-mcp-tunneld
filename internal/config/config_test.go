package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

// validCfg returns a ServeCmd that passes the E2E Validate; individual tests copy and mutate one field.
func validCfg(t *testing.T) ServeCmd {
	t.Helper()
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca-key.pem")
	digest := filepath.Join(dir, "signers.txt")
	for _, f := range []string{cert, key, digest} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ServeCmd{
		Listen:                 ":443",
		InternalListen:         ":9090",
		TunnelDomain:           "example.test",
		EnrollHost:             "enroll.example.test",
		ControlHost:            "connect.example.test",
		NameLength:             10,
		MeshListen:             ":9443",
		MeshAdvertise:          "node-a:9443",
		MeshPoolSize:           4,
		MeshPoolMax:            8,
		MeshCertTTL:            24 * time.Hour,
		MaxClients:             10000,
		RedisURL:               "redis://localhost:6379/0",
		CACert:                 cert,
		CAKey:                  key,
		CertValidity:           4380 * time.Hour,
		S3Endpoint:             "http://localhost:9000",
		S3Region:               "us-east-1",
		S3Bucket:               "tunneld",
		S3AccessKey:            "access",
		S3SecretKey:            "secret",
		S3ForcePathStyle:       true,
		RegistryClaimTimeout:   3 * time.Second,
		RegistryClaimSettle:    5 * time.Second,
		AttestSignerDigestFile: digest,
		AttestRootURL:          "https://android.googleapis.com/attestation/root",
		AttestStatusURL:        "https://android.googleapis.com/attestation/status",
		AttestRefresh:          time.Hour,
		AttestStatusMaxStale:   24 * time.Hour,
		ACMEDirLE:              "https://acme-v02.api.letsencrypt.org/directory",
		ACMEDirGTS:             "https://dv.acme-v02.api.pki.goog/directory",
		ACMEDirZeroSSL:         "https://acme.zerossl.com/v2/DV90",
		ACMEEmail:              "ops@example.test",
		ACMELEProfile:          "shortlived",
		ACMEGTSValidity:        168 * time.Hour,
		ACMEAccountDir:         dir,
		ACMEDNSProvider:        "cloudflare",
		ACMECooldownDefault:    time.Hour,
		ACMEBackoffInitial:     time.Minute,
		ACMEBackoffMax:         6 * time.Hour,
		ACMERenewMargin:        48 * time.Hour,
		IssuePerWeek:           3,
		LimitTrafficDay:        "1gb",
		LimitTrafficWeek:       "4gb",
		LimitConnRate:          10,
		LimitStreamPending:     64,
		LimitConnIdle:          120 * time.Second,
		LimitConnMinRate:       "2kb",
		LimitConnMinGrace:      60 * time.Second,
		LimitConnEvictIdle:     10 * time.Second,
		LimitConnProtectRate:   "256kb",
		HandshakeTimeout:       10 * time.Second, LimitDialBackTimeout: 10 * time.Second,
		ControlPingInterval: 30 * time.Second,
		RouteTTL:            30 * time.Second,
		BanPoll:             10 * time.Second,
		LimitBandwidth:      "1mbit",
		LimitConcurrent:     4,
		LimitEnrollHour:     20,
		LimitEnrollMinute:   2,
		LimitEnrollBody:     "16kb",
		ShutdownGrace:       15 * time.Second,
		Log:                 []string{"output=std;level=info"},
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	if err := validCfg(t).Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateRejectsBadNameLength(t *testing.T) {
	for _, n := range []int{0, 5, 33, 64} {
		c := validCfg(t)
		c.NameLength = n
		if err := c.Validate(); err == nil {
			t.Errorf("name-length %d expected error", n)
		}
	}
}

func TestValidateRejectsOversizeLabel(t *testing.T) {
	c := validCfg(t)
	c.NamePrefix = string(make([]byte, 60)) // 60 + 10 > 63
	c.NameLength = 10
	if err := c.Validate(); err == nil {
		t.Error("prefix+name-length > 63 expected error")
	}
}

func TestValidateRejectsUnreadableCAPaths(t *testing.T) {
	c := validCfg(t)
	c.CACert = ""
	if err := c.Validate(); err == nil {
		t.Error("empty --ca-cert expected error")
	}
	c = validCfg(t)
	c.CAKey = filepath.Join(t.TempDir(), "does-not-exist.pem")
	if err := c.Validate(); err == nil {
		t.Error("missing --ca-key file expected error")
	}
}

func TestValidateRequiresAttestSignerDigestFile(t *testing.T) {
	c := validCfg(t)
	c.AttestSignerDigestFile = ""
	if err := c.Validate(); err == nil {
		t.Error("empty --attest-signer-digest-file expected error")
	}
	c = validCfg(t)
	c.AttestSignerDigestFile = filepath.Join(t.TempDir(), "nope.txt")
	if err := c.Validate(); err == nil {
		t.Error("unreadable --attest-signer-digest-file expected error")
	}
}

func TestValidateRequiresS3Fields(t *testing.T) {
	for _, mut := range []func(*ServeCmd){
		func(c *ServeCmd) { c.S3Endpoint = "" },
		func(c *ServeCmd) { c.S3Bucket = "" },
		func(c *ServeCmd) { c.S3AccessKey = "" },
		func(c *ServeCmd) { c.S3SecretKey = "" },
	} {
		c := validCfg(t)
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Error("empty required S3 field expected error")
		}
	}
}

func TestValidateRequiresMeshACMEFields(t *testing.T) {
	for _, mut := range []func(*ServeCmd){
		func(c *ServeCmd) { c.MeshAdvertise = "" },
		func(c *ServeCmd) { c.ACMEEmail = "" },
		func(c *ServeCmd) { c.ACMEAccountDir = "" },
		func(c *ServeCmd) { c.ACMEDNSProvider = "" },
	} {
		c := validCfg(t)
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Error("empty required mesh/acme field expected error")
		}
	}
}

func TestValidateMeshPoolSizeRange(t *testing.T) {
	c := validCfg(t)
	c.MeshPoolSize = 0
	if err := c.Validate(); err == nil {
		t.Error("--mesh-pool-size 0 expected error")
	}
	c = validCfg(t)
	c.MeshPoolSize = c.MeshPoolMax + 1
	if err := c.Validate(); err == nil {
		t.Error("--mesh-pool-size > max expected error")
	}
}

func TestValidateTrafficWeekGEDay(t *testing.T) {
	c := validCfg(t)
	c.LimitTrafficWeek = "512mb"
	c.LimitTrafficDay = "1gb"
	if err := c.Validate(); err == nil {
		t.Error("week < day expected error")
	}
}

func TestValidateRenewMarginFitsShortlived(t *testing.T) {
	c := validCfg(t)
	c.ACMERenewMargin = 200 * time.Hour
	if err := c.Validate(); err == nil {
		t.Error("--acme-renew-margin 200h expected error (>= 160h)")
	}
}

func TestValidateRegistrySettleGreaterThanTimeout(t *testing.T) {
	c := validCfg(t)
	c.RegistryClaimSettle = 2 * time.Second
	c.RegistryClaimTimeout = 3 * time.Second
	if err := c.Validate(); err == nil {
		t.Error("settle <= timeout expected error")
	}
	if err := validCfg(t).Validate(); err != nil {
		t.Errorf("default settle > timeout expected pass, got %v", err)
	}
}

func TestValidateAttestationOptionalFailClosed(t *testing.T) {
	c := validCfg(t)
	c.AttestationOptional = true
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "")
	if err := c.Validate(); err == nil {
		t.Error("--attestation-optional without sentinel expected error")
	}
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")
	if err := c.Validate(); err != nil {
		t.Errorf("--attestation-optional with sentinel expected pass, got %v", err)
	}
}

func TestValidateRequiresBandwidthFloor(t *testing.T) {
	for _, bw := range []string{"128kbit", "256kbit"} {
		c := validCfg(t)
		c.LimitBandwidth = bw
		if err := c.Validate(); err == nil {
			t.Errorf("--limit-bandwidth %s expected error (below floor)", bw)
		}
	}
	for _, bw := range []string{"300kbit", "1mbit"} {
		c := validCfg(t)
		c.LimitBandwidth = bw
		if err := c.Validate(); err != nil {
			t.Errorf("--limit-bandwidth %s expected pass, got %v", bw, err)
		}
	}
}

func TestValidateRejectsZeroIntegerLimits(t *testing.T) {
	mut := []func(*ServeCmd){
		func(c *ServeCmd) { c.MaxClients = 0 },
		func(c *ServeCmd) { c.LimitConcurrent = 0 },
		func(c *ServeCmd) { c.LimitConnRate = 0 },
		func(c *ServeCmd) { c.IssuePerWeek = 0 },
		func(c *ServeCmd) { c.LimitStreamPending = 0 },
	}
	for i, m := range mut {
		c := validCfg(t)
		m(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: zero integer limit expected error", i)
		}
	}
}

func TestValidateRejectsBadRedisLimitsLog(t *testing.T) {
	c := validCfg(t)
	c.RedisURL = "://not-a-url"
	if err := c.Validate(); err == nil {
		t.Error("unparseable --redis-url expected error")
	}
	c = validCfg(t)
	c.LimitTrafficDay = "bogus"
	if err := c.Validate(); err == nil {
		t.Error("bad --limit-traffic-day expected error")
	}
	c = validCfg(t)
	c.Log = []string{"output=std;level=nonsense"}
	if err := c.Validate(); err == nil {
		t.Error("bad --log spec expected error")
	}
}

func TestValidate_DurationLowerBounds(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ServeCmd)
	}{
		{"control-ping-interval zero", func(c *ServeCmd) { c.ControlPingInterval = 0 }},
		{"handshake-timeout negative", func(c *ServeCmd) { c.HandshakeTimeout = -time.Second }},
		{"ban-poll zero", func(c *ServeCmd) { c.BanPoll = 0 }},
		{"cert-validity zero", func(c *ServeCmd) { c.CertValidity = 0 }},
		{"mesh-cert-ttl negative", func(c *ServeCmd) { c.MeshCertTTL = -time.Hour }},
		{"attest-refresh zero", func(c *ServeCmd) { c.AttestRefresh = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCfg(t)
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
		})
	}
}

func TestValidate_ZeroSizeRejected(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ServeCmd)
	}{
		{"limit-traffic-day", func(c *ServeCmd) { c.LimitTrafficDay = "0b" }},
		{"limit-conn-min-rate", func(c *ServeCmd) { c.LimitConnMinRate = "0" }},
		{"limit-conn-protect-rate", func(c *ServeCmd) { c.LimitConnProtectRate = "0b" }},
		{"limit-enroll-body", func(c *ServeCmd) { c.LimitEnrollBody = "0b" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCfg(t)
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s=0 expected error", tc.name)
			}
		})
	}
}

func TestValidate_HostAndDomain(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ServeCmd)
	}{
		{"empty domain", func(c *ServeCmd) { c.TunnelDomain = "" }},
		{"dotless domain", func(c *ServeCmd) { c.TunnelDomain = "example" }},
		{"empty enroll host", func(c *ServeCmd) { c.EnrollHost = "" }},
		{"dotless enroll host", func(c *ServeCmd) { c.EnrollHost = "enroll" }},
		{"empty control host", func(c *ServeCmd) { c.ControlHost = "" }},
		{"dotless control host", func(c *ServeCmd) { c.ControlHost = "connect" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCfg(t)
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("%s expected error", tc.name)
			}
		})
	}
}

func TestParseByteSize_Overflow(t *testing.T) {
	for _, in := range []string{"9223372036854775807kb", "9999999999999gb"} {
		if _, err := ParseByteSize(in); err == nil {
			t.Errorf("ParseByteSize(%q) expected overflow error", in)
		}
	}
}

func TestParseBitrate_Overflow(t *testing.T) {
	for _, in := range []string{"9223372036854775807kbit", "99999999999gbit"} {
		if _, err := ParseBitrate(in); err == nil {
			t.Errorf("ParseBitrate(%q) expected overflow error", in)
		}
	}
}

// TestEnvTwinOverridesFlag exercises one env twin per kong type category (DefaultEnvars): int, size
// string, duration, repeatable []string, plain string — backing the "every flag has a twin" AC. The
// full required-for-serve set is supplied via env so kong's automatic Validate passes on parse.
func TestEnvTwinOverridesFlag(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca-key.pem")
	digest := filepath.Join(dir, "signers.txt")
	for _, f := range []string{cert, key, digest} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Required-for-serve flags (no defaults) supplied via their env twins.
	t.Setenv("TUNNELD_CA_CERT", cert)
	t.Setenv("TUNNELD_CA_KEY", key)
	t.Setenv("TUNNELD_ATTEST_SIGNER_DIGEST_FILE", digest)
	t.Setenv("TUNNELD_MESH_ADVERTISE", "node-a:9443")
	// kong inserts an underscore at the letter→digit boundary, so --s3-* twins are TUNNELD_S_3_*.
	t.Setenv("TUNNELD_S_3_ENDPOINT", "http://localhost:9000")
	t.Setenv("TUNNELD_S_3_ACCESS_KEY", "access")
	t.Setenv("TUNNELD_S_3_SECRET_KEY", "secret")
	t.Setenv("TUNNELD_ACME_EMAIL", "ops@example.test")
	t.Setenv("TUNNELD_ACME_ACCOUNT_DIR", dir)
	// Overrides under test (one per kong type category):
	t.Setenv("TUNNELD_MAX_CLIENTS", "42")            // int twin
	t.Setenv("TUNNELD_S_3_BUCKET", "envbucket")      // plain string twin (digit-boundary env name)
	t.Setenv("TUNNELD_LIMIT_TRAFFIC_DAY", "2gb")     // size string twin
	t.Setenv("TUNNELD_CONTROL_PING_INTERVAL", "45s") // duration twin
	t.Setenv("TUNNELD_ACME_DNS_PROVIDER", "route53") // plain string twin
	t.Setenv("TUNNELD_LOG", "output=std;level=warn") // repeatable []string twin

	var cli struct {
		Serve ServeCmd `cmd:""`
	}
	parser, err := kong.New(&cli, kong.Name("tunneld"), kong.DefaultEnvars("TUNNELD"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"serve"}); err != nil {
		t.Fatalf("parse with env twins failed: %v", err)
	}
	if cli.Serve.MaxClients != 42 {
		t.Errorf("max-clients twin = %d", cli.Serve.MaxClients)
	}
	if cli.Serve.S3Bucket != "envbucket" {
		t.Errorf("s3-bucket twin = %q", cli.Serve.S3Bucket)
	}
	if cli.Serve.LimitTrafficDay != "2gb" {
		t.Errorf("limit-traffic-day twin = %q", cli.Serve.LimitTrafficDay)
	}
	if cli.Serve.ControlPingInterval != 45*time.Second {
		t.Errorf("control-ping-interval twin = %s", cli.Serve.ControlPingInterval)
	}
	if cli.Serve.ACMEDNSProvider != "route53" {
		t.Errorf("acme-dns-provider twin = %q", cli.Serve.ACMEDNSProvider)
	}
	if len(cli.Serve.Log) != 1 || cli.Serve.Log[0] != "output=std;level=warn" {
		t.Errorf("log twin = %v", cli.Serve.Log)
	}
}

// TestRemovedLegacyFlagsRejected asserts the legacy pre-E2E flags removed in the E2E rework are no longer
// accepted (parsing them yields an unknown-flag error).
func TestRemovedLegacyFlagsRejected(t *testing.T) {
	for _, flag := range []string{
		"--client-ip-header=X-Real-Ip", "--limit-body=1mb", "--limit-rps=10", "--ping-interval=30s",
		"--limit-request-timeout=60s", "--connect-auth-timeout=5s", "--limit-connect-pending=64",
	} {
		var cli struct {
			Serve ServeCmd `cmd:""`
		}
		parser, err := kong.New(&cli, kong.Name("tunneld"), kong.DefaultEnvars("TUNNELD"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse([]string{"serve", flag}); err == nil {
			t.Errorf("removed flag %q must be rejected as unknown", flag)
		}
	}
}
