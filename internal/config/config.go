// Package config defines the tunneld `serve` command's flag surface (kong) and its validation.
// Every flag has an automatic TUNNELD_* env twin via kong.DefaultEnvars("TUNNELD") in main.
//
// Plan 3 (E2E) reworks this surface ADDITIVELY: the new families below are added while the Plan-1
// proxy/HTTP-inspection flags remain (their legacy consumers still compile) until the US13 teardown
// removes them together with those consumers. See docs/plans/3_e2e_encrypted_tunneling_*.md.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/logging"
	"github.com/redis/go-redis/v9"
)

// bandwidthFloorBytesPerSec is the minimum accepted --limit-bandwidth in bytes/sec. It MUST equal
// wire.ChunkSize (32*1024): the bandwidth bucket's burst is one second of rate and every caller
// acquires tokens in ≤ChunkSize slices, so a rate below one chunk would make every chunk acquisition
// error and silently break the whole data plane. The literal is duplicated here with this note
// rather than importing wire (avoids an import cycle).
const bandwidthFloorBytesPerSec int64 = 32 * 1024

// shortlivedLifetime is Let's Encrypt's fixed `shortlived` profile validity (160h). --acme-renew-margin
// must fit strictly inside it so a renewal is attempted before expiry.
const shortlivedLifetime = 160 * time.Hour

// ServeCmd is the configuration surface of `tunneld serve`. kong derives the TUNNELD_* env twin for
// every flag from its name (main.go: kong.DefaultEnvars("TUNNELD")).
type ServeCmd struct {
	// --- Edge / listeners ---
	Listen         string `name:"listen" default:":443" help:"Raw TCP public edge (SNI-routed); NOT behind a proxy."`
	InternalListen string `name:"internal-listen" default:":9090" help:"Metrics + /healthz + /admin listener; never proxied."`

	TunnelDomain string `name:"tunnel-domain" default:"example.test" help:"Base domain for <name>.<tunnel-domain> (one wildcard)."`
	EnrollHost   string `name:"enroll-host" default:"enroll.example.test" help:"Hostname carrying POST /enroll (name-independent)."`
	ControlHost  string `name:"control-host" default:"connect.example.test" help:"Hostname the phone dials for its HTTP/2 control connection (mTLS)."`
	NamePrefix   string `name:"name-prefix" default:"" help:"Optional prefix on generated tunnel names."`
	NameLength   int    `name:"name-length" default:"10" help:"Random base32 chars in a generated name."`

	// --- Mesh (replica↔replica) ---
	MeshListen    string        `name:"mesh-listen" default:":9443" help:"Replica↔replica HTTP/2 mesh listener (internal network only)."`
	MeshAdvertise string        `name:"mesh-advertise" help:"This node's mesh dial address announced in the node registry. Required for serve."`
	MeshPoolSize  int           `name:"mesh-pool-size" default:"4" help:"HTTP/2 connections per directed node pair."`
	MeshPoolMax   int           `name:"mesh-pool-max" default:"8" help:"Hard cap on pool growth when max-concurrent-streams is hit."`
	MeshCertTTL   time.Duration `name:"mesh-cert-ttl" default:"24h" help:"Lifetime of a node's self-issued mesh-role cert."`
	MaxClients    int           `name:"max-clients" default:"10000" help:"Per-node ceiling on ALL concurrent inbound connections (memory bound), enforced at the edge accept loop."`

	RedisURL string `name:"redis-url" default:"redis://localhost:6379/0" help:"Valkey/Redis connection URL (control plane)."`

	// --- Internal CA ---
	CACert       string        `name:"ca-cert" help:"Internal CA certificate (PEM). Required for serve."`
	CAKey        string        `name:"ca-key" help:"Internal CA private key (PEM). Required for serve."`
	CertValidity time.Duration `name:"cert-validity" default:"4380h" help:"Internal identity-cert lifetime (6 months)."`

	// --- S3 / MinIO durable store ---
	S3Endpoint       string `name:"s3-endpoint" help:"S3/MinIO endpoint URL. Required for serve."`
	S3Region         string `name:"s3-region" default:"us-east-1" help:"S3 region."`
	S3Bucket         string `name:"s3-bucket" help:"Bucket for the name registry + connection logs. Required for serve."`
	S3AccessKey      string `name:"s3-access-key" help:"S3 access key (secret). Required for serve."`
	S3SecretKey      string `name:"s3-secret-key" help:"S3 secret key (secret). Required for serve."`
	S3ForcePathStyle bool   `name:"s3-force-path-style" default:"true" help:"Path-style addressing (MinIO default)."`

	RegistryClaimTimeout time.Duration `name:"registry-claim-timeout" default:"3s" help:"Hard timeout on the name-claim PUT (SDK retries disabled; timeout = name abandoned)."`
	RegistryClaimSettle  time.Duration `name:"registry-claim-settle" default:"5s" help:"Settle wait before the claim-verify GET (MUST exceed the claim timeout)."`

	// --- Attestation ---
	AttestSignerDigestFile string        `name:"attest-signer-digest-file" help:"Hot-reload file of accepted app signing-cert SHA-256 digests. Required for serve."`
	AttestRootURL          string        `name:"attest-root-url" default:"https://android.googleapis.com/attestation/root" help:"Google attestation root-set endpoint."`
	AttestStatusURL        string        `name:"attest-status-url" default:"https://android.googleapis.com/attestation/status" help:"Google attestation revocation-status endpoint."`
	AttestRefresh          time.Duration `name:"attest-refresh" default:"1h" help:"Root-set + status refresh cadence."`
	AttestStatusMaxStale   time.Duration `name:"attest-status-max-stale" default:"24h" help:"Refuse enrollment if the status list is staler than this."`
	AttestationOptional    bool          `name:"attestation-optional" default:"false" help:"Accept a fixture chain (tests only); fail-closed in prod (see Validate)."`

	// --- ACME chain ---
	ACMEDirLE       string        `name:"acme-dir-le" default:"https://acme-v02.api.letsencrypt.org/directory" help:"LE ACME directory."`
	ACMEDirGTS      string        `name:"acme-dir-gts" default:"https://dv.acme-v02.api.pki.goog/directory" help:"GTS ACME directory."`
	ACMEDirZeroSSL  string        `name:"acme-dir-zerossl" default:"https://acme.zerossl.com/v2/DV90" help:"ZeroSSL ACME directory."`
	ACMEEmail       string        `name:"acme-email" help:"ACME account contact. Required for serve."`
	ACMELEProfile   string        `name:"acme-le-profile" default:"shortlived" help:"LE certificate profile."`
	ACMEGTSValidity time.Duration `name:"acme-gts-validity" default:"168h" help:"Requested GTS validity (7d)."`

	ACMEEABGTSKID      string `name:"acme-eab-gts-kid" default:"" help:"GTS EAB key id (secret)."`
	ACMEEABGTSHMAC     string `name:"acme-eab-gts-hmac" default:"" help:"GTS EAB HMAC key (secret)."`
	ACMEEABZeroSSLKID  string `name:"acme-eab-zerossl-kid" default:"" help:"ZeroSSL EAB key id (secret)."`
	ACMEEABZeroSSLHMAC string `name:"acme-eab-zerossl-hmac" default:"" help:"ZeroSSL EAB HMAC key (secret)."`
	ACMEAccountDir     string `name:"acme-account-dir" help:"Directory holding persisted per-CA ACME account keys + reserved-host self-certs. Required for serve."`
	ACMEDNSProvider    string `name:"acme-dns-provider" help:"lego DNS-01 provider id (e.g. cloudflare, route53). Required for serve."`

	// DNS-01 propagation pre-check tuning (split-horizon / internal-DNS deployments; also the hermetic
	// ACME test tier). Defaults preserve lego's standard behaviour: system resolvers + authoritative-NS
	// propagation required.
	ACMEDNSResolvers            []string `name:"acme-dns-resolver" help:"Recursive nameserver(s) host[:port] used for the DNS-01 propagation pre-check; empty uses the system resolvers. Repeatable. Set for split-horizon/internal DNS or a hermetic ACME test server."`
	ACMEDNSSkipPropagationCheck bool     `name:"acme-dns-skip-propagation-check" default:"false" help:"Skip the authoritative-nameserver DNS-01 propagation requirement (split-horizon/internal DNS, or a test ACME server that validates via its own resolver)."`

	ACMECooldownDefault time.Duration `name:"acme-cooldown-default" default:"1h" help:"Per-CA cooldown when a CA answers rate-limited WITHOUT a Retry-After (Retry-After wins when larger)."`
	ACMEBackoffInitial  time.Duration `name:"acme-backoff-initial" default:"1m" help:"First per-CA backoff after a non-rate-limit failure (doubles per consecutive failure)."`
	ACMEBackoffMax      time.Duration `name:"acme-backoff-max" default:"6h" help:"Ceiling for the exponential per-CA failure backoff."`
	ACMERenewMargin     time.Duration `name:"acme-renew-margin" default:"48h" help:"Renew floor before public-cert expiry (ARI may pull earlier)."`
	IssuePerWeek        int           `name:"issue-per-week" default:"3" help:"Max SUCCESSFUL public-cert issuances per tunnel per rolling 7d."`

	// --- Traffic / connection caps ---
	LimitTrafficDay      string        `name:"limit-traffic-day" default:"1gb" help:"Per-tunnel bytes/day, both directions combined (BINARY)."`
	LimitTrafficWeek     string        `name:"limit-traffic-week" default:"4gb" help:"Per-tunnel bytes/rolling-7d, both directions combined (BINARY)."`
	LimitConnRate        int           `name:"limit-conn-rate" default:"10" help:"New public TCP connections/sec per source IP."`
	LimitStreamPending   int           `name:"limit-stream-pending" default:"64" help:"Max concurrent pre-bind phone control handshakes per node."`
	LimitDialBackTimeout time.Duration `name:"limit-dialback-timeout" default:"10s" help:"Max wait for the phone to open the dial-back /data stream before failing the public connection and releasing its stream slot."`
	LimitConnIdle        time.Duration `name:"limit-conn-idle" default:"120s" help:"Close a public connection idle (no bytes either direction) this long."`
	LimitConnMinRate     string        `name:"limit-conn-min-rate" default:"2kb" help:"Min bytes per rolling 60s (past grace) before kill (BINARY)."`
	LimitConnMinGrace    time.Duration `name:"limit-conn-min-grace" default:"60s" help:"Grace before the min-rate rule applies."`
	LimitConnEvictIdle   time.Duration `name:"limit-conn-evict-idle" default:"10s" help:"A public connection idle ≥ this is evictable on saturation."`
	LimitConnProtectRate string        `name:"limit-conn-protect-rate" default:"256kb" help:"Rolling-60s byte floor that protects a connection from eviction (BINARY)."`
	HandshakeTimeout     time.Duration `name:"handshake-timeout" default:"10s" help:"Max time to read a complete ClientHello before closing (pre-TLS slowloris guard)."`
	ControlPingInterval  time.Duration `name:"control-ping-interval" default:"30s" help:"Control-stream application PING cadence."`

	RouteTTL time.Duration `name:"route-ttl" default:"30s" help:"Valkey routing-entry TTL; the control heartbeat refreshes it at route-ttl/3."`

	DBIPCountryLiteCSV string        `name:"dbip-country-lite-csv" default:"" help:"DB-IP Country Lite CSV for 'country' ban expansion (empty = geo off)."`
	BanFile            []string      `name:"ban-file" help:"Ban file(s); repeatable."`
	BanPoll            time.Duration `name:"ban-poll" default:"10s" help:"Ban/CSV mtime poll interval; also the signer-digest allowlist poll cadence."`

	LimitBandwidth    string `name:"limit-bandwidth" default:"1mbit" help:"Per-tunnel, per-direction rate; minimum 32768 B/s (~263kbit — DECIMAL bits, so 256kbit=32000 B/s is REJECTED)."`
	LimitConcurrent   int    `name:"limit-concurrent" default:"4" help:"Concurrent data streams per tunnel (global Valkey counter)."`
	LimitEnrollHour   int    `name:"limit-enroll-hour" default:"20" help:"Enrollments/hour per source IP."`
	LimitEnrollMinute int    `name:"limit-enroll-minute" default:"2" help:"Enrollments/minute per source IP."`
	LimitEnrollBody   string `name:"limit-enroll-body" default:"16kb" help:"Max enrollment (CSR) request body."`

	ShutdownGrace time.Duration `name:"shutdown-grace" default:"15s" help:"Graceful-drain deadline on ctx cancel."`

	Log []string `name:"log" default:"output=std;level=info" help:"Repeatable composite log sink (output=std|/path;level=…;format=…;maxsize=…;maxfiles=…)."`
}

// Validate is invoked automatically by kong for the selected `serve` command. It enforces every
// cross-field and parseability invariant the plan requires before server.Run is reached.
func (c ServeCmd) Validate() error {
	if c.NameLength < 6 || c.NameLength > 32 {
		return fmt.Errorf("--name-length must be in [6,32], got %d", c.NameLength)
	}
	if len(c.NamePrefix)+c.NameLength > 63 {
		return fmt.Errorf("--name-prefix + --name-length must be ≤ 63 (DNS label limit), got %d", len(c.NamePrefix)+c.NameLength)
	}
	if err := checkReadable("--ca-cert", c.CACert); err != nil {
		return err
	}
	if err := checkReadable("--ca-key", c.CAKey); err != nil {
		return err
	}
	if err := checkReadable("--attest-signer-digest-file", c.AttestSignerDigestFile); err != nil {
		return err
	}
	if c.TunnelDomain == "" || !strings.Contains(c.TunnelDomain, ".") {
		return fmt.Errorf("--tunnel-domain must be a dotted domain, got %q", c.TunnelDomain)
	}
	if c.EnrollHost == "" || !strings.Contains(c.EnrollHost, ".") {
		return fmt.Errorf("--enroll-host must be a dotted host, got %q", c.EnrollHost)
	}
	if c.ControlHost == "" || !strings.Contains(c.ControlHost, ".") {
		return fmt.Errorf("--control-host must be a dotted host, got %q", c.ControlHost)
	}
	if _, err := redis.ParseURL(c.RedisURL); err != nil {
		return fmt.Errorf("--redis-url is not parseable: %w", err)
	}
	for _, req := range []struct{ name, v string }{
		{"--mesh-advertise", c.MeshAdvertise},
		{"--s3-endpoint", c.S3Endpoint},
		{"--s3-bucket", c.S3Bucket},
		{"--s3-access-key", c.S3AccessKey},
		{"--s3-secret-key", c.S3SecretKey},
		{"--acme-email", c.ACMEEmail},
		{"--acme-account-dir", c.ACMEAccountDir},
		{"--acme-dns-provider", c.ACMEDNSProvider},
	} {
		if req.v == "" {
			return fmt.Errorf("%s is required for serve", req.name)
		}
	}
	for _, u := range []struct{ name, v string }{
		{"--acme-dir-le", c.ACMEDirLE},
		{"--acme-dir-gts", c.ACMEDirGTS},
		{"--acme-dir-zerossl", c.ACMEDirZeroSSL},
		{"--attest-root-url", c.AttestRootURL},
		{"--attest-status-url", c.AttestStatusURL},
	} {
		if !strings.HasPrefix(u.v, "http://") && !strings.HasPrefix(u.v, "https://") {
			return fmt.Errorf("%s must be an http(s) URL, got %q", u.name, u.v)
		}
	}
	if c.MeshPoolSize < 1 || c.MeshPoolSize > c.MeshPoolMax {
		return fmt.Errorf("--mesh-pool-size must be in [1, --mesh-pool-max=%d], got %d", c.MeshPoolMax, c.MeshPoolSize)
	}
	for _, r := range c.ACMEDNSResolvers {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("--acme-dns-resolver entries must be non-empty host[:port]")
		}
		if strings.Contains(r, ":") {
			if _, _, err := net.SplitHostPort(r); err != nil {
				return fmt.Errorf("--acme-dns-resolver %q must be host[:port]: %w", r, err)
			}
		}
	}
	for _, il := range []struct {
		name string
		v    int
	}{
		{"--max-clients", c.MaxClients},
		{"--limit-concurrent", c.LimitConcurrent},
		{"--limit-conn-rate", c.LimitConnRate},
		{"--limit-stream-pending", c.LimitStreamPending},
		{"--issue-per-week", c.IssuePerWeek},
		{"--limit-enroll-hour", c.LimitEnrollHour},
		{"--limit-enroll-minute", c.LimitEnrollMinute},
	} {
		if il.v < 1 {
			return fmt.Errorf("%s must be ≥ 1, got %d", il.name, il.v)
		}
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"--route-ttl", c.RouteTTL},
		{"--shutdown-grace", c.ShutdownGrace},
		{"--ban-poll", c.BanPoll},
		{"--cert-validity", c.CertValidity},
		{"--mesh-cert-ttl", c.MeshCertTTL},
		{"--registry-claim-timeout", c.RegistryClaimTimeout},
		{"--registry-claim-settle", c.RegistryClaimSettle},
		{"--attest-refresh", c.AttestRefresh},
		{"--attest-status-max-stale", c.AttestStatusMaxStale},
		{"--acme-cooldown-default", c.ACMECooldownDefault},
		{"--acme-backoff-initial", c.ACMEBackoffInitial},
		{"--acme-backoff-max", c.ACMEBackoffMax},
		{"--acme-renew-margin", c.ACMERenewMargin},
		{"--acme-gts-validity", c.ACMEGTSValidity},
		{"--limit-conn-idle", c.LimitConnIdle},
		{"--limit-conn-min-grace", c.LimitConnMinGrace},
		{"--limit-conn-evict-idle", c.LimitConnEvictIdle},
		{"--limit-dialback-timeout", c.LimitDialBackTimeout},
		{"--handshake-timeout", c.HandshakeTimeout},
		{"--control-ping-interval", c.ControlPingInterval},
	} {
		if d.v <= 0 {
			return fmt.Errorf("%s must be > 0, got %s", d.name, d.v)
		}
	}
	if c.RegistryClaimSettle <= c.RegistryClaimTimeout {
		return fmt.Errorf("--registry-claim-settle (%s) must exceed --registry-claim-timeout (%s): the write-verify claim relies on the settle wait outlasting the PUT deadline", c.RegistryClaimSettle, c.RegistryClaimTimeout)
	}
	if c.ACMEBackoffInitial > c.ACMEBackoffMax {
		return fmt.Errorf("--acme-backoff-initial (%s) must be ≤ --acme-backoff-max (%s)", c.ACMEBackoffInitial, c.ACMEBackoffMax)
	}
	if c.ACMERenewMargin >= shortlivedLifetime {
		return fmt.Errorf("--acme-renew-margin must be < %s (the LE shortlived lifetime), got %s", shortlivedLifetime, c.ACMERenewMargin)
	}
	bw, err := ParseBitrate(c.LimitBandwidth)
	if err != nil {
		return fmt.Errorf("--limit-bandwidth: %w", err)
	}
	if bw < bandwidthFloorBytesPerSec {
		return fmt.Errorf("--limit-bandwidth must be ≥ %d B/s (= wire.ChunkSize; note DECIMAL bits, 256kbit=32000 B/s fails), got %d B/s", bandwidthFloorBytesPerSec, bw)
	}
	var day, week int64
	for _, sz := range []struct {
		name string
		v    string
		out  *int64
	}{
		{"--limit-traffic-day", c.LimitTrafficDay, &day},
		{"--limit-traffic-week", c.LimitTrafficWeek, &week},
		{"--limit-conn-min-rate", c.LimitConnMinRate, nil},
		{"--limit-conn-protect-rate", c.LimitConnProtectRate, nil},
		{"--limit-enroll-body", c.LimitEnrollBody, nil},
	} {
		n, err := ParseByteSize(sz.v)
		if err != nil {
			return fmt.Errorf("%s: %w", sz.name, err)
		}
		if n < 1 {
			return fmt.Errorf("%s must be ≥ 1 byte, got %q", sz.name, sz.v)
		}
		if sz.out != nil {
			*sz.out = n
		}
	}
	if week < day {
		return fmt.Errorf("--limit-traffic-week (%d) must be ≥ --limit-traffic-day (%d)", week, day)
	}
	if c.AttestationOptional && os.Getenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL") != "1" {
		return fmt.Errorf("--attestation-optional is fail-closed: set TUNNELD_ALLOW_ATTESTATION_OPTIONAL=1 (tests only) to enable it; real deployments must never enable it")
	}
	if err := logging.ParseSpecs(c.Log); err != nil {
		return fmt.Errorf("--log: %w", err)
	}
	return nil
}

// checkReadable ensures a mandatory path flag is non-empty and the file exists (fail-fast). The
// authoritative read + parse happens later at startup; here we only reject an empty/missing path early.
func checkReadable(flag, path string) error {
	if path == "" {
		return fmt.Errorf("%s is required for serve", flag)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s is not accessible: %w", flag, err)
	}
	return nil
}
