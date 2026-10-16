// Package config defines the tunneld `serve` command's flag surface (kong) and its validation.
// Every flag has an automatic TUNNELD_* env twin via kong.DefaultEnvars("TUNNELD") in main; Validate()
// enforces every cross-field invariant fail-fast at startup. See docs/ARCHITECTURE.md §10.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/logging"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// bandwidthFloorBytesPerSec is the minimum accepted --limit-bandwidth in bytes/sec. It MUST equal
// wire.ChunkSize (16*1024): each read charges up to one slice against the per-second byte window, so a
// rate below one slice would make a single read exceed the whole second's budget and throttle every
// read (the tunnel could never forward more than one slice per second).
const bandwidthFloorBytesPerSec int64 = wire.ChunkSize

// shortlivedLifetime is Let's Encrypt's fixed `shortlived` profile validity (160h). --acme-renew-margin
// must fit strictly inside it so a renewal is attempted before expiry.
const shortlivedLifetime = 160 * time.Hour

const (
	ChallengeDNS01     = "dns-01"
	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
)

// ServeCmd is the configuration surface of `tunneld serve`. kong derives the TUNNELD_* env twin for
// every flag from its name (main.go: kong.DefaultEnvars("TUNNELD")).
type ServeCmd struct {
	// --- Edge / listeners ---
	Listen         string `name:"listen" default:":443" help:"Raw TCP public edge (SNI-routed); NOT behind a proxy."`
	InternalListen string `name:"internal-listen" default:":9090" help:"Metrics + /healthz + /admin listener; never proxied."`

	TunnelDomain string `name:"tunnel-domain" default:"example.test" help:"Base domain for <name>.<tunnel-domain> (one wildcard)."`
	EnrollHost   string `name:"enroll-host" default:"enroll.example.test" help:"Hostname carrying POST /api/v1/enroll (name-independent)."`
	ControlHost  string `name:"control-host" default:"connect.example.test" help:"Hostname the phone dials for its HTTP/2 control connection (mTLS)."`
	NamePrefix   string `name:"name-prefix" default:"" help:"Optional prefix on generated tunnel names."`
	NameLength   int    `name:"name-length" default:"10" help:"Random base32 chars in a generated name."`

	DialBackAdvertise string `name:"dialback-advertise" help:"host:port the phone dials back to on THIS node for a public connection that entered here (this node's own public address, never a round-robin name): its TLS edge (--listen) with --dialback-https, its plain listener (--acme-http-listen) without. Required for serve."`
	DialBackHTTPS     bool   `name:"dialback-https" default:"true" help:"Phones dial back over TLS (SNI --control-host). false: plain TCP to the --acme-http-listen listener, authorised by the one-time token only."`
	DialBackMTLS      bool   `name:"dialback-mtls" default:"true" help:"Phones present their identity client certificate on every dial-back. Requires --dialback-https."`

	// --- Mesh (replica↔replica) ---
	MeshListen    string        `name:"mesh-listen" default:":9443" help:"Replica↔replica HTTP/2 mesh listener (internal network only)."`
	MeshAdvertise string        `name:"mesh-advertise" help:"This node's mesh dial address announced in the node registry. Required for serve."`
	MeshPoolSize  int           `name:"mesh-pool-size" default:"4" help:"HTTP/2 connections per directed node pair."`
	MeshCertTTL   time.Duration `name:"mesh-cert-ttl" default:"24h" help:"Lifetime of a node's self-issued mesh-role cert."`
	MaxClients    int           `name:"max-clients" default:"10000" help:"Per-node ceiling on ALL concurrent inbound connections (memory bound), enforced at the edge accept loop."`

	RedisURL string `name:"redis-url" default:"redis://localhost:6379/0" help:"Valkey/Redis connection URL (control plane). A master_name= query parameter selects Valkey Sentinel: the URL host and repeated addr= are the sentinels, the URL user:password authenticates to the sentinels, and username= / password= authenticate to the master."`

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

	ConnLogDir string `name:"conn-log-dir" help:"Connection-log spool directory on a persistent volume: events are appended locally, uploaded to S3 as per-node 5-minute JSONL objects, then deleted. Required for serve."`

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
	ACMEDirLE       string        `name:"acme-dir-le" default:"https://acme-v02.api.letsencrypt.org/directory" help:"LE ACME directory; empty leaves Let's Encrypt out of the chain."`
	ACMEDirGTS      string        `name:"acme-dir-gts" default:"https://dv.acme-v02.api.pki.goog/directory" help:"GTS ACME directory."`
	ACMEDirZeroSSL  string        `name:"acme-dir-zerossl" default:"https://acme.zerossl.com/v2/DV90" help:"ZeroSSL ACME directory."`
	ACMEEmail       string        `name:"acme-email" help:"ACME account contact. Required for serve."`
	ACMELEProfile   string        `name:"acme-le-profile" default:"shortlived" help:"LE certificate profile."`
	ACMEGTSValidity time.Duration `name:"acme-gts-validity" default:"168h" help:"Requested GTS validity (7d)."`

	ACMEEABZeroSSLKID  string `name:"acme-eab-zerossl-kid" default:"" help:"ZeroSSL EAB key id (secret)."`
	ACMEEABZeroSSLHMAC string `name:"acme-eab-zerossl-hmac" default:"" help:"ZeroSSL EAB HMAC key (secret)."`
	ACMEAccountDir     string `name:"acme-account-dir" help:"Directory holding the ACME account keys (<dir>/accounts/<id>.key: Let's Encrypt and ZeroSSL keys are created per node, GTS keys must already exist) + reserved-host self-certs. Required for serve."`
	ACMEDNSProvider    string `name:"acme-dns-provider" help:"lego DNS-01 provider id (e.g. cloudflare, route53). Required when a CA uses dns-01."`

	ACMEGTSAccounts []string `name:"acme-gts-account" help:"GTS ACME account ids, one per Public CA project (empty = no GTS); each EXISTING account's EC private key (PEM, SEC1 or PKCS#8) lives at <acme-account-dir>/accounts/<id>.key (tunneld never creates GTS accounts). Repeatable."`

	ACMEBudgetLEDomain        string `name:"acme-budget-le-domain" default:"50/168h" help:"Let's Encrypt new certificates per registered domain, <count>/<period>[:<burst>]."`
	ACMEBudgetLEOrders        string `name:"acme-budget-le-orders" default:"300/3h" help:"Let's Encrypt new orders per account, <count>/<period>[:<burst>]."`
	ACMEBudgetLEName          string `name:"acme-budget-le-name" default:"5/168h" help:"Let's Encrypt certificates per exact name, <count>/<period>[:<burst>]."`
	ACMEBudgetGTSOrders       string `name:"acme-budget-gts-orders" default:"100/1h" help:"GTS new orders per account, <count>/<period>[:<burst>]."`
	ACMEBudgetGTSRequests     string `name:"acme-budget-gts-requests" default:"120/1m" help:"GTS ACME requests per account, <count>/<period>[:<burst>]."`
	ACMEBudgetGTSCertPolls    string `name:"acme-budget-gts-cert-polls" default:"50/1m" help:"GTS requests to /cert/ URLs per account (within the request budget), <count>/<period>[:<burst>]."`
	ACMEBudgetZeroSSLOrders   string `name:"acme-budget-zerossl-orders" default:"200/1h:40" help:"ZeroSSL new orders per account, <count>/<period>[:<burst>]."`
	ACMEBudgetZeroSSLRequests string `name:"acme-budget-zerossl-requests" default:"240/1m" help:"ZeroSSL ACME requests per account, <count>/<period>[:<burst>]."`

	ACMEAttemptTimeoutLE      time.Duration `name:"acme-attempt-timeout-le" default:"20s" help:"Deadline of one Let's Encrypt order attempt."`
	ACMEAttemptTimeoutGTS     time.Duration `name:"acme-attempt-timeout-gts" default:"40s" help:"Deadline of one GTS order attempt."`
	ACMEAttemptTimeoutZeroSSL time.Duration `name:"acme-attempt-timeout-zerossl" default:"90s" help:"Deadline of one ZeroSSL order attempt."`
	ACMEPollFirstLE           time.Duration `name:"acme-poll-first-le" default:"2s" help:"Delay of the first certificate poll after a Let's Encrypt order is finalized."`
	ACMEPollFirstGTS          time.Duration `name:"acme-poll-first-gts" default:"5.6s" help:"Delay of the first certificate poll after a GTS order is finalized."`
	ACMEPollFirstZeroSSL      time.Duration `name:"acme-poll-first-zerossl" default:"15.2s" help:"Delay of the first certificate poll after a ZeroSSL order is finalized."`
	ACMEPollInterval          time.Duration `name:"acme-poll-interval" default:"2s" help:"Spacing of the following certificate polls."`

	ACMEChallengeLE      string `name:"acme-challenge-le" default:"tls-alpn-01" enum:"dns-01,http-01,tls-alpn-01" help:"Let's Encrypt validation method: dns-01 | http-01 | tls-alpn-01."`
	ACMEChallengeGTS     string `name:"acme-challenge-gts" default:"tls-alpn-01" enum:"dns-01,http-01,tls-alpn-01" help:"Google Trust Services validation method: dns-01 | http-01 | tls-alpn-01."`
	ACMEChallengeZeroSSL string `name:"acme-challenge-zerossl" default:"http-01" enum:"dns-01,http-01" help:"ZeroSSL validation method: dns-01 | http-01 (ZeroSSL has no tls-alpn-01)."`
	ACMEHTTPListen       string `name:"acme-http-listen" default:":80" help:"Public plain-HTTP listener: ACME HTTP-01 answers and, with --dialback-https=false, phone dial-backs. Bound only when one of them is in use."`

	// DNS-01 propagation pre-check tuning (split-horizon / internal-DNS deployments; also the hermetic
	// ACME test tier).
	ACMEDNSResolvers            []string `name:"acme-dns-resolver" help:"Recursive nameserver(s) host[:port] used for the DNS-01 propagation pre-check; empty uses the system resolvers. Repeatable. Set for split-horizon/internal DNS or a hermetic ACME test server."`
	ACMEDNSSkipPropagationCheck bool     `name:"acme-dns-skip-propagation-check" default:"false" help:"Skip the authoritative-nameserver DNS-01 propagation requirement (split-horizon/internal DNS, or a test ACME server that validates via its own resolver)."`

	ACMECooldownDefault time.Duration `name:"acme-cooldown-default" default:"1h" help:"Per-account cooldown when a CA answers rate-limited WITHOUT a Retry-After header."`
	ACMEBackoffInitial  time.Duration `name:"acme-backoff-initial" default:"1m" help:"First per-account backoff after a non-rate-limit failure (doubles per consecutive failure)."`
	ACMEBackoffMax      time.Duration `name:"acme-backoff-max" default:"6h" help:"Ceiling for the exponential per-account failure backoff."`
	ACMERenewMargin     time.Duration `name:"acme-renew-margin" default:"48h" help:"Renew floor before public-cert expiry (LE renews at NotAfter minus this)."`
	IssuePerWeek        int           `name:"issue-per-week" default:"3" help:"Max SUCCESSFUL public-cert issuances per tunnel per 7d window (anchored at the first issuance)."`

	// --- Traffic / connection caps ---
	LimitTrafficDay      string        `name:"limit-traffic-day" default:"1gb" help:"Per-tunnel bytes per 24h window (UTC-aligned), per direction (BINARY)."`
	LimitTrafficWeek     string        `name:"limit-traffic-week" default:"4gb" help:"Per-tunnel bytes per 7d window (epoch-aligned), per direction (BINARY)."`
	LimitConnRate        int           `name:"limit-conn-rate" default:"10" help:"New public TCP connections/sec per source IP."`
	LimitStreamPending   int           `name:"limit-stream-pending" default:"64" help:"Max concurrent pre-bind phone control handshakes per node."`
	LimitDialBackTimeout time.Duration `name:"limit-dialback-timeout" default:"10s" help:"Max wait for the phone to open the dial-back /api/v1/data stream before failing the public connection and releasing its stream slot."`
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

	LimitBandwidth    string `name:"limit-bandwidth" default:"1mbit" help:"Per-tunnel, per-direction rate; minimum 16384 B/s (~131kbit — DECIMAL bits, so 128kbit=16000 B/s is REJECTED)."`
	LimitPackets      int    `name:"limit-packets" default:"100" help:"Max reads (packets) per second per tunnel per direction — a loose backstop against tiny-packet floods; the byte rate is the primary limit."`
	LimitConcurrent   int    `name:"limit-concurrent" default:"4" help:"Concurrent data streams per tunnel (global Valkey counter)."`
	LimitEnrollHour   int    `name:"limit-enroll-hour" default:"20" help:"Enrollments/hour per source IP."`
	LimitEnrollMinute int    `name:"limit-enroll-minute" default:"2" help:"Enrollments/minute per source IP."`
	LimitEnrollBody   string `name:"limit-enroll-body" default:"16kb" help:"Max enrollment (CSR) request body."`

	ShutdownGrace time.Duration `name:"shutdown-grace" default:"15s" help:"Graceful-drain deadline on ctx cancel."`

	Log []string `name:"log" default:"output=std;level=info" help:"Repeatable composite log sink (output=std|/path;level=…;format=…;maxsize=…;maxfiles=…)."`
}

func (c ServeCmd) LEEnabled() bool  { return c.ACMEDirLE != "" }
func (c ServeCmd) GTSEnabled() bool { return len(c.ACMEGTSAccounts) > 0 }
func (c ServeCmd) ZeroSSLEnabled() bool {
	return c.ACMEEABZeroSSLKID != "" && c.ACMEEABZeroSSLHMAC != ""
}

func (c ServeCmd) UsesChallenge(method string) bool {
	return (c.LEEnabled() && c.ACMEChallengeLE == method) ||
		(c.GTSEnabled() && c.ACMEChallengeGTS == method) ||
		(c.ZeroSSLEnabled() && c.ACMEChallengeZeroSSL == method)
}

func (c ServeCmd) ServesPlainHTTP() bool {
	return c.UsesChallenge(ChallengeHTTP01) || !c.DialBackHTTPS
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
	// The prefix is lowercased at runtime (server.Run) so it matches the lowercased SNI at the edge; a
	// non-DNS-label character would otherwise fail late at ACME issuance. Validate case-insensitively.
	for _, r := range strings.ToLower(c.NamePrefix) {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("--name-prefix must be [a-z0-9-] only, got %q", c.NamePrefix)
		}
	}
	if strings.HasPrefix(c.NamePrefix, "-") {
		return fmt.Errorf("--name-prefix must not start with '-', got %q", c.NamePrefix)
	}
	for _, a := range []struct{ name, v string }{
		{"--listen", c.Listen}, {"--mesh-listen", c.MeshListen}, {"--internal-listen", c.InternalListen},
	} {
		if _, _, err := net.SplitHostPort(a.v); err != nil {
			return fmt.Errorf("%s must be host:port or :port, got %q: %w", a.name, a.v, err)
		}
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
	if strings.EqualFold(c.EnrollHost, c.ControlHost) {
		return fmt.Errorf("--enroll-host and --control-host must differ (SNI dispatch would hide the control plane), both %q", c.EnrollHost)
	}
	if _, err := ParseRedisURL(c.RedisURL); err != nil {
		return err
	}
	for _, req := range []struct{ name, v string }{
		{"--mesh-advertise", c.MeshAdvertise},
		{"--s3-endpoint", c.S3Endpoint},
		{"--s3-bucket", c.S3Bucket},
		{"--s3-access-key", c.S3AccessKey},
		{"--s3-secret-key", c.S3SecretKey},
		{"--acme-email", c.ACMEEmail},
		{"--acme-account-dir", c.ACMEAccountDir},
		{"--conn-log-dir", c.ConnLogDir},
		{"--dialback-advertise", c.DialBackAdvertise},
	} {
		if req.v == "" {
			return fmt.Errorf("%s is required for serve", req.name)
		}
	}
	host, port, err := net.SplitHostPort(c.DialBackAdvertise)
	if err != nil {
		return fmt.Errorf("--dialback-advertise must be host:port, got %q: %w", c.DialBackAdvertise, err)
	}
	if host == "" {
		return fmt.Errorf("--dialback-advertise needs a host (this node's own public address), got %q", c.DialBackAdvertise)
	}
	if p, perr := strconv.Atoi(port); perr != nil {
		return fmt.Errorf("--dialback-advertise port %q: %w", port, perr)
	} else if p < 1 || p > 65535 {
		return fmt.Errorf("--dialback-advertise port must be 1-65535, got %d", p)
	}
	if c.DialBackMTLS && !c.DialBackHTTPS {
		return errors.New("--dialback-mtls requires --dialback-https: a plain dial-back carries no client certificate")
	}
	if fi, err := os.Stat(c.ConnLogDir); err == nil && !fi.IsDir() {
		return fmt.Errorf("--conn-log-dir %q is not a directory", c.ConnLogDir)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("--conn-log-dir %q: %w", c.ConnLogDir, err)
	}
	for _, ch := range []struct {
		name, method string
		allowALPN    bool
	}{
		{"--acme-challenge-le", c.ACMEChallengeLE, true},
		{"--acme-challenge-gts", c.ACMEChallengeGTS, true},
		{"--acme-challenge-zerossl", c.ACMEChallengeZeroSSL, false},
	} {
		if ch.method != ChallengeDNS01 && ch.method != ChallengeHTTP01 && (!ch.allowALPN || ch.method != ChallengeTLSALPN01) {
			return fmt.Errorf("%s does not support validation method %q", ch.name, ch.method)
		}
	}
	if c.UsesChallenge(ChallengeDNS01) && c.ACMEDNSProvider == "" {
		return fmt.Errorf("--acme-dns-provider is required when a CA uses dns-01")
	}
	if c.ServesPlainHTTP() {
		if _, _, err := net.SplitHostPort(c.ACMEHTTPListen); err != nil {
			return fmt.Errorf("--acme-http-listen must be host:port or :port, got %q: %w", c.ACMEHTTPListen, err)
		}
	}
	urls := []struct{ name, v string }{
		{"--acme-dir-gts", c.ACMEDirGTS},
		{"--acme-dir-zerossl", c.ACMEDirZeroSSL},
		{"--attest-root-url", c.AttestRootURL},
		{"--attest-status-url", c.AttestStatusURL},
		{"--s3-endpoint", c.S3Endpoint},
	}
	if c.LEEnabled() {
		urls = append(urls, struct{ name, v string }{"--acme-dir-le", c.ACMEDirLE})
	}
	for _, u := range urls {
		if !strings.HasPrefix(u.v, "http://") && !strings.HasPrefix(u.v, "https://") {
			return fmt.Errorf("%s must be an http(s) URL, got %q", u.name, u.v)
		}
	}
	if c.MeshPoolSize < 1 {
		return fmt.Errorf("--mesh-pool-size must be ≥ 1, got %d", c.MeshPoolSize)
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
		{"--limit-packets", c.LimitPackets},
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
		{"--acme-attempt-timeout-le", c.ACMEAttemptTimeoutLE},
		{"--acme-attempt-timeout-gts", c.ACMEAttemptTimeoutGTS},
		{"--acme-attempt-timeout-zerossl", c.ACMEAttemptTimeoutZeroSSL},
		{"--acme-poll-first-le", c.ACMEPollFirstLE},
		{"--acme-poll-first-gts", c.ACMEPollFirstGTS},
		{"--acme-poll-first-zerossl", c.ACMEPollFirstZeroSSL},
		{"--acme-poll-interval", c.ACMEPollInterval},
	} {
		if d.v <= 0 {
			return fmt.Errorf("%s must be > 0, got %s", d.name, d.v)
		}
	}
	if c.ControlPingInterval > wire.MaxControlPingInterval {
		return fmt.Errorf("--control-ping-interval must be ≤ %s: phones treat %s without a control frame as a dead connection (docs/PROTOCOL.md §3), got %s", wire.MaxControlPingInterval, wire.ControlSilenceTimeout, c.ControlPingInterval)
	}
	for _, r := range []struct{ name, v string }{
		{"--acme-budget-le-domain", c.ACMEBudgetLEDomain},
		{"--acme-budget-le-orders", c.ACMEBudgetLEOrders},
		{"--acme-budget-le-name", c.ACMEBudgetLEName},
		{"--acme-budget-gts-orders", c.ACMEBudgetGTSOrders},
		{"--acme-budget-gts-requests", c.ACMEBudgetGTSRequests},
		{"--acme-budget-gts-cert-polls", c.ACMEBudgetGTSCertPolls},
		{"--acme-budget-zerossl-orders", c.ACMEBudgetZeroSSLOrders},
		{"--acme-budget-zerossl-requests", c.ACMEBudgetZeroSSLRequests},
	} {
		if _, err := ParseRate(r.v); err != nil {
			return fmt.Errorf("%s: %w", r.name, err)
		}
	}
	if err := validGTSAccounts(c.ACMEGTSAccounts); err != nil {
		return err
	}
	if (c.ACMEEABZeroSSLKID == "") != (c.ACMEEABZeroSSLHMAC == "") {
		return errors.New("--acme-eab-zerossl-kid and --acme-eab-zerossl-hmac must be set together (ZeroSSL is used only with both)")
	}
	if !c.LEEnabled() && !c.GTSEnabled() && !c.ZeroSSLEnabled() {
		return errors.New("no ACME CA is enabled: keep --acme-dir-le, list a --acme-gts-account, or set the ZeroSSL EAB pair")
	}
	if c.AttestStatusMaxStale <= c.AttestRefresh {
		return fmt.Errorf("--attest-status-max-stale (%s) must exceed --attest-refresh (%s): a staleness bound at or below the refresh cadence refuses enrollment for the tail of every refresh window", c.AttestStatusMaxStale, c.AttestRefresh)
	}
	if c.ACMEGTSValidity <= shortlivedLifetime-c.ACMERenewMargin {
		return fmt.Errorf("--acme-gts-validity (%s) must exceed %s (the fixed non-LE renewal point = 160h shortlived − --acme-renew-margin): shorter GTS certs would expire before the renewal nudge fires", c.ACMEGTSValidity, shortlivedLifetime-c.ACMERenewMargin)
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
		return fmt.Errorf("--limit-bandwidth must be ≥ %d B/s (= wire.ChunkSize; note DECIMAL bits, 128kbit=16000 B/s fails), got %d B/s", bandwidthFloorBytesPerSec, bw)
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

var gtsAccountRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validGTSAccounts(ids []string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		switch {
		case !gtsAccountRe.MatchString(id):
			return fmt.Errorf("--acme-gts-account %q must be lowercase letters, digits and hyphens", id)
		case id == "letsencrypt" || id == "zerossl":
			return fmt.Errorf("--acme-gts-account %q collides with another CA's account key file", id)
		case seen[id]:
			return fmt.Errorf("--acme-gts-account %q is listed twice", id)
		}
		seen[id] = true
	}
	return nil
}
