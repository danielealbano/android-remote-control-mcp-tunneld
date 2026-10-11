<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 14 — ACME HTTP-01 + TLS-ALPN-01 validation (per CA), answered by the edge, plus a real-CA staging tier

## Scope

Agreed with the user (2026-10-10 / 2026-10-11):

- **Per-CA validation method.** Keep DNS-01 and add HTTP-01 and TLS-ALPN-01, selected per CA. The deployed
  configuration is Let's Encrypt = TLS-ALPN-01, Google Trust Services = TLS-ALPN-01, ZeroSSL = HTTP-01
  (ZeroSSL has no TLS-ALPN-01; it issued via HTTP-01 in the 2026-10-10 tests). The DNS provider credential is
  needed only when a CA uses DNS-01.
- **TLS-ALPN-01 is answered by the raw `:443` edge**, which already peeks the ClientHello: a ClientHello whose
  first ALPN protocol is `acme-tls/1` gets the challenge certificate locally and is never spliced. The challenge
  certificate is tunneld's own — ECDSA P-256, key usage `digitalSignature`, critical `id-pe-acmeIdentifier`, a
  single DNS SAN — served through lego's custom-provider hook. lego's own `tlsalpn01.ChallengeCert` /
  `ProviderServer` MUST NOT be used: its certificate carries key usage `keyEncipherment` only, which Google Trust
  Services' BoringSSL validators reject in TLS 1.3 (`illegal_parameter`; RFC 8446 §4.4.2.2). Root-caused and
  proven 2026-10-11 with live A/B orders against GTS production + staging and LE production + staging; reported
  upstream as go-acme/lego#3303 (this plan does not depend on that fix).
- **HTTP-01 is answered by a new public `:80` listener** that serves ONLY `/.well-known/acme-challenge/<token>`;
  every other request is refused. The user approved exposing `:80`.
- **Multi-node:** a CA validator may reach any replica, so the challenge material lives in Valkey (TTL'd) and
  every replica answers from it.
- **Tests:** a unit test pins the challenge certificate's key usage (Pebble validates with Go `crypto/tls`
  and cannot catch the BoringSSL behaviour); hermetic Pebble integration + e2e tests for both methods,
  including validation answered by the OTHER replica; and a new **staging tier** against Let's Encrypt
  staging and GTS staging:
  - it runs on **every CI run**;
  - the CA reaches the test through a **reverse SSH tunnel** on the small fleet node the user designated
    (`<staging-node>`; updated and rebooted 2026-10-11) — its address, like every staging secret, lives only in
    `~/.secrets` and GitHub secrets, never in the repository;
  - a **new dedicated SSH key**; the node IP, the SSH username and the key are **GitHub secrets** — nothing
    visible in the pipeline;
  - the test **skips when the key is missing**;
  - the DNS record is created **from the workstation** with the Cloudflare token, never remotely;
  - the GTS staging account registered on 2026-10-11 is reused: re-registering an existing account key
    against GTS staging succeeds with no EAB and with the consumed EAB (verified 2026-10-11, fresh client).
- Let's Encrypt staging limits (verified 2026-10-11, letsencrypt.org/docs/staging-environment): 30 000
  certificates per week per exact identifier set, 1 500 new orders per account per 3 h, 50 new accounts per
  IP per 3 h, 200 authorization failures per identifier per account per hour. GTS staging publishes no limits.

Decisions made while planning (consistent with the discussion; surfaced at the plan stop):

1. **Flags:** `--acme-challenge-le`, `--acme-challenge-gts`, `--acme-challenge-zerossl` (defaults
   `tls-alpn-01`, `tls-alpn-01`, `http-01`), `--acme-http-listen` (default `:80`). `--acme-dns-provider` becomes
   required only when a CA uses `dns-01`. **`:80` is bound only when a CA uses `http-01`** (the deployed
   configuration does: ZeroSSL).
2. **Startup order changes.** Today reserved-host (`--enroll-host` / `--control-host`) certificates are
   obtained synchronously BEFORE any listener binds. HTTP-01 / TLS-ALPN-01 must be answered by the node's own
   listeners, so: a valid disk cache is still loaded before binding; issuance runs AFTER the listeners bind;
   a host without a certificate is degraded (its TLS refused, tunnel splicing unaffected) and is retried every
   minute instead of hourly. This REPLACES the contract of the existing integration test
   `TestIntegration_StartupBindsAfterConstruction` (it asserts `:443` is refused while issuance is in flight);
   the plan rewrites it to the new contract — approving this plan approves that test change.
3. **One pending TLS-ALPN-01 challenge per domain cluster-wide.** A validator connection carries only the SNI,
   so two concurrent orders for the same domain cannot both be answered. The challenge key is written with
   `SET NX`; reserved-host issuance is serialized across replicas by a per-host `SETNX` lock: a replica waits up
   to 5 min for the lock, then gets up to 5 min to issue; an issuance abandoned at that deadline keeps the lock
   until its 10-min TTL (the background lego order may still hold the challenge); a shutdown releases it.
4. **Local challenge-store errors never count against a CA.** A pending-challenge conflict or a Valkey error
   inside the challenge provider is classified `local`: the chain stops and returns a retryable error
   (Retry-After 30 s) WITHOUT setting the per-CA cooldown / backoff. **The chain also stops once its context is
   done** (an issuance deadline, an aborted `/api/v1/issue`, shutdown): no further CA is tried and no failure
   bookkeeping is recorded for the interrupted attempt, so at most the one in-flight lego order continues in the
   background.
5. All challenge code lives in `internal/acme` (it already carries the package comment revive's
   `package-comments` rule requires); the edge reaches it through a one-method interface returning the
   ready-built certificate, so the edge never imports lego.
6. **The `:80` surface:** a listener wrapper used ONLY by the `:80` ACME challenge listener runs the
   per-connection checks off the accept loop in the documented order ban → conn-rate (`--limit-conn-rate`,
   the same `conn-rate` window as `:443`, fail-open) → `--max-clients` (the SAME per-node counter as the `:443`
   edge); keep-alives are disabled so one connection carries one request; an unmatched request records the NEW
   rejection label `acme-http-miss` (empty tunnel value, standard caplog dedup). `acme-http-miss` is not in the
   `NoRouteSpike` alert; the existing `HighRejectionRate` alert (any single reason > 10/s for 10 min) covers it,
   and the `:80` `conn-rate` / `max-clients` rejections feed the existing labels (and `SustainedIngressLimiting`).
   An `acme-tls/1` handshake with no pending challenge records `no-route`.
7. **Logging and Valkey bounds:** challenge served / handshake failed / lookup failed are Debug only
   (attacker-triggerable while a challenge is pending). The challenge Valkey calls use the connection / request
   context exactly like the existing `:443` conn-rate check: the Valkey client is built without
   `ContextTimeoutEnabled`, so each call is bounded by go-redis's socket timeouts (v9.23.0 defaults: 5 s read,
   5 s write), not by a context deadline.
8. **Staging tier specifics (user decision 2026-10-11: root key on the CI-only test VPS, no "monster"):** build
   tag `staging`, test package `staging/`, `make test-staging`, CI job `test-staging` (concurrency group with
   `queue: max`, so no run is cancelled). The new dedicated key is added to root's `authorized_keys`; the test
   opens `ssh -R 0.0.0.0:80:… -R 0.0.0.0:443:…` to the node, so LE/GTS staging reach the local tunneld directly
   (only root can bind ports below 1024, and no forwarder units are needed). ONE sshd drop-in on the node (3
   lines, installed under a dead-man rollback timer): `GatewayPorts clientspecified` (sshd binds remote forwards
   to loopback only by default) and `ClientAliveInterval 30` / `ClientAliveCountMax 4` (a dead CI run's session
   releases 80/443 within ~2 min). While 80/443 are held by another run, the test waits (≤ 20 min), which
   serializes local and CI runs. Wildcard DNS `*.<staging-domain>` → `<staging-node>` (`<staging-domain>` is a
   name directly under the registered domain, chosen by the user; its value is a secret). The ACME contact is the hygiene placeholder
   `ops@free.example.com` (Boulder's `policy.ValidEmail` accepts it; GTS staging accepted it when re-registering
   the reused account on 2026-10-11). Both staging CAs use a persisted account key — the reused GTS account and
   one LE staging account key generated once on the workstation (a seventh secret) — so runs create no new ACME
   accounts (LE staging allows 50 new accounts per IP per 3 h, and CI runner IPs are not ours). The test streams
   tunneld's, lego's and ssh's output to the test output line by line with the secrets redacted, and redacts them
   from failure messages.
9. **Method assertions:** every Pebble and staging test proves which method answered by counting tunneld's
   Debug "challenge served" log records with a counting log handler that forwards every record to the test's
   output handler.
10. **Deployment example:** `TUNNELD_ACME_DNS_PROVIDER` and `CF_DNS_API_TOKEN` are left EMPTY in
    `deploy/tunneld.env.example` (the default methods need no DNS credential in the internet-facing process).
11. **Ban/geo engine and validators:** HTTP-01 / TLS-ALPN-01 validation connections pass through the ban/geo
    checks like every ingress connection; a country ban can drop a CA's remote validation perspectives (DNS-01
    was immune) — documented for operators.
12. **Staging exposure:** during a staging run (minutes, every CI run) the test's tunneld — attestation-optional,
    like every test tier — is reachable from the internet through `<staging-node>:80/:443`; every client arrives as
    `127.0.0.1` through the tunnel, so the staging config caps enrollment at 10/min and 50/h and conn-rate at
    100/s; its certificates come from untrusted staging CAs; the per-case random reserved hostnames appear in the
    staging CT logs.

SACRED user rules applied: NO comments ADDED to hand-written code in any language (Go, YAML, Makefile, systemd
units, sshd drop-ins, env files); an existing comment a change makes wrong is REMOVED (the wrong part only —
never rewritten); existing correct comments stay (moved code keeps its comments); no nits. Exempt:
auto-generated files and the `# vX.Y.Z` action-pin tags. Every commit uses the global git identity (never a
repo-local override). Lint, build and tests run ONLY in Task 8.3.

This plan modifies the Mermaid charts in `docs/ARCHITECTURE.md` §1 and §9, so Task 8.3 validates every Mermaid
chart.

Placeholders used below (values live only outside the repository): `<staging-node>` = the small fleet node the
user designated for the staging tier; `<test-node>` = the fleet node that ran the 2026-10-11 TLS-ALPN-01 A/B
tests; `<gts-staging-account-key>` = the path, on `<test-node>`, of the lego account key file of the GTS staging
account registered there (PKCS#8 EC); both values are in the operator's private notes; `<staging-domain>`;
`<user>` / `<host>` in the staging test = the `TUNNELD_STAGING_SSH_USER` (`root`) / `TUNNELD_STAGING_SSH_HOST`
(`<staging-node>`) values.

## User Stories

- [x] **US1 — Per-CA validation method configuration**
- [x] **US2 — Challenge store, challenge certificate, HTTP-01 handler**
- [x] **US3 — lego wiring per CA**
- [x] **US4 — Edge answers TLS-ALPN-01**
- [x] **US5 — Server assembly: HTTP-01 listener, startup order, cluster lock**
- [x] **US6 — Hermetic Pebble coverage for both methods**
- [x] **US7 — Real-CA staging tier**
- [x] **US8 — Deployment, documentation, ground-up verification**

---

## US1 — Per-CA validation method configuration

Operators choose each CA's validation method; the DNS credential stops being mandatory.

Acceptance criteria:
- [x] The four new flags exist with the defaults above; kong rejects an unknown method; `Validate()` rejects an
      unsupported method per CA (ZeroSSL never `tls-alpn-01`), a missing `--acme-dns-provider` only when a CA
      uses `dns-01`, and a malformed `--acme-http-listen` only when a CA uses `http-01`.

### [x] Task 1.1 — Flags and validation

- [x] **Action** — modify `internal/config/config.go`: add after the `shortlivedLifetime` constant:

```go
const (
	ChallengeDNS01     = "dns-01"
	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
)
```

- [x] **Action** — modify `internal/config/config.go`: replace the `ACMEDNSProvider` field and add the new fields
  directly after it (before the blank line that precedes the DNS-01 tuning block):

```go
	ACMEDNSProvider    string `name:"acme-dns-provider" help:"lego DNS-01 provider id (e.g. cloudflare, route53). Required when a CA uses dns-01."`

	ACMEChallengeLE      string `name:"acme-challenge-le" default:"tls-alpn-01" enum:"dns-01,http-01,tls-alpn-01" help:"Let's Encrypt validation method: dns-01 | http-01 | tls-alpn-01."`
	ACMEChallengeGTS     string `name:"acme-challenge-gts" default:"tls-alpn-01" enum:"dns-01,http-01,tls-alpn-01" help:"Google Trust Services validation method: dns-01 | http-01 | tls-alpn-01."`
	ACMEChallengeZeroSSL string `name:"acme-challenge-zerossl" default:"http-01" enum:"dns-01,http-01" help:"ZeroSSL validation method: dns-01 | http-01 (ZeroSSL has no tls-alpn-01)."`
	ACMEHTTPListen       string `name:"acme-http-listen" default:":80" help:"Public HTTP-01 challenge listener; bound only when a CA uses http-01."`
```

- [x] **Action** — modify `internal/config/config.go`: add the method (value receiver, like `Validate`):

```go
func (c ServeCmd) UsesChallenge(method string) bool {
	return c.ACMEChallengeLE == method || c.ACMEChallengeGTS == method || c.ACMEChallengeZeroSSL == method
}
```

- [x] **Action** — modify `internal/config/config.go` `Validate()`: delete the `{"--acme-dns-provider", c.ACMEDNSProvider},`
  entry from the required-flags table, and insert directly after that table's loop:

```go
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
	if c.UsesChallenge(ChallengeHTTP01) {
		if _, _, err := net.SplitHostPort(c.ACMEHTTPListen); err != nil {
			return fmt.Errorf("--acme-http-listen must be host:port or :port, got %q: %w", c.ACMEHTTPListen, err)
		}
	}
```

Definition of Done:
- [x] `validCfg` in `internal/config/config_test.go` (and every other valid-config fixture there) sets
      `ACMEChallengeLE: ChallengeTLSALPN01, ACMEChallengeGTS: ChallengeTLSALPN01, ACMEChallengeZeroSSL: ChallengeHTTP01, ACMEHTTPListen: ":80"`.

Tests (`internal/config`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestValidate_ACMEChallenge` (table) | ZeroSSL `tls-alpn-01` rejected; LE/GTS `tls-alpn-01` accepted; empty / unknown method rejected per CA | base = existing valid fixture |
| `TestValidate_DNSProviderOnlyWithDNS01` (table) | missing provider accepted with no `dns-01`; rejected when any one CA uses `dns-01` | |
| `TestValidate_ACMEHTTPListen` (table) | a malformed value is rejected only when a CA uses `http-01`; ignored otherwise | |
| `TestServeCmd_UsesChallenge` (table) | true iff any of the three fields equals the method | |
| `TestKongDefaults_ACMEChallenge` | with every required flag supplied through its env twin, parsing `serve` yields `tls-alpn-01`/`tls-alpn-01`/`http-01` and `:80`; parsing `serve --acme-challenge-zerossl=tls-alpn-01` fails with kong's enum error (`must be one of "dns-01","http-01" but got "tls-alpn-01"`) | env twins as in `TestEnvTwinOverridesFlag`; error-text assertion as in `TestRemovedLegacyFlagsRejected` |
| existing tests requiring `--acme-dns-provider` | updated to the conditional rule | |

---

## US2 — Challenge store, challenge certificate, HTTP-01 handler

The material both listeners answer from, shared by every replica.

Acceptance criteria:
- [x] Every new Valkey key is written with its TTL in the same command (`SET … EX` / `SET … NX EX`).
- [x] Every challenge-store error wraps `ErrChallengeStore` (so issuance can classify it as local).
- [x] The challenge certificate has key usage exactly `digitalSignature`, an ECDSA P-256 key, a critical
      `1.3.6.1.5.5.7.1.31` extension whose value is the DER OCTET STRING of SHA-256(keyAuthorization), and
      exactly one DNS SAN.
- [x] The HTTP-01 handler answers only `GET`/`HEAD` `/.well-known/acme-challenge/<token>` for a stored
      `(host, token)` (200 with the key authorization); a challenge-store error is 503; every other request is
      404 and calls `onMiss`.

### [x] Task 2.1 — Challenge certificate

- [x] **Action** — create `internal/acme/challenge_cert.go` (the exact shape GTS production accepted on 2026-10-11):

```go
package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

var idPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

func challengeCertificate(domain, keyAuth string) (*tls.Certificate, error) {
	sum := sha256.Sum256([]byte(keyAuth))
	value, err := asn1.Marshal(sum[:])
	if err != nil {
		return nil, fmt.Errorf("acme: tls-alpn-01 extension: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("acme: tls-alpn-01 key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("acme: tls-alpn-01 serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ACME Challenge TEMP"},
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
		ExtraExtensions:       []pkix.Extension{{Id: idPeAcmeIdentifier, Critical: true, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("acme: tls-alpn-01 certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
```

Definition of Done:
- [x] The file imports nothing from `github.com/go-acme/lego`.

Tests (`internal/acme`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestChallengeCertificate_KeyUsage` | `KeyUsage == x509.KeyUsageDigitalSignature` exactly (the GTS regression guard) | |
| `TestChallengeCertificate_Shape` | ECDSA P-256 key; exactly one DNS SAN equal to the domain; the extension is critical and its value equals `asn1.Marshal(sha256(keyAuth))` | |
| `TestChallengeCertificate_TLS13Handshake` | a `tls.Server` with the certificate + `NextProtos [acme-tls/1]` completes a TLS 1.3 handshake with a client offering only `acme-tls/1`; the client sees the extension | `net.Pipe` |

### [x] Task 2.2 — Valkey challenge store

- [x] **Action** — create `internal/acme/challenge_store.go`:

```go
package acme

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	ChallengeTTL      = 10 * time.Minute
	selfLockTTL       = 10 * time.Minute
	selfUnlockTimeout = 5 * time.Second
)

var (
	ErrChallengeStore   = errors.New("acme: challenge store")
	ErrChallengePending = fmt.Errorf("%w: another tls-alpn-01 challenge is pending for this domain", ErrChallengeStore)
)

type ChallengeStore struct {
	rdb redis.UniversalClient
	ttl time.Duration
}

func NewChallengeStore(rdb redis.UniversalClient, ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{rdb: rdb, ttl: ttl}
}

func alpnChallengeKey(domain string) string { return "acme:alpn:" + strings.ToLower(domain) }

func httpChallengeKey(domain, token string) string {
	return "acme:http:" + strings.ToLower(domain) + ":" + token
}

func selfLockKey(host string) string { return "lock:acme-self:" + strings.ToLower(host) }

func (s *ChallengeStore) PutTLSALPN(ctx context.Context, domain, keyAuth string) error {
	key := alpnChallengeKey(domain)
	for range 2 {
		set, err := s.rdb.SetNX(ctx, key, keyAuth, s.ttl).Result()
		if err != nil {
			return fmt.Errorf("%w: store tls-alpn-01 challenge for %s: %w", ErrChallengeStore, domain, err)
		}
		if set {
			return nil
		}
		cur, err := s.rdb.Get(ctx, key).Result()
		switch {
		case err == nil && cur == keyAuth:
			return nil
		case err == nil:
			return ErrChallengePending
		case !errors.Is(err, redis.Nil):
			return fmt.Errorf("%w: read tls-alpn-01 challenge for %s: %w", ErrChallengeStore, domain, err)
		}
	}
	return ErrChallengePending
}

func (s *ChallengeStore) DeleteTLSALPN(ctx context.Context, domain, keyAuth string) error {
	return s.deleteIfValue(ctx, alpnChallengeKey(domain), keyAuth)
}

func (s *ChallengeStore) TLSALPNCertificate(ctx context.Context, domain string) (*tls.Certificate, bool, error) {
	keyAuth, ok, err := s.get(ctx, alpnChallengeKey(domain))
	if err != nil || !ok {
		return nil, false, err
	}
	cert, err := challengeCertificate(strings.ToLower(domain), keyAuth)
	if err != nil {
		return nil, false, fmt.Errorf("%w: tls-alpn-01 certificate for %s: %w", ErrChallengeStore, domain, err)
	}
	return cert, true, nil
}

func (s *ChallengeStore) PutHTTP(ctx context.Context, domain, token, keyAuth string) error {
	if err := s.rdb.Set(ctx, httpChallengeKey(domain, token), keyAuth, s.ttl).Err(); err != nil {
		return fmt.Errorf("%w: store http-01 challenge for %s: %w", ErrChallengeStore, domain, err)
	}
	return nil
}

func (s *ChallengeStore) DeleteHTTP(ctx context.Context, domain, token, keyAuth string) error {
	return s.deleteIfValue(ctx, httpChallengeKey(domain, token), keyAuth)
}

func (s *ChallengeStore) HTTPKeyAuth(ctx context.Context, domain, token string) (string, bool, error) {
	return s.get(ctx, httpChallengeKey(domain, token))
}

func (s *ChallengeStore) LockSelf(ctx context.Context, host string) (func() error, bool, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return noUnlock, false, fmt.Errorf("%w: self-issuance lock token: %w", ErrChallengeStore, err)
	}
	token := hex.EncodeToString(b[:])
	set, err := s.rdb.SetNX(ctx, selfLockKey(host), token, selfLockTTL).Result()
	if err != nil {
		return noUnlock, false, fmt.Errorf("%w: self-issuance lock for %s: %w", ErrChallengeStore, host, err)
	}
	if !set {
		return noUnlock, false, nil
	}
	return func() error {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), selfUnlockTimeout)
		defer cancel()
		return s.deleteIfValue(uctx, selfLockKey(host), token)
	}, true, nil
}

func noUnlock() error { return nil }

func (s *ChallengeStore) get(ctx context.Context, key string) (string, bool, error) {
	v, err := s.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("%w: read %s: %w", ErrChallengeStore, key, err)
	}
	return v, true, nil
}

func (s *ChallengeStore) deleteIfValue(ctx context.Context, key, want string) error {
	cur, ok, err := s.get(ctx, key)
	if err != nil || !ok || cur != want {
		return err
	}
	if err := s.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("%w: delete %s: %w", ErrChallengeStore, key, err)
	}
	return nil
}
```

Definition of Done:
- [x] No `Eval`, `Watch`, `TxPipelined` or `MULTI` anywhere in the file.

Tests (`internal/acme`, miniredis):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestChallengeStore_TLSALPNPutGetDelete` | put → certificate served for the domain (case-insensitive key); delete with the right keyAuth removes it | |
| `TestChallengeStore_TLSALPNPendingConflict` | a second put with a different keyAuth returns `ErrChallengePending` (and `errors.Is(err, ErrChallengeStore)`); the same keyAuth is idempotent (nil) | |
| `TestChallengeStore_TLSALPNExpiredBetweenRetries` | when the key expires between the `SET NX` and the `GET`, the put retries and succeeds | a go-redis hook (`AddHook`) that deletes the key in miniredis right after the first `SETNX` returns false |
| `TestChallengeStore_TLSALPNTTL` | the key's TTL equals the store TTL right after put | `mr.TTL(key)` |
| `TestChallengeStore_DeleteIgnoresForeignValue` | deleting with a different keyAuth leaves the key (both kinds) | |
| `TestChallengeStore_HTTPPutGetDelete` (table) | per-(host, token) storage, TTL, miss returns `found=false` | |
| `TestChallengeStore_ErrorsWrapChallengeStore` | a closed miniredis yields errors satisfying `errors.Is(err, ErrChallengeStore)` from get/put/delete/lock (no false hit) | `mr.Close()` before the call |
| `TestChallengeStore_LockSelf` | first lock ok with TTL `selfLockTTL`; second returns ok=false; unlock releases (also after the lock ctx is cancelled); a stale unlock (token replaced) does not delete the new holder; with Valkey unreachable the unlock returns an error within `selfUnlockTimeout` + 1 s | unreachable case: `mr.Close()` before unlock |

### [x] Task 2.3 — Lego providers

- [x] **Action** — create `internal/acme/challenge_providers.go`:

```go
package acme

import "context"

type TLSALPNChallenges interface {
	PutTLSALPN(ctx context.Context, domain, keyAuth string) error
	DeleteTLSALPN(ctx context.Context, domain, keyAuth string) error
}

type HTTPChallenges interface {
	PutHTTP(ctx context.Context, domain, token, keyAuth string) error
	DeleteHTTP(ctx context.Context, domain, token, keyAuth string) error
}

type tlsALPNProvider struct{ s TLSALPNChallenges }

func (p *tlsALPNProvider) Present(ctx context.Context, domain, _, keyAuth string) error {
	return p.s.PutTLSALPN(ctx, domain, keyAuth)
}

func (p *tlsALPNProvider) CleanUp(ctx context.Context, domain, _, keyAuth string) error {
	return p.s.DeleteTLSALPN(ctx, domain, keyAuth)
}

type httpProvider struct{ s HTTPChallenges }

func (p *httpProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	return p.s.PutHTTP(ctx, domain, token, keyAuth)
}

func (p *httpProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	return p.s.DeleteHTTP(ctx, domain, token, keyAuth)
}
```

Definition of Done:
- [x] `*ChallengeStore` satisfies `TLSALPNChallenges` and `HTTPChallenges` (compile-time assertions in the tests).

Tests (`internal/acme`, hand-written fakes):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestTLSALPNProvider_PresentCleanUp` | Present/CleanUp forward (domain, keyAuth) and propagate errors | |
| `TestHTTPProvider_PresentCleanUp` | same for (domain, token, keyAuth) | |

### [x] Task 2.4 — HTTP-01 handler

- [x] **Action** — create `internal/acme/challenge_http.go`:

```go
package acme

import (
	"context"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

const (
	httpChallengePrefix = "/.well-known/acme-challenge/"
	maxChallengeToken   = 256
	maxChallengeHost    = 253
)

type HTTPKeyAuths interface {
	HTTPKeyAuth(ctx context.Context, domain, token string) (string, bool, error)
}

func HTTPChallengeHandler(keyAuths HTTPKeyAuths, onMiss func(clientIP string), logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientHost(r.RemoteAddr)
		token, isChallenge := strings.CutPrefix(r.URL.Path, httpChallengePrefix)
		host := challengeHost(r.Host)
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || !isChallenge || !validChallengeToken(token) || host == "" {
			onMiss(ip)
			http.NotFound(w, r)
			return
		}
		keyAuth, found, err := keyAuths.HTTPKeyAuth(r.Context(), host, token)
		if err != nil {
			logger.Debug("acme http-01 challenge lookup failed", "domain", host, "ip", ip, "err", err)
			http.Error(w, "challenge store unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			onMiss(ip)
			http.NotFound(w, r)
			return
		}
		logger.Debug("acme http-01 challenge served", "domain", host, "ip", ip)
		w.Header().Set("Content-Type", "text/plain")
		if _, err := io.WriteString(w, html.EscapeString(keyAuth)); err != nil {
			logger.Debug("acme http-01 challenge response write failed", "domain", host, "ip", ip, "err", err)
		}
	})
}

func clientHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func challengeHost(hostHeader string) string {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > maxChallengeHost {
		return ""
	}
	return host
}

func validChallengeToken(token string) bool {
	if token == "" || len(token) > maxChallengeToken {
		return false
	}
	for _, c := range []byte(token) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
```

  `html.EscapeString` is a no-op on a key authorization (`<token>.<base64url thumbprint>`: `[A-Za-z0-9_.-]`); it
  satisfies gosec G705 (verified against the repo lint config during plan review).

Definition of Done:
- [x] No Info/Warn/Error log call in the file (every log line is Debug); `*ChallengeStore` satisfies `HTTPKeyAuths`
      (compile-time assertion in the tests).

Tests (`internal/acme`, httptest + a fake `HTTPKeyAuths` + a capturing slog handler):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestHTTPChallengeHandler_Serves` (table) | stored (host, token) → 200 `text/plain` body equal to the keyAuth for GET and HEAD; Host with port, upper case and trailing dot normalized; no record above Debug | |
| `TestHTTPChallengeHandler_Misses` (table) | POST, other path, empty / invalid / over-long token, over-long or empty Host, unknown token → 404 and `onMiss(ip)` called once; no record above Debug | |
| `TestHTTPChallengeHandler_StoreError` | a store error → 503, `onMiss` not called, no keyAuth in the body | |

---

## US3 — lego wiring per CA

Each CA's lego client uses the configured method; DNS-01 behaves exactly as before; a local challenge-store
problem never cools a CA down.

Acceptance criteria:
- [x] `tls-alpn-01` registers the custom TLS-ALPN-01 provider; `http-01` the custom HTTP-01 provider; `dns-01`
      (and an empty method) the existing DNS-01 path unchanged; any other value fails client construction.
- [x] The DNS provider is resolved only when a CA uses `dns-01`.
- [x] An issuance error wrapping `ErrChallengeStore` stops the chain with a retryable error (Retry-After
      `localChallengeRetry`) and sets NO per-CA cooldown / failure streak.

### [x] Task 3.1 — `NewLegoClient`

- [x] **Action** — modify `internal/acme/lego_client.go` `LegoConfig`: add after the `DNSSkipPropagationCheck`
  field:

```go
	Challenge string
	TLSALPN   TLSALPNChallenges
	HTTP      HTTPChallenges
```

- [x] **Action** — modify `internal/acme/lego_client.go` `NewLegoClient`: replace the block from
  `cfg.applyDNSResolvers()` through the end of the DNS-01 `switch` with:

```go
	switch challenge.Type(cfg.Challenge) {
	case challenge.TLSALPN01:
		if cfg.TLSALPN == nil {
			return nil, fmt.Errorf("acme: %s: tls-alpn-01 needs a challenge store", cfg.CAID)
		}
		if err := client.Challenge.SetTLSALPN01Provider(&tlsALPNProvider{s: cfg.TLSALPN}); err != nil {
			return nil, fmt.Errorf("acme: set tls-alpn-01 (%s): %w", cfg.CAID, err)
		}
	case challenge.HTTP01:
		if cfg.HTTP == nil {
			return nil, fmt.Errorf("acme: %s: http-01 needs a challenge store", cfg.CAID)
		}
		if err := client.Challenge.SetHTTP01Provider(&httpProvider{s: cfg.HTTP}); err != nil {
			return nil, fmt.Errorf("acme: set http-01 (%s): %w", cfg.CAID, err)
		}
	case challenge.DNS01, "":
		cfg.applyDNSResolvers()
		dnsOpts := cfg.dnsChallengeOpts()
		switch {
		case cfg.RawDNS != nil:
			if err := client.Challenge.SetDNS01Provider(cfg.RawDNS, dnsOpts...); err != nil {
				return nil, fmt.Errorf("acme: set dns01 (%s): %w", cfg.CAID, err)
			}
		case cfg.DNS != nil:
			if err := client.Challenge.SetDNS01Provider(&legoDNSAdapter{p: cfg.DNS}, dnsOpts...); err != nil {
				return nil, fmt.Errorf("acme: set dns01 (%s): %w", cfg.CAID, err)
			}
		}
	default:
		return nil, fmt.Errorf("acme: %s: unsupported challenge %q", cfg.CAID, cfg.Challenge)
	}
```

- [x] **Action** — modify `internal/acme/lego_client.go`: in the comment above `NewLegoClient`
  (`// NewLegoClient constructs and registers (or EAB-registers) the per-CA account and wires the DNS-01` /
  `// provider. Network-touching; exercised by the Pebble-backed integration tier.`) REMOVE the now-wrong words
  ` and wires the DNS-01` and `provider` (it now wires the per-CA method; the period after `provider` stays) and
  re-flow the two lines without adding a word, giving
  `// NewLegoClient constructs and registers (or EAB-registers) the per-CA account. Network-touching;` /
  `// exercised by the Pebble-backed integration tier.`
- [x] **Action** — modify `internal/acme/issuer.go`: in the package comment REMOVE the now-wrong `DNS-01, ` from
  `spillover, DNS-01, the split renewal timing` (DNS-01 is no longer the only method).

Definition of Done:
- [x] `grep -n 'tlsalpn01\.' internal/acme/*.go` shows no use of lego's `ChallengeCert`, `ChallengeBlocks` or
      `NewProviderServer`.

Tests (`internal/acme`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestNewLegoClient_UnsupportedChallenge` | an unknown method fails with the CA id and method in the error | `httptest` ACME directory stub (directory fetch only) |
| `TestNewLegoClient_ChallengeNeedsStore` (table) | `tls-alpn-01` / `http-01` with a nil store fail with the CA id in the error | same stub |
| existing EAB integration test | unchanged (empty method = DNS-01 path) | |

The positive registrations (the right provider per method, per CA) are proven end to end by US6 / US7, which
assert which listener answered.

### [x] Task 3.2 — `buildACMEChain`

- [x] **Action** — modify `internal/server/acmewire.go` `buildACMEChain`: change the signature to
  `func buildACMEChain(cfg config.ServeCmd, lim *limit.Limiter, chal *acme.ChallengeStore, rec acme.Recorder, logger *slog.Logger) (acmeChain, error)`;
  delete the `dnsProvider, err := acme.DNSProviderByName(...)` call and its `Warn` block at the top; replace the
  three `acme.LegoConfig` literals and the `return` with:

```go
	le := acme.LegoConfig{
		CAID: acme.CALetsEncrypt, DirectoryURL: cfg.ACMEDirLE, Email: cfg.ACMEEmail,
		AccountKey: leKey,
		Profile:    cfg.ACMELEProfile, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		UseARI:    true,
		Challenge: cfg.ACMEChallengeLE, TLSALPN: chal, HTTP: chal,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	gts := acme.LegoConfig{
		CAID: acme.CAGTS, DirectoryURL: cfg.ACMEDirGTS, Email: cfg.ACMEEmail,
		AccountKey: gtsKey,
		Validity:   cfg.ACMEGTSValidity, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		EABKID: cfg.ACMEEABGTSKID, EABHMAC: cfg.ACMEEABGTSHMAC,
		Challenge: cfg.ACMEChallengeGTS, TLSALPN: chal, HTTP: chal,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	zerossl := acme.LegoConfig{
		CAID: acme.CAZeroSSL, DirectoryURL: cfg.ACMEDirZeroSSL, Email: cfg.ACMEEmail,
		AccountKey:  zerosslKey,
		RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
		EABKID: cfg.ACMEEABZeroSSLKID, EABHMAC: cfg.ACMEEABZeroSSLHMAC,
		Challenge: cfg.ACMEChallengeZeroSSL, TLSALPN: chal, HTTP: chal,
		DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
	}
	if cfg.UsesChallenge(config.ChallengeDNS01) {
		dnsProvider, err := acme.DNSProviderByName(cfg.ACMEDNSProvider)
		if err != nil {
			logger.Warn("acme dns provider unavailable (issuance degraded until configured)",
				"provider", cfg.ACMEDNSProvider, "err", err)
		} else {
			le.RawDNS, gts.RawDNS, zerossl.RawDNS = dnsProvider, dnsProvider, dnsProvider
		}
	}
	return acme.NewChain(chainCfg, le, gts, zerossl), nil
```

- [x] **Action** — modify `internal/server/acmewire.go`: in the comment above `buildACMEChain` REMOVE the now-overbroad
  `the DNS-01 provider selected by` and `--acme-dns-provider, ` (the DNS-01 provider is resolved only when a CA uses
  `dns-01`), leaving `… chain from config: per-CA accounts whose keys are persisted …`.
- [x] **Action** — modify `internal/server/server.go` `Run`: after the `lim := limit.NewLimiter(...)` statement add
  `chal := acme.NewChallengeStore(rdb, acme.ChallengeTTL)` (add the `internal/acme` import), and change the chain
  construction to `chain, err := buildACMEChain(cfg, lim, chal, rec, logger)`; in the comment above it REMOVE the
  now-overbroad `; DNS-01 provider selected by --acme-dns-provider`, leaving
  `// ACME chain (lazy self-healing lego clients). An` / `// existing-but-unreadable account key aborts startup …`.

Definition of Done:
- [x] `buildACMEChain` resolves the DNS provider only inside the `UsesChallenge(config.ChallengeDNS01)` branch; its
      only production call site passes `chal`.

Tests (`internal/server`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestBuildACMEChain_LegoLogsToStderr` (existing) | updated to the new signature | pass a miniredis-backed `acme.NewChallengeStore` |
| `TestBuildACMEChain_CorruptAccountKeyAborts` (existing, acmewire_test.go) | updated to the new signature; behaviour unchanged | same |
| `TestBuildACMEChain_DNSProviderOnlyWhenUsed` | with no `dns-01` an unknown `--acme-dns-provider` produces no Warn; with `dns-01` it Warns | capture the logger |

### [x] Task 3.3 — Local challenge errors bypass the CA cooldown

- [x] **Action** — modify `internal/acme/issuer.go`: add `ClassLocal = "local"` to the class constants, and after
  `permanent`:

```go
func local(retry time.Duration, err error) *IssuerError {
	return &IssuerError{Class: ClassLocal, Reason: "challenge store", Retry: retry, Err: err}
}
```

- [x] **Action** — modify `internal/acme/lego_client.go`: add `const localChallengeRetry = 30 * time.Second` and
  make the first statement of `classifyLego`:

```go
	if errors.Is(err, ErrChallengeStore) {
		return local(localChallengeRetry, err)
	}
```

- [x] **Action** — modify `internal/acme/chain.go`: in the comment above `run` REMOVE the now-overbroad
  ` and applying reactive cooldown/backoff on failure` and `, other repeated failures get exponential backoff`
  (local challenge-store errors and a done context set no cooldown/backoff); pure removal, the rest stays.
- [x] **Action** — modify `internal/acme/chain.go` `run`: make the first statement inside the `for _, ca := range cas {`
  loop (before the existing cooldown comment):

```go
		if err := ctx.Err(); err != nil {
			return nil, store.CertInfo{}, transient(err)
		}
```

  and directly after the `if err == nil { … }` success block (before `c.cfg.Recorder.ACMEIssue(ca.id(), "fail")`)
  insert:

```go
		if ctx.Err() != nil {
			return nil, store.CertInfo{}, transient(fmt.Errorf("%w (CA order: %v)", ctx.Err(), err))
		}
		class := ClassTransient
		var ie *IssuerError
		if asIssuerError(err, &ie) {
			class = ie.Class
		}
		c.cfg.Logger.Warn("acme CA order failed", "ca", ca.id(), "name", name, "class", class, "err", err)
		if class == ClassLocal {
			return nil, store.CertInfo{}, rateLimited(ie.Retry, err)
		}
```

Definition of Done:
- [x] No caller outside `internal/acme` ever receives an error of class `ClassLocal` (the chain converts it); once
      `ctx` is done `run` calls no further `obtain`, `ACMEIssue` or cooldown/backoff method.

Tests (`internal/acme`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestClassifyLego_ChallengeStoreIsLocal` | an error wrapping `ErrChallengePending` (and a lego-style multi-error around it) classifies `ClassLocal` with Retry `localChallengeRetry` | build the wrap with `fmt.Errorf("…%w", …)` + `errors.Join` |
| `TestChain_LocalErrorSkipsCooldown` | a CA failing with a local error: chain returns `ClassRateLimited` with Retry 30 s, stops (next CA not called), `CACooldown` / failure streak untouched, no `ACMEIssue(…, "fail")` | fake `caIssuer`s + miniredis limiter + recorder fake |
| `TestChain_StopsWhenContextDone` (table: ctx cancelled before the call; ctx cancelled while the first CA's obtain runs; a local error returned while the ctx is cancelled) | no (further) CA `obtain`, no `ACMEIssue`, no cooldown / failure streak set; the returned error satisfies `errors.Is(err, context.Canceled)` | same fakes; the first CA's fake cancels the ctx and returns `transient(ctx.Err())` |
| `TestChain_LogsEachCAFailure` | every failed CA order is logged at Warn as `acme CA order failed` with `ca`, `name`, `class` and the error text, and the spillover still reaches the next CA | `rateLimited` LE, `transient` GTS, succeeding ZeroSSL; buffer-backed text handler |
| `TestChain_LogsBookkeepingErrors` (table: failed, rate-limited and successful order) | with Valkey down, each best-effort cooldown/streak error is logged (`cooldown check`, `failure-streak bump`, `cooldown write`, `failure-streak reset`) and the order outcome is unchanged | miniredis closed after the chain is built |

---

## US4 — Edge answers TLS-ALPN-01

A validator's `acme-tls/1` handshake is answered at the edge from Valkey; it never reaches a phone.

Acceptance criteria:
- [x] After the ban → conn-rate → max-clients → ClientHello checks, a ClientHello whose first ALPN protocol is
      `acme-tls/1` is answered locally (any SNI, reserved hosts included) and never routed or spliced.
- [x] No pending challenge (or a store error) → `no-route` recorded, connection closed, nothing logged above
      Debug; a failed or stalled handshake is closed after `--handshake-timeout` and releases its
      `--max-clients` slot.

### [x] Task 4.1 — Edge surface

- [x] **Action** — modify `internal/edge/edge.go`: add `"crypto/tls"` and `"log/slog"` to the imports; add the
  consumer interface after `Recorder`:

```go
type ACMEChallenges interface {
	TLSALPNCertificate(ctx context.Context, domain string) (*tls.Certificate, bool, error)
}
```

- [x] **Action** — modify `internal/edge/edge.go`: add `Logger *slog.Logger` as the last field of `Config`; add
  `chal ACMEChallenges` to `Edge` after `logs`; change `New` to take it after `logs` and store it:

```go
func New(cfg Config, ban func(netip.Addr) bool, banTun func(string, string) bool,
	rec Recorder, r Router, local LocalDialer, mesh MeshDialer, lim StreamLimiter, logs PhoneEventSink,
	chal ACMEChallenges, addr net.Addr) *Edge {
	return &Edge{
		cfg: cfg, ban: ban, banTun: banTun, rec: rec, router: r, local: local, mesh: mesh,
		lim: lim, logs: logs, chal: chal,
		enrollLn: newChanListener(addr), controlLn: newChanListener(addr), now: time.Now,
	}
}
```

- [x] **Action** — modify `internal/edge/accept.go`: add after `release`:

```go
func (e *Edge) Admit() bool { return e.admit() }

func (e *Edge) Release() { e.release() }
```

- [x] **Action** — modify `internal/server/server.go` `Run`: in the `edge.New(...)` call add `Logger: logger` as the
  last `edge.Config` field and pass `chal` between the `&edgeLogSink{…}` argument and `edgeAddr`.

Definition of Done:
- [x] Every `New(...)` / `Config{...}` construction in `internal/edge` tests passes a non-nil `ACMEChallenges` and
      `Logger`; the `server.Run` call passes `logger` and `chal`.

### [x] Task 4.2 — Interception

- [x] **Action** — create `internal/edge/acme.go`:

```go
package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

const acmeTLS1Protocol = "acme-tls/1"

func (e *Edge) serveACMEChallenge(ctx context.Context, conn net.Conn, info ClientHelloInfo, ip string) {
	domain := strings.ToLower(info.SNI)
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			e.cfg.Logger.Debug("acme tls-alpn-01 challenge close failed", "domain", domain, "ip", ip, "err", err)
		}
	}()
	cert, ok, err := e.chal.TLSALPNCertificate(ctx, domain)
	if err != nil {
		e.cfg.Logger.Debug("acme tls-alpn-01 challenge lookup failed", "domain", domain, "ip", ip, "err", err)
	}
	if err != nil || !ok {
		e.rec.Reject("no-route", info.SNI, ip)
		return
	}
	tc := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert}, NextProtos: []string{acmeTLS1Protocol}, MinVersion: tls.VersionTLS12,
	})
	if err := tc.SetDeadline(time.Now().Add(e.cfg.HandshakeTimeout)); err != nil {
		e.cfg.Logger.Debug("acme tls-alpn-01 challenge deadline failed", "domain", domain, "ip", ip, "err", err)
		return
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		e.cfg.Logger.Debug("acme tls-alpn-01 challenge handshake failed", "domain", domain, "ip", ip, "err", err)
		return
	}
	e.cfg.Logger.Debug("acme tls-alpn-01 challenge served", "domain", domain, "ip", ip)
}
```

- [x] **Action** — modify `internal/edge/accept.go` `handleConn`: insert directly after the
  `peekClientHello` error block (before the reserved-SNI comment + `switch`):

```go
	if info.ALPN == acmeTLS1Protocol {
		e.serveACMEChallenge(ctx, pc, info, ip)
		return
	}
```

Definition of Done:
- [x] The `acme-tls/1` branch sits after the ban / conn-rate / max-clients / ClientHello checks and before the
      reserved-SNI dispatch; its max-clients slot is released by `handleConn`'s existing deferred release.

Tests (`internal/edge`, fake `ACMEChallenges` + fake Router/LocalDialer + capturing slog handler):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestEdge_ACMETLSALPN_Serves` | an `acme-tls/1` client completes a handshake and sees the challenge certificate for the (lower-cased) SNI; Router / LocalDialer never called; nothing logged above Debug | fake returns a self-signed cert built in the test |
| `TestEdge_ACMETLSALPN_NoChallenge` (table) | fake ok=false and fake error → `Reject("no-route", sni, ip)`, conn closed, no handshake, nothing logged above Debug | recorder fake |
| `TestEdge_ACMETLSALPN_HandshakeFailure` (table: client aborts after the ClientHello; client stalls) | the conn is closed (stall: within `HandshakeTimeout`), the max-clients slot is released (`Admit` succeeds again at `MaxClients: 1`), nothing logged above Debug | small `HandshakeTimeout` |
| `TestEdge_ACMETLSALPN_ReservedHost` | `acme-tls/1` with SNI = enroll host is answered by the challenge path, not pushed to the enroll listener | |
| `TestEdge_ACMETLSALPN_BanFirst` | a banned IP offering `acme-tls/1` is rejected `ban` before any lookup | |
| `TestEdge_NonACMEALPNUnchanged` | `h2` / `http/1.1` ClientHellos keep the existing dispatch | |
| `TestEdge_AdmitRelease` | `Admit` honours `MaxClients` and `Release` frees a slot (shared counter) | |

---

## US5 — Server assembly: HTTP-01 listener, startup order, cluster lock

The process binds `:80` when needed, issues reserved-host certificates after its listeners are up, and
serializes reserved-host issuance across replicas.

Acceptance criteria:
- [x] `:80` (`--acme-http-listen`) binds only when a CA uses `http-01` and serves ONLY the ACME challenge handler;
      its connections are checked off the accept loop (ban → conn-rate, fail-open → the edge's `--max-clients`
      counter); keep-alives are disabled; an unmatched request records `acme-http-miss`; it drains on shutdown
      and its goroutines are joined before the final flushes.
- [x] A valid reserved-host disk cache is served from the moment the listeners bind; issuance runs after the
      bind; a degraded host is retried every minute; renewal stays hourly.
- [x] Reserved-host issuance takes the per-host cluster lock (wait budget and issuance budget separate); a lock
      error issues without it (fail-open, logged); an issuance abandoned at its deadline does not release the
      lock; a shutdown (while waiting or while issuing) releases a held lock and logs no lock/issuance problem.

### [x] Task 5.1 — Reserved-host certificates

- [x] **Action** — modify `internal/server/reserved.go`: add after the `shouldRenewFunc` type:

```go
type selfLocker interface {
	LockSelf(ctx context.Context, host string) (unlock func() error, ok bool, err error)
}

const (
	reservedDegradedRetry = time.Minute
	selfLockWait          = 5 * time.Minute
	selfIssueTimeout      = 5 * time.Minute
	selfLockPoll          = 2 * time.Second
)
```

- [x] **Action** — modify `internal/server/reserved.go` `reservedCerts`: delete the `renewMargin time.Duration`
  field; add after `shouldRenew`:

```go
	lock         selfLocker
	lockWait     time.Duration
	issueTimeout time.Duration
	lockPoll     time.Duration
```

- [x] **Action** — modify `internal/server/reserved.go`: in the `reservedCerts` type comment REMOVE the now-wrong
  `no CA can issue AND ` from `when no CA can issue AND no usable cache exists it starts DEGRADED` (every start
  without a usable cache is degraded until issuance lands); the rest of the comment stays.
- [x] **Action** — modify `internal/server/reserved_test.go`: in `TestReservedCerts_RenewsExpiringCache` REMOVE the
  now-wrong ` but inside the renew margin` from `// Cached pair is still valid but inside the renew margin → must be renewed at startup.`
  (the `shouldRenew` fake now decides; the `renewMargin` field is gone).
- [x] **Action** — modify `internal/server/reserved.go`: replace `newReservedCerts`, `ensure`, `runRenewal` and
  `maybeRenew` (with their comments) with the code below. The `// newReservedCerts builds the manager.` line is
  the existing comment with its now-wrong remainder REMOVED (it no longer issues at construction nor runs
  before the bind); the `ensure` and `runRenewal` comments go with the deleted functions.

```go
// newReservedCerts builds the manager.
func newReservedCerts(accountDir string, hosts []string, obtain selfIssuer, shouldRenew shouldRenewFunc,
	lock selfLocker, logger *slog.Logger) *reservedCerts {
	rc := &reservedCerts{
		dir: filepath.Join(accountDir, "self"), obtain: obtain, shouldRenew: shouldRenew, lock: lock,
		lockWait: selfLockWait, issueTimeout: selfIssueTimeout, lockPoll: selfLockPoll,
		logger: logger, now: time.Now, hosts: map[string]*reservedHost{},
	}
	for _, h := range hosts {
		rc.hosts[h] = &reservedHost{host: h}
	}
	return rc
}

func (rc *reservedCerts) loadCache() {
	for _, rh := range rc.hosts {
		if cert, info, ok := rc.loadCached(rh.host); ok && rc.now().Before(info.NotAfter) {
			rh.store(cert, info)
		}
	}
}

func (rc *reservedCerts) run(ctx context.Context, renewEvery, degradedEvery time.Duration) error {
	for {
		for _, rh := range rc.hosts {
			rc.maybeRenew(ctx, rh)
		}
		wait := renewEvery
		if rc.degraded() {
			wait = degradedEvery
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

func (rc *reservedCerts) degraded() bool {
	for _, rh := range rc.hosts {
		if rh.cur.Load() == nil {
			return true
		}
	}
	return false
}

func (rc *reservedCerts) maybeRenew(ctx context.Context, rh *reservedHost) {
	if rh.cur.Load() != nil {
		due, _, err := rc.shouldRenew(ctx, rh.currentInfo())
		if err != nil {
			rc.logger.Warn("reserved-host renewal check failed (will retry next scan)", "host", rh.host, "err", err)
			return
		}
		if !due {
			return
		}
	}
	rc.issue(ctx, rh)
}

func (rc *reservedCerts) issue(ctx context.Context, rh *reservedHost) {
	lockCtx, lockCancel := context.WithTimeout(ctx, rc.lockWait)
	unlock, locked, err := rc.acquire(lockCtx, rh.host)
	lockCancel()
	switch {
	case ctx.Err() != nil:
		if locked {
			rc.releaseLock(rh.host, unlock)
		}
		return
	case err != nil:
		rc.logger.Warn("reserved-host issuance lock unavailable (issuing without it)", "host", rh.host, "err", err)
	case !locked:
		rc.logger.Info("reserved-host issuance busy on another node (will retry)", "host", rh.host)
		return
	}
	issueCtx, cancel := context.WithTimeout(ctx, rc.issueTimeout)
	defer cancel()
	certPEM, keyPEM, info, err := rc.obtain(issueCtx, rh.host)
	abandoned := err != nil && ctx.Err() == nil && issueCtx.Err() != nil
	if locked {
		if abandoned {
			rc.logger.Warn("reserved-host issuance abandoned at its deadline (lock kept until its TTL)", "host", rh.host)
		} else {
			rc.releaseLock(rh.host, unlock)
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if rh.cur.Load() == nil {
			rc.logger.Warn("reserved-host cert unavailable (degraded; will retry)", "host", rh.host, "err", err)
		} else {
			rc.logger.Warn("reserved-host cert renewal failed (keeping current)", "host", rh.host, "err", err)
		}
		return
	}
	c, perr := tls.X509KeyPair(certPEM, keyPEM)
	if perr != nil {
		rc.logger.Warn("reserved-host cert parse failed", "host", rh.host, "err", perr)
		return
	}
	rh.store(&c, info)
	rc.persist(rh.host, certPEM, keyPEM, info)
}

func (rc *reservedCerts) releaseLock(host string, unlock func() error) {
	if err := unlock(); err != nil {
		rc.logger.Warn("reserved-host issuance lock release failed (expires by TTL)", "host", host, "err", err)
	}
}

func (rc *reservedCerts) acquire(ctx context.Context, host string) (func() error, bool, error) {
	for {
		unlock, ok, err := rc.lock.LockSelf(ctx, host)
		if err != nil && ctx.Err() != nil {
			return unlock, false, nil
		}
		if err != nil || ok {
			return unlock, ok, err
		}
		t := time.NewTimer(rc.lockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return unlock, false, nil
		case <-t.C:
		}
	}
}
```

Definition of Done:
- [x] `grep -n 'renewMargin\|runRenewal\|func (rc \*reservedCerts) ensure' internal/server/reserved.go` returns nothing.

Tests (`internal/server`, fake `selfIssuer` / `shouldRenewFunc` / `selfLocker`; tiny `lockWait` / `issueTimeout` /
`lockPoll` set on the struct):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestReservedCerts_CacheReused` (adapted) | `loadCache` serves a valid cache without calling obtain; the first `run` pass does not re-obtain a not-due cert | |
| `TestReservedCerts_LoadCacheUsesInjectedClock` (replaces `TestReservedEnsure_UsesInjectedClock`) | an expired-by-injected-clock cache is not served | set `rc.now` before `loadCache` |
| `TestReservedCerts_ObtainsWhenNoCache` (adapted) | the first `run` pass obtains + persists | ctx cancelled after the pass |
| `TestReservedCerts_DegradedWhenNoCAAndNoCache` (adapted) | obtain failure leaves the host degraded | |
| `TestReservedCerts_RenewsExpiringCache` (adapted) | a cache the `shouldRenew` fake reports due is renewed in the first pass, and the old cert is kept when that renewal fails | `shouldRenew` fake returns due=true |
| `TestReservedMaybeRenew_LogsShouldRenewError` (adapted) | with a seeded cache + `loadCache` + an always-free locker, a `shouldRenew` error is logged and obtain is not called | |
| `TestReservedCerts_RunRetriesDegradedSooner` | while degraded the next pass comes after `degradedEvery`, once healthy after `renewEvery` | tiny durations |
| `TestReservedCerts_WaitsForClusterLock` | lock busy then free → obtain called once after the wait; unlock called | fake locker |
| `TestReservedCerts_LockErrorFailsOpen` | locker error → obtain still called, Warn logged, no unlock | |
| `TestReservedCerts_LockBusyUntilWaitBudget` | lock never free → no obtain, Info logged, returns after `lockWait` | |
| `TestReservedCerts_LockErrorAfterWaitBudget` | a locker that returns an error once its ctx deadline has passed → treated as "busy" (no obtain, Info logged, no Warn) | fake locker returns `ctx.Err()` after the deadline |
| `TestReservedCerts_AbandonedIssuanceKeepsLock` | obtain blocks past `issueTimeout` → unlock NOT called, the "abandoned" Warn logged | fake obtain honours ctx |
| `TestReservedCerts_SeparateBudgets` | a lock acquired at the end of `lockWait` still gets a full `issueTimeout` for obtain | fake records the obtain ctx deadline |
| `TestReservedCerts_ShutdownWhileWaitingForLock` | ctx cancelled while the lock is busy → no obtain, no Info/Warn record; a lock obtained exactly as ctx is cancelled is released | fake locker |
| `TestReservedCerts_ShutdownDuringIssuanceReleasesLock` | ctx cancelled while obtain blocks → unlock called, no Warn record | fake obtain honours ctx |
| persist / legacy / corrupt-bundle tests (existing) | unchanged | |

### [x] Task 5.2 — Accept guard for the `:80` ACME listener

- [x] **Action** — create `internal/server/acmehttp.go` (used ONLY by the `:80` ACME challenge listener):

```go
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	acmeHTTPIdleTimeout    = 30 * time.Second
	acmeHTTPMaxHeaderBytes = 8 << 10
)

type connRateLimiter interface {
	Allow(ctx context.Context, scope string, ip netip.Addr, limit int, window time.Duration) (bool, time.Duration, error)
}

func connRateAllow(lim connRateLimiter, rate int, logger *slog.Logger) func(context.Context, netip.Addr) bool {
	return func(ctx context.Context, ip netip.Addr) bool {
		ok, _, err := lim.Allow(ctx, "conn-rate", ip, rate, time.Second)
		if err != nil {
			logger.Debug("acme-http conn-rate check failed (allowing)", "ip", ip, "err", err)
			return true
		}
		return ok
	}
}

type guardedListener struct {
	ln      net.Listener
	ban     func(netip.Addr) bool
	allow   func(context.Context, netip.Addr) bool
	admit   func() bool
	release func()
	reject  func(reason, tunnelName, clientIP string)
	logger  *slog.Logger
	conns   chan net.Conn
	closed  chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func newGuardedListener(ctx context.Context, ln net.Listener, ban func(netip.Addr) bool,
	allow func(context.Context, netip.Addr) bool, admit func() bool, release func(),
	reject func(reason, tunnelName, clientIP string), logger *slog.Logger) *guardedListener {
	l := &guardedListener{
		ln: ln, ban: ban, allow: allow, admit: admit, release: release, reject: reject, logger: logger,
		conns: make(chan net.Conn), closed: make(chan struct{}),
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.acceptLoop(ctx)
	}()
	return l
}

func (l *guardedListener) acceptLoop(ctx context.Context) {
	var delay time.Duration
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			l.logger.Warn("acme-http accept failed (backing off)", "backoff", delay, "err", err)
			select {
			case <-time.After(delay):
			case <-l.closed:
				return
			}
			continue
		}
		delay = 0
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.check(ctx, c)
		}()
	}
}

func (l *guardedListener) check(ctx context.Context, c net.Conn) {
	host, _, serr := net.SplitHostPort(c.RemoteAddr().String())
	if serr != nil {
		host = c.RemoteAddr().String()
	}
	ip, perr := netip.ParseAddr(host)
	if perr == nil && l.ban(ip) {
		l.reject("ban", "", host)
		closeLogged(l.logger, "acme-http rejected conn", c)
		return
	}
	if perr == nil && !l.allow(ctx, ip) {
		l.reject("conn-rate", "", host)
		closeLogged(l.logger, "acme-http rejected conn", c)
		return
	}
	if !l.admit() {
		l.reject("max-clients", "", host)
		closeLogged(l.logger, "acme-http rejected conn", c)
		return
	}
	sc := &slotConn{Conn: c, release: l.release}
	select {
	case l.conns <- sc:
	case <-l.closed:
		closeLogged(l.logger, "acme-http pending conn", sc)
	}
}

func (l *guardedListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *guardedListener) Close() error {
	err := net.ErrClosed
	l.once.Do(func() {
		close(l.closed)
		err = l.ln.Close()
	})
	return err
}

func (l *guardedListener) Addr() net.Addr { return l.ln.Addr() }

func (l *guardedListener) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { l.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
```

Definition of Done:
- [x] `Accept` never performs I/O beyond the channel receive; every Valkey call runs in a tracked per-connection
      goroutine; `newGuardedListener` is referenced only by the `:80` ACME wiring in `server.Run`.

Tests (`internal/server`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestGuardListener_Order` (table) | banned → `ban` (allow never called); over-rate → `conn-rate` (admit never called); admit false → `max-clients`; each closed | loopback listener + dialer |
| `TestGuardListener_SlowRateCheckDoesNotBlockAccept` | while one connection's `allow` blocks, a second connection is accepted promptly | `allow` blocks on a test channel |
| `TestGuardListener_AcceptErrorBackoff` | with a listener whose `Accept` always fails (non-`net.ErrClosed`), successive attempts are ≥ 5 ms apart (no hot spin) and `Close` during the backoff ends the loop (`Wait` returns); the accept error is logged at Warn | fake `net.Listener` recording `Accept` times |
| `TestGuardListener_SlotReleasedOnClose` | the shared slot frees exactly once on (double) Close | count admit/release |
| `TestGuardListener_Close` | `Accept` returns `net.ErrClosed` after Close; pending checks close their conns and release their slots | |
| `TestConnRateAllow` (table) | limiter allows → true; limiter denies → false; limiter error → true (fail-open) and logged; the call uses scope `conn-rate`, the configured rate and a 1 s window | hand-written fake `connRateLimiter` |
| `TestGuardListener_WaitJoinsGoroutines` | after Close, `Wait` returns only once a blocked `allow` has returned; `Wait` returns at its ctx deadline while `allow` stays blocked | `allow` blocks on a test channel |

### [x] Task 5.3 — `server.Run`

- [x] **Action** — modify `internal/observ/recorder.go`: append `"acme-http-miss"` to `RejectReasons` (after
  `"acme-failed"`); in its comment REMOVE the now-wrong ` (enroll, edge, phoneconn, acme)` (the `:80` guard in
  `internal/server` is now also a writer).
- [x] **Action** — modify `internal/server/server.go` `Run`:
  - replace the reserved-certs construction statement (its `// Reserved-host certs (…)` comment line stays) with:

```go
	reserved := newReservedCerts(cfg.ACMEAccountDir, []string{cfg.EnrollHost, cfg.ControlHost},
		chain.ObtainSelf, chain.ShouldRenew, chal, logger)
	reserved.loadCache()
```

  - directly before the `// Bind the public + mesh listeners LAST` block add:

```go
	var acmeHTTPSrv *http.Server
	if cfg.UsesChallenge(config.ChallengeHTTP01) {
		acmeHTTPSrv = &http.Server{
			Handler:           acme.HTTPChallengeHandler(chal, func(ip string) { rec.Reject("acme-http-miss", "", ip) }, logger),
			ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readHeaderTimeout, WriteTimeout: readHeaderTimeout,
			IdleTimeout: acmeHTTPIdleTimeout, MaxHeaderBytes: acmeHTTPMaxHeaderBytes,
			DisableGeneralOptionsHandler: true,
		}
		acmeHTTPSrv.SetKeepAlivesEnabled(false)
	}
```

  - after the `internalLn` bind block add:

```go
	var acmeHTTPLn net.Listener
	if acmeHTTPSrv != nil {
		acmeHTTPLn, err = net.Listen("tcp", cfg.ACMEHTTPListen)
		if err != nil {
			closeLogged(logger, "raw listener", rawLn)
			closeLogged(logger, "mesh listener", meshLn)
			closeLogged(logger, "internal listener", internalLn)
			return fmt.Errorf("acme http listen %s: %w", cfg.ACMEHTTPListen, err)
		}
	}
```

  - after the `g.Go(func() error { ed.Serve(gctx, rawLn); return nil })` line add:

```go
	var guarded *guardedListener
	if acmeHTTPSrv != nil {
		guarded = newGuardedListener(gctx, acmeHTTPLn, banIP, connRateAllow(lim, cfg.LimitConnRate, logger),
			ed.Admit, ed.Release, rec.Reject, logger)
		g.Go(func() error { return serveTLS(gctx, acmeHTTPSrv, guarded, logger, "acme-http") })
	}
```

  - replace `g.Go(func() error { return reserved.runRenewal(gctx, renewalScanInterval) })` with
    `g.Go(func() error { return reserved.run(gctx, renewalScanInterval, reservedDegradedRetry) })`;
  - in the drain: after the raw-listener close add
    `if guarded != nil { closeLogged(logger, "acme-http listener", guarded) }`; after the internal server's
    shutdown add `if acmeHTTPSrv != nil { shutdownLogged(sctx, logger, "acme-http", acmeHTTPSrv) }`; after the
    `ed.Wait(sctx)` line add `if guarded != nil { guarded.Wait(sctx) }` (before `g.Wait()` and the final flushes).
- [x] **Action** — modify `internal/server/server.go`: in the `// Bind the public + mesh listeners LAST` comment
  REMOVE the now-wrong `(reserved-cert` and `issuance) ` fragments (reserved-cert issuance no longer precedes the
  bind); the rest stays.
- [x] **Action** — modify `internal/server/serve.go`: in the `serveTLS` comment REMOVE the now-wrong enumeration
  ` internal (metrics/healthz/admin)` (the plain listener is now also the HTTP-01 one), leaving
  `ln is a tls.Listener for the TLS servers (enroll/control/mesh), or the plain` / `// listener.` followed by the
  unchanged rest.
- [x] **Action** — modify `internal/server/server_test.go` `TestRun_Lifecycle`: the reserved-host issuance now
  writes `lock:acme-self:*` keys at startup, so "any key exists" no longer proves the heartbeat landed; replace the
  `waitUntil` predicate with one that is true only once a `node:` key exists (its existing comment stays accurate):

```go
	waitUntil(t, 5*time.Second, func() bool {
		for _, k := range mr.DB(0).Keys() {
			if strings.HasPrefix(k, "node:") {
				return true
			}
		}
		return false
	})
```

  and add `"strings"` to that file's imports.

Definition of Done:
- [x] `server.Run` binds `--acme-http-listen` only when `cfg.UsesChallenge(config.ChallengeHTTP01)`; the HTTP-01
      server is shut down and its guard joined in the drain before the final flushes.

Tests (`internal/metrics/metrics_test.go`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestRejectionIncrementsACMEHTTPMiss` | `rec.Reject("acme-http-miss", "", ip)` yields `tunneld_rejections_total{reason="acme-http-miss"} 1` on `/metrics` and no "unregistered rejection reason" Error | as `TestRejectionIncrementsReasonCounter` |

Tests (`internal/server/server_test.go`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestRun_ACMEHTTPBindFailureIsFatal` | with a CA on `http-01` and `ACMEHTTPListen` already in use, `Run` returns an error containing `acme http listen`, and the internal listener's address can be bound again afterwards (no leaked listener) | as `TestRun_InternalBindFailureIsFatal`: `lifecycleConfig` + `ACMEChallengeZeroSSL: config.ChallengeHTTP01` + an occupied `ACMEHTTPListen`; `InternalListen` set to a probed free address so it can be re-bound |

Tests (`internal/server/serve_test.go`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestCloseLogged` (table) | a clean close and an already-closed (`net.ErrClosed`) close log nothing; any other close error is logged at Warn | `io.Closer` func fake; buffer-backed text handler |
| `TestShutdownLogged` (table) | a `Shutdown` whose listener close reports `net.ErrClosed` logs nothing; any other close error is logged at Warn | real `http.Server` on a loopback listener whose `Close` returns the case's error; one request first so `Serve` tracks it |

The `server.Run` wiring is covered by US6.

---

## US6 — Hermetic Pebble coverage for both methods

Pebble validates HTTP-01 / TLS-ALPN-01 against tunneld's real listeners, including validation answered by the
replica that did not start the order; the existing tiers keep passing under the new startup order.

Acceptance criteria:
- [x] Integration: enroll + public-cert issuance + frontend roundtrip succeed with LE/GTS on `tls-alpn-01`
      (ZeroSSL `http-01`) and with all CAs on `http-01`; each case proves the configured method answered and the
      other did not.
- [x] E2E: the same with the orders started on replica A and every validation answered by replica B (A answers
      none).
- [x] Every pre-existing integration / e2e configuration pins `dns-01` explicitly, waits until BOTH reserved hosts
      serve a certificate, and still passes.
- [x] The startup contract test asserts the NEW order; `:80` is unbound without `http-01`, refuses keep-alive,
      counts `acme-http-miss`, and drains on shutdown; a valid cache is served while issuance is pending.

### [x] Task 6.1 — Shared test harness (`internal/tunneltest`)

- [x] **Action** — modify `internal/tunneltest/containers.go`: change the build constraint to
  `//go:build integration || e2e || staging`; in the header comment REMOVE the now-wrong
  ` for the integration (//go:build integration) and e2e (//go:build e2e)` + `tiers` (the staging tier uses it
  too) and ` (user decision: the automated tiers are hermetic)` (the staging tier reaches real staging CAs),
  re-flowing the remaining words.
- [x] **Action** — modify `internal/tunneltest/containers.go`: add `HostIP string`, `HTTPPort int`, `TLSPort int`
  at the end of `PebbleEnv`; add the import `"github.com/moby/moby/client"` (`bytes`, `encoding/json`, `net` are
  already imported); add:

```go
type pebbleSetup struct{ hostValidation bool }

type PebbleOption func(*pebbleSetup) error

func WithHostValidation() PebbleOption {
	return func(s *pebbleSetup) error {
		s.hostValidation = true
		return nil
	}
}

const pebbleHostConfigPath = "/test/config/pebble-host-validation.json"

func pebbleHostValidationConfig(t *testing.T, httpPort, tlsPort int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"pebble": map[string]any{
		"listenAddress":                  "0.0.0.0:14000",
		"managementListenAddress":        "0.0.0.0:15000",
		"certificate":                    "test/certs/localhost/cert.pem",
		"privateKey":                     "test/certs/localhost/key.pem",
		"httpPort":                       httpPort,
		"tlsPort":                        tlsPort,
		"ocspResponderURL":               "",
		"externalAccountBindingRequired": false,
		"retryAfter":                     map[string]any{"authz": 3, "order": 5},
		"keyAlgorithm":                   "ecdsa",
		"profiles": map[string]any{
			"default":    map[string]any{"description": "default", "validityPeriod": 7776000},
			"shortlived": map[string]any{"description": "shortlived", "validityPeriod": 518400},
		},
	}})
	if err != nil {
		t.Fatalf("pebble host-validation config: %v", err)
	}
	return raw
}

func networkGateway(t *testing.T, nw *testcontainers.DockerNetwork) string {
	t.Helper()
	ctx := context.Background()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatalf("docker client: %v", err)
	}
	defer func() {
		if err := cli.Close(); err != nil {
			t.Logf("close the docker client: %v", err)
		}
	}()
	res, err := cli.NetworkInspect(ctx, nw.ID, client.NetworkInspectOptions{})
	if err != nil {
		t.Fatalf("inspect network %s: %v", nw.Name, err)
	}
	for _, c := range res.Network.IPAM.Config {
		if c.Gateway.Is4() {
			return c.Gateway.String()
		}
	}
	t.Fatalf("network %s has no IPv4 gateway", nw.Name)
	return ""
}

func freePortOn(t *testing.T, ip string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("free port on %s: %v", ip, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release port probe on %s: %v", ip, err)
	}
	return port
}
```

- [x] **Action** — modify `internal/tunneltest/containers.go` `StartPebble`: change the signature to
  `func StartPebble(t *testing.T, opts ...PebbleOption) *PebbleEnv`; at the top apply the options into a
  `var setup pebbleSetup` (`t.Fatalf` on an option error); after `nw := newNetwork(t)` compute:

```go
	defaultIPv4 := "127.0.0.1"
	pebbleConfig := "/test/config/pebble-config.json"
	var files []testcontainers.ContainerFile
	var hostIP string
	var httpPort, tlsPort int
	if setup.hostValidation {
		hostIP = networkGateway(t, nw)
		httpPort, tlsPort = freePortOn(t, hostIP), freePortOn(t, hostIP)
		defaultIPv4 = hostIP
		pebbleConfig = pebbleHostConfigPath
		files = []testcontainers.ContainerFile{{
			Reader: bytes.NewReader(pebbleHostValidationConfig(t, httpPort, tlsPort)), ContainerFilePath: pebbleHostConfigPath, FileMode: 0o644,
		}}
	}
```

  then use `defaultIPv4` in the challtestsrv `Cmd` (`"-defaultIPv4", defaultIPv4`), `pebbleConfig` in the Pebble
  `Cmd` (`"-config", pebbleConfig`), set `Files: files` on the Pebble request, and return
  `HostIP: hostIP, HTTPPort: httpPort, TLSPort: tlsPort` in the `PebbleEnv`. Calls without options behave exactly
  as before.
- [x] **Action** — create `internal/tunneltest/acme.go`:

```go
//go:build integration || e2e || staging

package tunneltest

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

func ServesCertificate(t *testing.T, edgeAddr, host string) (bool, error) {
	t.Helper()
	var presented bool
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", edgeAddr, &tls.Config{
		ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			presented = len(cs.PeerCertificates) > 0
			return nil
		},
	})
	if err != nil {
		return presented, err
	}
	if err := conn.Close(); err != nil {
		t.Logf("close the %s certificate probe: %v", host, err)
	}
	return presented, nil
}

func WaitReservedHosts(t *testing.T, edgeAddr string, hosts []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for _, host := range hosts {
		for {
			ok, err := ServesCertificate(t, edgeAddr, host)
			if ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("reserved host %s served no certificate within %s (last probe: %v)", host, timeout, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

type LogCounter struct {
	state *logCounts
	next  slog.Handler
}

type logCounts struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewLogCounter(next slog.Handler) *LogCounter {
	return &LogCounter{state: &logCounts{counts: map[string]int{}}, next: next}
}

func (c *LogCounter) Logger() *slog.Logger { return slog.New(c) }

func (c *LogCounter) Enabled(context.Context, slog.Level) bool { return true }

func (c *LogCounter) Handle(ctx context.Context, r slog.Record) error {
	c.state.mu.Lock()
	c.state.counts[r.Message]++
	c.state.mu.Unlock()
	if !c.next.Enabled(ctx, r.Level) {
		return nil
	}
	return c.next.Handle(ctx, r)
}

func (c *LogCounter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LogCounter{state: c.state, next: c.next.WithAttrs(attrs)}
}

func (c *LogCounter) WithGroup(name string) slog.Handler {
	return &LogCounter{state: c.state, next: c.next.WithGroup(name)}
}

func (c *LogCounter) Count(msg string) int {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	return c.state.counts[msg]
}
```

- [x] **Action** — run `go mod tidy` (the new direct import moves `github.com/moby/moby/client` to a direct
  requirement).

Definition of Done:
- [x] `go.mod` lists `github.com/moby/moby/client` without `// indirect`; no other `go.mod` line changes.

### [x] Task 6.2 — Existing harnesses: DNS-01 pin + reserved-host readiness

- [x] **Action** — modify `internal/server/integration_test.go`: add `internalAddr string` and `acmeHTTPAddr string`
  to `itEnv` (after `edgeAddr`); in `itServeConfig` add to the returned literal
  `ACMEChallengeLE: config.ChallengeDNS01, ACMEChallengeGTS: config.ChallengeDNS01, ACMEChallengeZeroSSL: config.ChallengeDNS01,`
  (every integration config built from it — including `drain_startup_integration_test.go`'s — inherits the pin).
- [x] **Action** — modify `internal/server/integration_test.go`: move the tail of `startIntegrationServer` (from
  `ctx, cancel := context.WithCancel(...)` to the `return &itEnv{...}`) into the helper below (the moved code keeps
  its existing `// drain cancels …` comment; the old `// Readiness: …` comment and its Valkey-keys `waitBool` block
  are deleted with the code they described — the reserved-host wait replaces them); make `startIntegrationServer`
  end with
  `env, ok := runIntegrationServer(t, cfg, pebble, testLogger(), redisURL, s3URL, access, secret); if !ok { t.Fatal("integration server exited before serving") }; return env`;
  in its doc comment REMOVE the now-wrong ` (construction, incl. the reserved-host cert obtain, has finished and` +
  `the node heartbeat has landed)` (readiness is now both reserved hosts serving), leaving
  `… and waits until it is ready.`:

```go
func runIntegrationServer(t *testing.T, cfg config.ServeCmd, pebble *tunneltest.PebbleEnv, logger *slog.Logger,
	redisURL, s3URL, access, secret string) (*itEnv, bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, logger, "it") }()

	deadline := time.Now().Add(120 * time.Second)
	for {
		enrollOK, enrollErr := tunneltest.ServesCertificate(t, cfg.Listen, cfg.EnrollHost)
		controlOK, controlErr := tunneltest.ServesCertificate(t, cfg.Listen, cfg.ControlHost)
		if enrollOK && controlOK {
			break
		}
		select {
		case runErr := <-done:
			cancel()
			t.Logf("integration server exited before serving: %v", runErr)
			return nil, false
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			runErr := <-done
			t.Fatalf("integration server never served both reserved-host certificates (last probe: %v; run: %v)", errors.Join(enrollErr, controlErr), runErr)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// drain cancels the server and waits for Run to return, AT MOST ONCE: both t.Cleanup and a test that
	// exercises shutdown explicitly may call it — the second call is a no-op returning the recorded result.
	var drainOnce sync.Once
	var drainErr error
	drain := func() error {
		drainOnce.Do(func() {
			cancel()
			select {
			case drainErr = <-done:
			case <-time.After(20 * time.Second):
				drainErr = fmt.Errorf("server did not drain within 20s of cancellation")
			}
		})
		return drainErr
	}
	t.Cleanup(func() {
		if err := drain(); err != nil {
			t.Error(err)
		}
	})

	opts, _ := redis.ParseURL(redisURL)
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	st, err := store.NewS3Store(context.Background(), store.S3Config{
		Endpoint: s3URL, Region: "us-east-1", Bucket: itBucket,
		AccessKey: access, SecretKey: secret, ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &itEnv{
		edgeAddr: cfg.Listen, internalAddr: cfg.InternalListen, acmeHTTPAddr: cfg.ACMEHTTPListen,
		pebble: pebble, s3URL: s3URL, s3Access: access, s3Secret: secret, rdb: rdb, st: st, drain: drain,
	}, true
}
```

  Add `"log/slog"` to the file's imports.
- [x] **Action** — modify `e2e/e2e_test.go`: replace `replicaOpts` (its comment and the existing field comments
  stay) with:

```go
// replicaOpts tweaks a replica's config for a specific scenario.
type replicaOpts struct {
	acmeDirLE  string // override the LE directory (for spillover); empty = Pebble
	trafficDay string // override --limit-traffic-day; empty = 1gb
	concurrent int    // override --limit-concurrent; 0 = 8
	bandwidth  string // override --limit-bandwidth; empty = 10mbit
	// Real attestation (NOT optional): when attestRootURL is set, the replica runs the full seven-point
	// attestation gate against these live root/status URLs + signer allowlist (empty = dummy + optional).
	attestRootURL    string
	attestStatusURL  string
	attestSignerFile string

	edgeAddr         string
	acmeHTTPListen   string
	challengeLE      string
	challengeGTS     string
	challengeZeroSSL string
	logger           *slog.Logger
}
```

- [x] **Action** — modify `e2e/e2e_test.go`: in the `startReplica` comment REMOVE the now-wrong
  ` (internal /healthz is 200)` (readiness also requires both reserved hosts); in the `runReplicaOnce` comment
  REMOVE the now-wrong ` on fresh freeAddr ports` (the edge may be a fixed Pebble validation address); replace the
  body of `runReplicaOnce` with (its inner comments are the existing ones, kept; the final `t.Fatal` message drops
  its now-wrong cause, since `/healthz` readiness no longer depends on issuance):

```go
	t.Helper()
	edgeAddr := freeAddr(t)
	if opts.edgeAddr != "" {
		edgeAddr = opts.edgeAddr
	}
	meshAddr := freeAddr(t)
	internalAddr := freeAddr(t)
	acmeHTTPListen := freeAddr(t)
	if opts.acmeHTTPListen != "" {
		acmeHTTPListen = opts.acmeHTTPListen
	}

	leDir := inf.pebble.DirectoryURL
	if opts.acmeDirLE != "" {
		leDir = opts.acmeDirLE
	}
	trafficDay := "1gb"
	if opts.trafficDay != "" {
		trafficDay = opts.trafficDay
	}
	concurrent := 8
	if opts.concurrent != 0 {
		concurrent = opts.concurrent
	}

	bandwidth := "10mbit"
	if opts.bandwidth != "" {
		bandwidth = opts.bandwidth
	}

	challengeLE, challengeGTS, challengeZeroSSL := config.ChallengeDNS01, config.ChallengeDNS01, config.ChallengeDNS01
	if opts.challengeLE != "" {
		challengeLE = opts.challengeLE
	}
	if opts.challengeGTS != "" {
		challengeGTS = opts.challengeGTS
	}
	if opts.challengeZeroSSL != "" {
		challengeZeroSSL = opts.challengeZeroSSL
	}
	logger := testOutputLogger()
	if opts.logger != nil {
		logger = opts.logger
	}

	// Attestation: default is the dummy unreachable URLs + optional mode. When a real root URL is given,
	// run the full attestation gate against it (the reference-client test uses this).
	attestOptional := true
	attestRoot := "http://127.0.0.1:1/root"
	attestStatus := "http://127.0.0.1:1/status"
	attestSigner := emptyFile(t)
	if opts.attestRootURL != "" {
		attestOptional = false
		attestRoot = opts.attestRootURL
		attestStatus = opts.attestStatusURL
		attestSigner = opts.attestSignerFile
	}

	cfg := config.ServeCmd{
		RedisURL: inf.redisURL, Listen: edgeAddr, MeshListen: meshAddr, InternalListen: internalAddr,
		MeshAdvertise: meshAddr, MeshPoolSize: 4, MeshCertTTL: 24 * time.Hour,
		TunnelDomain: e2eTunnelDomain, EnrollHost: e2eEnrollHost, ControlHost: e2eControlHost, NameLength: 10,
		CACert: inf.caCert, CAKey: inf.caKey, CertValidity: 4380 * time.Hour,
		S3Endpoint: inf.s3URL, S3Region: "us-east-1", S3Bucket: e2eBucket,
		S3AccessKey: inf.access, S3SecretKey: inf.secret, S3ForcePathStyle: true,
		RegistryClaimTimeout: 3 * time.Second, RegistryClaimSettle: 5 * time.Second,
		AttestSignerDigestFile: attestSigner,
		AttestRootURL:          attestRoot, AttestStatusURL: attestStatus,
		AttestRefresh: time.Hour, AttestStatusMaxStale: 24 * time.Hour, AttestationOptional: attestOptional,
		ACMEDirLE: leDir, ACMEDirGTS: inf.pebble.DirectoryURL, ACMEDirZeroSSL: inf.pebble.DirectoryURL,
		ACMEEmail: "ops@example.test", ACMELEProfile: "shortlived", ACMEGTSValidity: 168 * time.Hour,
		ACMEAccountDir: t.TempDir(), ACMEDNSProvider: "httpreq",
		ACMEChallengeLE: challengeLE, ACMEChallengeGTS: challengeGTS, ACMEChallengeZeroSSL: challengeZeroSSL,
		ACMEHTTPListen:   acmeHTTPListen,
		ACMEDNSResolvers: []string{inf.pebble.DNSResolver}, ACMEDNSSkipPropagationCheck: true,
		ACMECooldownDefault: time.Second, ACMEBackoffInitial: time.Second, ACMEBackoffMax: 5 * time.Second,
		ACMERenewMargin: 48 * time.Hour, IssuePerWeek: 10,
		RouteTTL: 30 * time.Second, ControlPingInterval: 30 * time.Second,
		LimitStreamPending: 64, LimitEnrollHour: 1000, LimitEnrollMinute: 1000, LimitEnrollBody: "64kb",
		MaxClients: 100, LimitConnRate: 1000, LimitConcurrent: concurrent, LimitPackets: 100000, HandshakeTimeout: 5 * time.Second, LimitDialBackTimeout: 10 * time.Second,
		LimitConnIdle: 120 * time.Second, LimitConnMinGrace: 60 * time.Second, LimitConnEvictIdle: 1 * time.Second,
		LimitConnMinRate: "1kb", LimitConnProtectRate: "1mb", LimitBandwidth: bandwidth,
		LimitTrafficDay: trafficDay, LimitTrafficWeek: "4gb",
		BanPoll: time.Second, ShutdownGrace: 3 * time.Second, Log: []string{"output=std;level=error"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, cfg, logger, "e2e") }()

	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case runErr := <-done:
			cancel()
			// Run exited before serving. Usually a freeAddr port race (retry with fresh ports), but log
			// the actual error so a NON-port failure (e.g. a fatal config/ACME error) is diagnosable.
			t.Logf("replica boot attempt exited before serving: %v", runErr)
			return "", false
		default:
		}
		if healthOK(internalAddr) {
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
					t.Error("replica did not drain within 20s")
				}
			})
			tunneltest.WaitReservedHosts(t, edgeAddr, []string{e2eEnrollHost, e2eControlHost}, 120*time.Second)
			inf.internal[edgeAddr] = internalAddr
			return edgeAddr, true
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("replica never became ready")
	return "", false
```

Definition of Done:
- [x] Every e2e and integration test that enrolls runs after both reserved hosts serve a certificate.

### [x] Task 6.3 — Startup contract

- [x] **Action** — modify `internal/server/drain_startup_integration_test.go`: rewrite
  `TestIntegration_StartupBindsAfterConstruction` (user-approved with this plan; its doc comment and inline
  comments describe the old contract and are deleted with it) as
  `TestIntegration_ListenersServeWhileReservedIssuancePending`, and add
  `TestIntegration_ReservedCacheServedWhileIssuancePending` and `TestIntegration_ACMEHTTPListenerOnlyWhenUsed`, per
  the table; in the comment above the mesh-bind-failure test's `itServeConfig` call REMOVE the now-wrong
  ` → the reserved-cert obtain fails fast and starts degraded, so construction` + `still reaches the listener binds`
  (issuance no longer runs during construction), leaving `// Unreachable ACME (port 1).`; in the
  `hangACMEListener` comment REMOVE the now-wrong ` — keeping server construction deliberately in flight` (the hang
  now holds post-bind issuance), leaving `… blocks in its TLS handshake.`

Definition of Done:
- [x] `TestIntegration_StartupBindsAfterConstruction` no longer exists; the three tests below exist in
      `drain_startup_integration_test.go`; the mesh-bind-failure comment reads `// Unreachable ACME (port 1).`; the
      `hangACMEListener` comment no longer mentions server construction.

Tests (`internal/server/drain_startup_integration_test.go`, `//go:build integration`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestIntegration_ListenersServeWhileReservedIssuancePending` | with every ACME directory hanging: within 5 s `:443` accepts TCP, an unrouted SNI is closed (`no-route`), and both reserved hosts present NO certificate (`tunneltest.ServesCertificate` false); cancelling + releasing the hang lets `Run` return | existing `newHangACMEListener`; `itServeConfig` |
| `TestIntegration_ReservedCacheServedWhileIssuancePending` | a still-valid but renewal-due `bundle.json` for both hosts, written into `<ACMEAccountDir>/self/<host>/` before `Run`, is served (`ServesCertificate` true, the served leaf equals the cached one) while the first `run` pass is blocked renewing against the hanging directories (the hang listener has received a connection) | bundle from a self-signed cert per host + `store.CertInfo{NotBefore: now-150h, NotAfter: now+10h}` (no CA → the chain's fixed floor NotBefore + 160 h − 48 h is already past, so the renewal starts at once, with no network call to decide it) |
| `TestIntegration_ACMEHTTPListenerOnlyWhenUsed` | with no CA on `http-01`, once `:443` accepts TCP a dial to `ACMEHTTPListen` is refused | `itServeConfig` (dns-01) + hanging ACME; `ACMEHTTPListen = freeAddr(t)` |

### [x] Task 6.4 — New method coverage

- [x] **Action** — modify `internal/server/integration_test.go`: add `"strconv"` to the imports and add the helper
  (shared by the new tests):

```go
func startChallengeServer(t *testing.T, method string, mutate ...func(*config.ServeCmd)) (*itEnv, *tunneltest.LogCounter) {
	t.Helper()
	redisURL := tunneltest.StartValkey(t)
	s3URL, access, secret := tunneltest.StartMinIO(t)
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, itBucket)
	t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")
	for range 5 {
		pebble := tunneltest.StartPebble(t, tunneltest.WithHostValidation())
		t.Setenv("LEGO_CA_CERTIFICATES", pebble.MinicaFile)
		cfg := itServeConfig(t, redisURL, s3URL, access, secret,
			net.JoinHostPort(pebble.HostIP, strconv.Itoa(pebble.TLSPort)), freeAddr(t),
			pebble.DirectoryURL, pebble.DirectoryURL, pebble.DirectoryURL, nil)
		cfg.ACMEDNSProvider = ""
		cfg.ACMEChallengeLE, cfg.ACMEChallengeGTS, cfg.ACMEChallengeZeroSSL = method, method, config.ChallengeHTTP01
		cfg.ACMEHTTPListen = net.JoinHostPort(pebble.HostIP, strconv.Itoa(pebble.HTTPPort))
		for _, m := range mutate {
			m(&cfg)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("config invalid: %v", err)
		}
		logs := tunneltest.NewLogCounter(testLogger().Handler())
		if env, ok := runIntegrationServer(t, cfg, pebble, logs.Logger(), redisURL, s3URL, access, secret); ok {
			return env, logs
		}
	}
	t.Fatal("challenge server never bound Pebble's validation ports after 5 attempts")
	return nil, nil
}
```

- [x] **Action** — create `internal/server/challenge_integration_test.go` (`//go:build integration`, package
  `server`) and add to `e2e/e2e_test.go` the e2e test, per the tables.

Definition of Done:
- [x] `startChallengeServer` is used by every test in `challenge_integration_test.go`; each roundtrip test (integration
      and e2e) asserts both "challenge served" counts.

Tests (`internal/server/challenge_integration_test.go`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestIntegration_ChallengeRoundtrip` (table: `tls-alpn-01`, `http-01`) | reserved certs + Phase-2 public cert issued by Pebble, then the same enroll → bind → frontend roundtrip as `TestIntegration_EnrollConnectRoundtrip`; the configured method's "challenge served" count (`acme tls-alpn-01 challenge served` / `acme http-01 challenge served`) is ≥ 1 and the other method's is 0 | `env, logs := startChallengeServer(t, method)` |
| `TestIntegration_TLSALPNNeverSpliced` | an `acme-tls/1` ClientHello for a bound tunnel's SNI with no pending challenge is closed (`no-route`) and never reaches the phone | `tls-alpn-01` server + bound echo phone |
| `TestIntegration_ACMEHTTPNoKeepAlive` | a response from `env.acmeHTTPAddr` carries `Connection: close` and a second request on the same connection fails | `http-01` server |
| `TestIntegration_ACMEHTTPMissCounted` | a GET for a non-challenge path and an `OPTIONS *` request on `env.acmeHTTPAddr` both return 404, and `http://<env.internalAddr>/metrics` then contains `tunneld_rejections_total{reason="acme-http-miss"} 2` | `http-01` server; `OPTIONS *` sent as a raw request line over TCP |
| `TestIntegration_ACMEHTTPListenerDrains` | after `env.drain()`, a dial to `env.acmeHTTPAddr` is refused | `http-01` server |

Tests (`e2e/e2e_test.go`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestE2E_ChallengeAnsweredByPeerReplica` (table: `tls-alpn-01`, `http-01`) | replica A runs the ACME orders (its reserved certs and the phone's public cert) while Pebble validates against replica B, which answers from Valkey: B's counter shows the configured method's "challenge served" ≥ 1 and the other method's 0, A's counter shows 0 for both; both replicas serve reserved certs (serialized by the cluster lock); a frontend roundtrip via A succeeds | `inf := startE2EInfra(t)`; then up to 5 attempts: `p := tunneltest.StartPebble(t, tunneltest.WithHostValidation())`, `inf.pebble = p` (so `runReplicaOnce` and `echoPhone` use this Pebble's directory and issuing roots), `t.Setenv("LEGO_CA_CERTIFICATES", p.MinicaFile)`, boot B with `inf.runReplicaOnce` (`edgeAddr: p.HostIP:p.TLSPort`, `acmeHTTPListen: p.HostIP:p.HTTPPort`, LE/GTS = method, ZeroSSL `http-01`, `logger: logsB.Logger()`) — a boot that exits before serving retries with a fresh Pebble; then A via `inf.startReplica` (same methods, `logger: logsA.Logger()`); `echoPhone` enrolls + binds through A; the frontend verifies against `p.IssuingRoots` |

---

## US7 — Real-CA staging tier

The same flows against Let's Encrypt staging and GTS staging, on every CI run.

Acceptance criteria:
- [x] `make test-staging` issues reserved + public certificates from LE staging and GTS staging through both
      methods via the reverse tunnel, proving which method answered; it skips (not fails) when
      `TUNNELD_STAGING_SSH_KEY` is empty.
- [x] The node IP, private key, host key, staging domain and the GTS / LE staging account keys never appear in the
      repository, a log, or CI output; in CI they — and the SSH username — exist only as GitHub secrets, on the
      workstation only in `~/.secrets` (mode 600).
- [x] A dead tunnel frees the node's 80/443 within ~2 min; concurrent runs (CI or local) wait for each other
      instead of failing or being cancelled.

### [x] Task 7.1 — Remote endpoint, DNS and secrets (operations)

- [x] **Action** — read-only pre-checks BEFORE any change; if any fails, STOP and ask the user:
  - from the workstation, CAA for `<staging-domain>` and every parent name up to the registered domain
    (`dig +short CAA <name>`): no CAA record, or records authorizing `letsencrypt.org` and `pki.goog` without a
    `validationmethods` parameter that excludes `tls-alpn-01` / `http-01`;
  - on `<staging-node>` as root: nothing listens on `:80` / `:443` (`ss -ltnH 'sport = :80 or sport = :443'`
    prints nothing); the nftables ruleset accepts inbound TCP 80 and 443 (`nft list ruleset`); `sshd -T` shows
    `allowtcpforwarding yes` (or `remote`), `disableforwarding no`, `permitrootlogin` other than `no`, and no
    `permitlisten` restriction (`permitlisten any`);
  - GitHub-hosted runners connect from arbitrary internet addresses: the nftables ruleset accepts inbound TCP 22
    from any source, and `sshd -T -C user=root,host=x,addr=203.0.113.10,laddr=<staging-node>,lport=22` (an
    arbitrary non-workstation source) still shows `permitrootlogin` other than `no`, `allowtcpforwarding yes` (or
    `remote`), and no `allowusers` / `allowgroups` / `denyusers` entry that would refuse root from that source.
- [x] **Action** — on the workstation, generate the dedicated key (never printed):
  `ssh-keygen -q -t ed25519 -N '' -C tunneld-acme-staging -f ~/.secrets/tunneld-staging-ssh`; write
  `~/.secrets/tunneld-staging.env` (mode 600) with `TUNNELD_STAGING_SSH_HOST=<staging-node>`,
  `TUNNELD_STAGING_SSH_USER=root` and `TUNNELD_STAGING_DOMAIN=<staging-domain>`.
- [x] **Action** — on `<staging-node>`, add the public key under a dead-man restore (SSH must never be lost):
  `cp -a /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak`; arm
  `systemd-run --unit=staging-authkeys-rollback --on-active=180 /bin/cp -a /root/.ssh/authorized_keys.bak /root/.ssh/authorized_keys`;
  append a newline first when the file does not end with one (`[ -z "$(tail -c1 /root/.ssh/authorized_keys)" ] || echo >> /root/.ssh/authorized_keys`),
  then append the public key (passed through stdin); verify FRESH root logins from the workstation with the
  existing key AND with `-o IdentitiesOnly=yes -i ~/.secrets/tunneld-staging-ssh`; only then
  `systemctl stop staging-authkeys-rollback.timer` and `rm /root/.ssh/authorized_keys.bak`.
- [x] **Action** — on `<staging-node>`, add the sshd drop-in under the dead-man procedure (SSH must never be
  lost): arm `systemd-run --unit=staging-sshd-rollback --on-active=180 /bin/sh -c 'rm -f /etc/ssh/sshd_config.d/10-acme-staging.conf && systemctl reload ssh'`
  FIRST; write `/etc/ssh/sshd_config.d/10-acme-staging.conf`:

```
GatewayPorts clientspecified
ClientAliveInterval 30
ClientAliveCountMax 4
```

  then `sshd -t && systemctl reload ssh`; verify a FRESH root SSH login from the workstation (existing key) and
  `sshd -T | grep -E '^(gatewayports|clientaliveinterval|clientalivecountmax) '` shows `clientspecified` / `30` /
  `4`; only then `systemctl stop staging-sshd-rollback.timer`.
- [x] **Action** — on the workstation: `ssh-keyscan -t ed25519 <staging-node> > ~/.secrets/tunneld-staging-known-hosts`
  (mode 600) and confirm its key equals the node's `/etc/ssh/ssh_host_ed25519_key.pub` (read over the existing root
  SSH).
- [x] **Action** — from the workstation with the Cloudflare API token in `~/.secrets` (never on the node): create
  `*.<staging-domain>` `A <staging-node>`, proxied false, TTL 300 (no other record touched).
- [x] **Action** — copy `<gts-staging-account-key>` from `<test-node>` to `~/.secrets/gts-staging-account.key`
  (mode 600) through SSH stdout, never printed; confirm it is an EC P-256 key without printing it:
  `openssl pkey -in ~/.secrets/gts-staging-account.key -noout -text | grep -q 'ASN1 OID: prime256v1'`.
- [x] **Action** — on the workstation, generate the Let's Encrypt staging account key (never printed):
  `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ~/.secrets/le-staging-account.key` (mode
  600); the first staging run registers it, every later run re-uses that account.
- [x] **Action** — set the GitHub Actions secrets with `gh secret set <NAME>` reading each value from stdin (never
  on a command line or printed): `TUNNELD_STAGING_SSH_HOST`, `TUNNELD_STAGING_SSH_USER`, `TUNNELD_STAGING_DOMAIN`
  (from `~/.secrets/tunneld-staging.env`), `TUNNELD_STAGING_SSH_KEY` (the private key file),
  `TUNNELD_STAGING_SSH_KNOWN_HOSTS` (the known-hosts file), `TUNNELD_STAGING_GTS_ACCOUNT_KEY` (the GTS account key
  file), `TUNNELD_STAGING_LE_ACCOUNT_KEY` (the LE account key file).

Definition of Done:
- [x] `gh secret list` shows the seven names.
- [x] **Manual Test** — smoke test from the workstation with the new key
      (`ssh -N -F /dev/null -o BatchMode=yes -o ExitOnForwardFailure=yes -o IdentitiesOnly=yes -i ~/.secrets/tunneld-staging-ssh -R 0.0.0.0:80:127.0.0.1:<local port> root@<staging-node>`
      with a local HTTP listener on `<local port>`): `curl http://x.<staging-domain>/` reaches the local listener;
      after `kill -STOP` of the ssh client (a vanished peer: no FIN, no keepalive replies), `ss -ltnH 'sport = :80'`
      on the node is empty within 3 minutes; then `kill -KILL` the stopped client.

### [x] Task 7.2 — Staging test

- [x] **Action** — create `staging/staging_test.go` (`//go:build staging`, package `staging_test`) per the table.

Tests (`staging/staging_test.go`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestStaging_ACMEValidation/le-tls-alpn-01` | LE staging issues both reserved certs and the phone's public cert via TLS-ALPN-01 answered by the local edge through the tunnel; `Identity.CA == "letsencrypt"`; the leaf's only DNS SAN is `<name>.<domain>`; `acme tls-alpn-01 challenge served` ≥ 1 and `acme http-01 challenge served` = 0 | LE dir `https://acme-staging-v02.api.letsencrypt.org/directory`; GTS and ZeroSSL dirs `https://127.0.0.1:1/dir`; `<account-dir>/accounts/letsencrypt.key` written (0600) from `TUNNELD_STAGING_LE_ACCOUNT_KEY`; LE/GTS `tls-alpn-01`, ZeroSSL `http-01` |
| `TestStaging_ACMEValidation/le-http-01` | the same via HTTP-01 (served counts reversed) | as above (incl. the LE account key), all three `http-01` |
| `TestStaging_ACMEValidation/gts-tls-alpn-01` | GTS staging via TLS-ALPN-01; `Identity.CA == "gts"`; served counts as in `le-tls-alpn-01` | LE and ZeroSSL dirs `https://127.0.0.1:1/dir` (LE spills to GTS); GTS dir `https://dv.acme-v02.test-api.pki.goog/directory`; `<account-dir>/accounts/gts.key` written (0600) from `TUNNELD_STAGING_GTS_ACCOUNT_KEY`; no EAB |
| `TestStaging_ACMEValidation/gts-http-01` | GTS staging via HTTP-01 (served counts reversed) | as above, all `http-01` |
| `TestStagingEnv_Redact` (table) | host, user and domain are replaced; SSH key fingerprints (`SHA256:…`) and the remote OpenSSH version (`remote software version …`, `compat_banner: match: … pat`) are redacted; the local version string and words merely containing the user are kept | placeholder `TUNNELD_STAGING_*` values via `t.Setenv`; runs without the staging node |

Setup notes (whole file):
- Skip with `t.Skip` when `TUNNELD_STAGING_SSH_KEY` is empty; when it is set, every other `TUNNELD_STAGING_*`
  variable MUST be non-empty (else `t.Fatal` naming the variable, never its value).
- Nothing secret is printed, and no output is discarded: a redacting writer replaces the host, user and domain
  with `<staging-node>` / `<staging-user>` / `<staging-domain>` line by line and writes to `os.Stdout`; before the
  first `server.Run`, `os.Stderr` and the standard `log` output are swapped for a pipe copied through it (lego's
  log output is bound to `os.Stderr` when the chain is built), restored and flushed in `t.Cleanup` (each error
  reported); `server.Run` gets a fresh `tunneltest.LogCounter` per case whose next handler is a Debug text handler
  on the redacting writer; ssh's stdout and every stderr line (prefixed `ssh: `) go to the redacting writer; every
  error passed to `t.Fatal`/`t.Error` is redacted the same way, and a timed-out wait reports its last error;
  `server.Run`'s result is kept: an early exit fails the readiness waits at once with its redacted error, and a
  non-nil result at the case's shutdown is reported. The
  redaction also replaces SSH key fingerprints (`SHA256:…`) and the node's OpenSSH version (`remote software
  version …`, `compat_banner: match: … pat`), which `ssh -v` prints and would identify the node.
- Valkey + MinIO from `tunneltest` (bucket via `EnsureS3Bucket`); one free local edge port and one free local
  HTTP-01 port (on `127.0.0.1`) reused by every case; `t.Setenv("TUNNELD_ALLOW_ATTESTATION_OPTIONAL", "1")`; an
  internal CA written to `t.TempDir()` the way `e2e/e2e_test.go` `writeCA` does.
- The `config.ServeCmd` literal copies every field value of `e2e/e2e_test.go` `runReplicaOnce`'s literal, except:
  `Listen` / `ACMEHTTPListen` = the two local ports; `TunnelDomain = <domain>`; reserved hosts `e<rand>.<domain>` /
  `c<rand>.<domain>` (fresh per case so no cached authorization skips the challenge); `ACMEEmail:
  "ops@free.example.com"`; `ACMEDNSProvider: ""`, no DNS resolvers; `LimitEnrollMinute: 10`,
  `LimitEnrollHour: 50`, `LimitConnRate: 100` (every client arrives as `127.0.0.1` through the tunnel); the
  per-case directories and methods from the table; `ACMEAccountDir` a fresh `t.TempDir()` per case;
  `cfg.Validate()` MUST pass.
- One reverse tunnel for the whole test: key and known-hosts written to `t.TempDir()` with mode 600, each as
  `strings.TrimRight(value, "\r\n") + "\n"` (GitHub secrets and `$(cat …)` strip the trailing newline OpenSSH
  needs to load the key);
  `ssh -v -N -F /dev/null -o BatchMode=yes -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<tmp> -o IdentitiesOnly=yes -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o ServerAliveInterval=15 -i <tmp key> -R 0.0.0.0:443:127.0.0.1:<edge> -R 0.0.0.0:80:127.0.0.1:<http> <user>@<host>`,
  killed in `t.Cleanup`. Its stderr (`-v` debug output, streamed redacted as above) is read line by line: the
  tunnel is established once both `remote forward success for: listen 0.0.0.0:443` and
  `remote forward success for: listen 0.0.0.0:80` appear (≤ 60 s). A `remote port forwarding failed` line (80/443
  held by another run; ssh then exits) logs `t.Log("remote forward ports busy; retrying in 15s")` and retries every
  15 s for up to 20 min, then fails with "remote forward ports busy"; any other exit or the 60-s bound fails at
  once with a redacted "ssh tunnel failed".
- Tunnel check (every case, after the server is up): an HTTP GET to
  `http://<host>:80/.well-known/acme-challenge/probe` with `Host: probe.<domain>` returns tunneld's 404 (≤ 60 s
  polling; every case binds the local HTTP-01 listener, since ZeroSSL is `http-01` in all four).
- Readiness: wait (≤ 5 min) for both `<account-dir>/self/<host>/bundle.json`; the client trust pool is every
  certificate in both bundles; then `client.Enroll` and assert the issued identity.
- Each case shuts its server down before the next starts.

Definition of Done:
- [x] The first statement of `TestStaging_ACMEValidation` skips when `TUNNELD_STAGING_SSH_KEY` is empty; no
      `t.Log*` call prints an environment value.

### [x] Task 7.3 — Makefile and CI

- [x] **Action** — modify `Makefile`: add `test-staging` to `.PHONY`; add the target and include it in `test-all`;
  add a fourth lint pass `golangci-lint run --build-tags=staging ./...` after the e2e pass; in the lint comment
  REMOVE the now-wrong `Three ` and `, so all three are required` (there are four passes; pure removal — the
  comment then starts with `passes, one per build-tag set:`):

```make
test-staging:
	go test -tags=staging -race -count=1 -timeout 50m -v ./staging/...
```

  `test-all: test-unit test-integration test-e2e test-staging`.
- [x] **Action** — modify `.github/workflows/ci.yml`: in `static-checks` add, after `lint (e2e tags)`:

```yaml
      - name: lint (staging tags)
        uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0
        with:
          version: v2.14.0
          args: --build-tags=staging
```

  and add the job after `test-e2e`:

```yaml
  test-staging:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    concurrency:
      group: acme-staging
      cancel-in-progress: false
      queue: max
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: go.mod
      - run: make test-staging
        env:
          TUNNELD_STAGING_SSH_HOST: ${{ secrets.TUNNELD_STAGING_SSH_HOST }}
          TUNNELD_STAGING_SSH_USER: ${{ secrets.TUNNELD_STAGING_SSH_USER }}
          TUNNELD_STAGING_SSH_KEY: ${{ secrets.TUNNELD_STAGING_SSH_KEY }}
          TUNNELD_STAGING_SSH_KNOWN_HOSTS: ${{ secrets.TUNNELD_STAGING_SSH_KNOWN_HOSTS }}
          TUNNELD_STAGING_DOMAIN: ${{ secrets.TUNNELD_STAGING_DOMAIN }}
          TUNNELD_STAGING_GTS_ACCOUNT_KEY: ${{ secrets.TUNNELD_STAGING_GTS_ACCOUNT_KEY }}
          TUNNELD_STAGING_LE_ACCOUNT_KEY: ${{ secrets.TUNNELD_STAGING_LE_ACCOUNT_KEY }}
```

Definition of Done:
- [x] The Makefile `lint` target has four `golangci-lint run` lines and `ci.yml` four lint steps; the job timeout
      (60 min) exceeds the inner `go test -timeout 50m`.

---

## US8 — Deployment, documentation, ground-up verification

The deployment exposes `:80`, and the canonical docs describe the new behaviour.

Acceptance criteria:
- [x] Compose publishes `80:80`; the env example sets the three methods and leaves the DNS provider and its token
      empty.
- [x] `docs/ARCHITECTURE.md`, `docs/PROJECT.md`, `docs/PROTOCOL.md`, `README.md` and `.claude/rules/project.md`
      carry the exact text below.

### [x] Task 8.1 — Deployment files

- [x] **Action** — modify `deploy/docker-compose.yml` tunneld service: `ports: ["443:443", "80:80"]`; in its
  trailing comment REMOVE the now-wrong `the ONLY published port: the raw SNI edge. ` (the rest — mesh and internal
  never published — stays).
- [x] **Action** — modify `deploy/tunneld.env.example`: change `TUNNELD_ACME_DNS_PROVIDER=cloudflare` to
  `TUNNELD_ACME_DNS_PROVIDER=` and `CF_DNS_API_TOKEN=changeme` to `CF_DNS_API_TOKEN=`, and add after them:

```
TUNNELD_ACME_CHALLENGE_LE=tls-alpn-01
TUNNELD_ACME_CHALLENGE_GTS=tls-alpn-01
TUNNELD_ACME_CHALLENGE_ZEROSSL=http-01
```

Definition of Done:
- [x] The compose tunneld `ports` list is `["443:443", "80:80"]`; `deploy/tunneld.env.example` contains no new
      comment line.

### [x] Task 8.2 — Documentation

- [x] **Action** — modify `docs/ARCHITECTURE.md`:
  - §1: replace `ALL construction — reserved-host cert` / `issuance included — completes BEFORE the `:443` and
    `:9443` listeners bind: a socket is never bound while` / `unserved (a cold-start issuance delays readiness, never
    leaves an accepting-but-dead port).` with:

    > ALL construction completes BEFORE the `:443`, `:9443` and `:9090` listeners (and, when a CA uses HTTP-01,
    > the `:80` challenge listener) bind: a socket is never bound while unserved. A valid reserved-host certificate
    > cached on disk is loaded before the bind; reserved-host issuance runs AFTER the bind, because HTTP-01 /
    > TLS-ALPN-01 validations are answered by the node's own listeners. Until a reserved host has a certificate its
    > TLS is refused (degraded; tunnel splicing is unaffected) and issuance is retried every minute.

  - §1 Mermaid chart: after the `metrics["metrics: internal listener + PromRecorder"]` node line add
    `acmehttp[":80 ACME HTTP-01 challenge listener (only when a CA uses http-01)"]`; after `run --> metrics` add
    `run --> acmehttp`; after `edge --> mesh` add `edge --> acme` and `acmehttp --> acme`.
  - §2: replace `(a hermetic Pebble CA stands in for the test tiers)` with
    `(a hermetic Pebble CA stands in for the integration and e2e tiers; the staging tier uses Let's Encrypt staging + GTS staging)`.
  - package map: replace the `internal/edge` role with
    `raw `:443` SNI edge: ClientHello peek + JA4, reserved-SNI local termination, `acme-tls/1` TLS-ALPN-01 answering, bridge (fast path + mesh), connection policy (idle/min-rate/eviction)`
    and the `internal/acme` role with
    `LE→GTS→ZeroSSL issuance chain (lego; DNS-01 / HTTP-01 / TLS-ALPN-01 per CA, Valkey-shared challenge store + TLS-ALPN-01 challenge certificate, spillover, per-CA cooldown/backoff retry-after, self-heal)`.
  - §2: append after the paragraph ending `— tunneld never sees plaintext.`:

    > **ACME validations.** A ClientHello whose first ALPN protocol is `acme-tls/1` is a TLS-ALPN-01 validation
    > addressed to tunneld itself, not tunnel traffic: after the ban / conn-rate / `--max-clients` checks the edge
    > answers it locally with the challenge certificate built from the Valkey challenge store (ECDSA P-256, key
    > usage `digitalSignature`, critical `id-pe-acmeIdentifier`, one DNS SAN) and never routes or splices it; with
    > no pending challenge it is closed (`no-route`). When a CA uses HTTP-01, a plain `:80` listener
    > (`--acme-http-listen`) serves ONLY `GET`/`HEAD /.well-known/acme-challenge/<token>` from the same store — one
    > request per connection (keep-alives off); any other request is a 404 (`acme-http-miss`) — behind the same check
    > order (ban → conn-rate → the shared `--max-clients` counter), evaluated off the accept loop.

  - §3: replace the final sentence `The name registry record carries the cert metadata; the reserved-host
    (`--enroll-host`/`--control-host`)` / `certs are obtained by the server itself (`ObtainSelf`) at startup and
    renewed on schedule.` with:

    > The name registry record carries the cert metadata; the reserved-host (`--enroll-host`/`--control-host`)
    > certs are obtained by the server itself (`ObtainSelf`) after the listeners bind (a valid disk cache is served
    > immediately), retried every minute while missing, and renewed on schedule. Reserved-host issuance is
    > serialized across replicas by a per-host Valkey lock (`lock:acme-self:{host}`): a replica waits up to 5 min
    > for it, then gets up to 5 min to issue; an issuance abandoned at that deadline keeps the lock until its
    > 10-min TTL (the background lego order may still hold the challenge); a shutdown releases it; a lock error
    > issues without it.
    >
    > Each CA validates with its own method (`--acme-challenge-le` / `--acme-challenge-gts` /
    > `--acme-challenge-zerossl`: `dns-01`, `http-01`, `tls-alpn-01` — ZeroSSL has no `tls-alpn-01`; defaults LE +
    > GTS `tls-alpn-01`, ZeroSSL `http-01`); `--acme-dns-provider` is needed only when a CA uses `dns-01`. The
    > challenge material lives in Valkey, so any replica answers a validation. The TLS-ALPN-01 certificate is
    > tunneld's own: lego's built-in one carries key usage `keyEncipherment` only, which BoringSSL validators
    > (Google Trust Services) reject in TLS 1.3 (RFC 8446 §4.4.2.2). Only ONE TLS-ALPN-01 challenge can be pending
    > per domain cluster-wide (a validator sends only the SNI); a conflicting or failed challenge-store write is a
    > LOCAL error: the chain stops with Retry-After 30 s and sets no per-CA cooldown. When CAA records carry
    > `validationmethods`, they must allow each CA's configured method.

  - §5: replace `single-use enrollment nonces, and per-CA ACME` / `cooldown/backoff.` with
    `single-use enrollment nonces, per-CA ACME cooldown/backoff, the ACME challenge material (`acme:alpn:{domain}` via `SET NX EX` and `acme:http:{domain}:{token}` via `SET EX`, both 10 min; removed only while they still hold this order's value — GET-compare, then DEL), and the reserved-host issuance lock (`lock:acme-self:{host}`, `SET NX EX` 10 min, released the same GET-compare-then-DEL way).`
  - §7: append to the first paragraph, after `The ban` / `check is the FIRST handler-level check on every ingress edge.`:
    ` This includes ACME validation connections (TLS-ALPN-01 on `:443`, HTTP-01 on `:80`): an `ip` / `cidr` / `country` ban can drop a CA's validation perspectives and fail issuance (DNS-01 is unaffected).`
  - §8 rejection table: replace the rows
    `| `ban` | edge accept, enroll handler, phone control handler (each ban gate) |` and
    `| `no-route`, `handshake-timeout`, `conn-rate`, `max-clients` | edge accept/dispatch |` with:

```markdown
| `ban` | edge accept, HTTP-01 accept guard, enroll handler, phone control handler (each ban gate) |
| `no-route` | edge accept/dispatch, edge TLS-ALPN-01 interception (no pending challenge) |
| `handshake-timeout` | edge accept/dispatch |
| `conn-rate`, `max-clients` | edge accept/dispatch, HTTP-01 accept guard |
```

    and append the row
    `| `acme-http-miss` | HTTP-01 handler (an unmatched `:80` request; not in `NoRouteSpike`, covered by `HighRejectionRate`) |`.
  - §9 Mermaid: change `close["close raw :443 listener (stop new public conns)"]` to
    `close["close raw :443 + HTTP-01 :80 listeners (stop new public conns)"]`,
    `drain["Shutdown enroll / control / mesh / internal servers"]` to
    `drain["Shutdown enroll / control / mesh / internal / acme-http servers"]`, and
    `join["join public handlers (Edge.Wait): splice + end-event enqueue + slot release returned"]` to
    `join["join public handlers (Edge.Wait + HTTP-01 guard Wait): splice + end-event enqueue + slot release returned"]`.
  - §10: append `The ACME validation flags are `--acme-challenge-le` / `--acme-challenge-gts` (`dns-01` | `http-01` | `tls-alpn-01`, default `tls-alpn-01`), `--acme-challenge-zerossl` (`dns-01` | `http-01`, default `http-01`) and `--acme-http-listen` (default `:80`, bound only when a CA uses `http-01`).`
- [x] **Action** — modify `docs/PROJECT.md`:
  - "Never publish" paragraph: replace `— only the raw edge `:443` is` / `public;` with
    `— only the raw edge `:443` and, when a CA uses HTTP-01, the ACME challenge listener `:80` are` / `public;`.
  - ACME bullet: replace `with automatic spillover,` / `DNS-01, and short-lived certs` with
    `with automatic spillover,` / `a per-CA validation method (DNS-01 / HTTP-01 / TLS-ALPN-01; defaults LE + GTS TLS-ALPN-01, ZeroSSL HTTP-01 — answered by tunneld's own listeners from Valkey, so any replica answers), and short-lived certs`.
  - §3 Public surface: insert as the FIRST table row
    `| any SNI, first ALPN protocol `acme-tls/1` (checked before the rows below) | ACME TLS-ALPN-01 validation: answered locally with the challenge certificate; no pending challenge → closed (`no-route`); never spliced |`,
    and after the table insert the paragraph
    `When a CA uses HTTP-01, a plain `:80` listener (`--acme-http-listen`) serves ONLY `/.well-known/acme-challenge/<token>` for pending challenges (one request per connection; anything else → 404, `acme-http-miss`).`
  - Ban / geo engine: replace `check on every ingress edge (public, `/api/v1/enroll`, `/api/v1/control`), keyed on the trusted client IP.`
    with
    `check on every ingress edge (public `:443`, the HTTP-01 `:80` listener, `/api/v1/enroll`, `/api/v1/control`), keyed on the trusted client IP — including CA validation connections, so an IP/CIDR/country ban can fail HTTP-01 / TLS-ALPN-01 issuance (DNS-01 is unaffected).`
  - §5 Valkey: replace `single-use enrollment nonces, ACME cooldown/backoff. Every` with
    `single-use enrollment nonces, ACME cooldown/backoff, ACME challenge material (`acme:alpn:` / `acme:http:`, 10 min) and the reserved-host issuance lock (`lock:acme-self:`, 10 min). Every`.
  - §7 Standard commands: replace ``test-integration`, `test-e2e`, `test-scripts`,` with
    ``test-integration`, `test-e2e`, `test-staging`, `test-scripts`,`, and replace `The integration` / `and e2e tiers require Docker (testcontainers: Valkey, MinIO via the PGSTY Silo build, Pebble).` with
    `The integration,` / `e2e and staging tiers require Docker (testcontainers: Valkey, MinIO via the PGSTY Silo build, Pebble); the staging tier also reaches Let's Encrypt staging + GTS staging through a reverse SSH tunnel and skips without `TUNNELD_STAGING_SSH_KEY`.`
- [x] **Action** — modify `docs/PROTOCOL.md`:
  - intro: replace `routes on` / `SNI, and splices` with
    `routes on` / `SNI (a ClientHello whose first ALPN protocol is `acme-tls/1` is an ACME TLS-ALPN-01 validation answered locally by tunneld, never spliced), and splices`.
  - §6: append the bullet
    `- A ClientHello whose first ALPN protocol is `acme-tls/1` is an ACME validation addressed to tunneld: it is answered locally with tunneld's challenge certificate and NEVER spliced to a phone.`
- [x] **Action** — modify `README.md`:
  - replace deployment step 4 (`4. **DNS + ACME**: …` through `… as an operator DNS step.`) with:

```markdown
4. **DNS + ACME**: point `*.<tunnel-domain>`, `<enroll-host>`, and `<control-host>` at this host. tunneld
   issues the phone's public cert (and its own reserved-host certs) via ACME, validated per CA
   (`TUNNELD_ACME_CHALLENGE_LE` / `_GTS` / `_ZEROSSL`; defaults `tls-alpn-01`, `tls-alpn-01`, `http-01`):
   TLS-ALPN-01 is answered on `:443`, HTTP-01 on `:80` (so `:80` must be reachable when a CA uses it). Set
   `TUNNELD_ACME_DNS_PROVIDER` + its credential only for a CA set to `dns-01`. Publish the CAA `issue` records
   for Let's Encrypt / GTS / ZeroSSL as an operator DNS step; if they carry `validationmethods`, allow
   `tls-alpn-01` (LE, GTS) and `http-01` (ZeroSSL).
```

  - "Never publish": replace `— only the raw edge `:443` is` / `public.` with
    `— only the raw edge `:443` and the ACME HTTP-01 listener `:80` are` / `public.`.
  - ban paragraph: replace `check on every ingress edge (public, `/api/v1/enroll`, `/api/v1/control`), keyed on the trusted client IP.`
    with
    `check on every ingress edge (public `:443`, the HTTP-01 `:80` listener, `/api/v1/enroll`, `/api/v1/control`), keyed on the trusted client IP — including CA validation connections, so an IP/country ban can fail HTTP-01 / TLS-ALPN-01 issuance.`
  - The step-3 shell line (`… + the lego DNS-provider secret`) stays: the env file is still where that secret goes
    when `dns-01` is used.
- [x] **Action** — modify `.claude/rules/project.md`:
  - Tech Stack ACME row notes: `LE→GTS→ZeroSSL chain, DNS-01 / HTTP-01 / TLS-ALPN-01 per CA (answered by tunneld's own listeners from Valkey-shared challenge state), spillover, per-CA cooldown/backoff retry-after, self-heal.`
  - Tech Stack integration row notes: `Valkey + MinIO (PGSTY Silo build) + Pebble/challtestsrv (`//go:build integration` / `e2e` / `staging`); needs Docker. The `staging` tier also uses real LE / GTS staging through a reverse SSH tunnel.`
  - Tech Stack edge row notes: replace `one `tunneld` on :443,` with `one `tunneld` on :443 (+ :80 for ACME HTTP-01),`.
  - End-to-end encryption invariant: append
    ` A ClientHello whose first ALPN protocol is `acme-tls/1` is an ACME TLS-ALPN-01 validation addressed to tunneld — answered locally with its challenge certificate and NEVER spliced (it carries no tunnel traffic).`
  - Source-IP + ingress: replace `(public SNI, `/api/v1/enroll`,` / ``/api/v1/control`)` with
    `(public SNI, the ACME HTTP-01 `:80` listener, `/api/v1/enroll`,` / ``/api/v1/control`)`; replace
    `only the raw edge `:443` is public.` with `only the raw edge `:443` and the ACME HTTP-01 listener `:80` are public.`;
    replace `- The public edge dispatches by SNI:` with
    `- The public edge answers a ClientHello whose first ALPN protocol is `acme-tls/1` locally (TLS-ALPN-01), then dispatches by SNI:`.
  - Valkey invariant: replace `enrollment nonces, ACME cooldown/backoff, the per-name` / `locks)` with
    `enrollment nonces, ACME cooldown/backoff, the ACME challenge keys `acme:alpn:` / `acme:http:`, the per-name` /
    `locks and the reserved-host issuance lock `lock:acme-self:`)`.
  - Observability: append to the cap-hit bullet
    ` `acme-http-miss` (an unmatched `:80` request; empty tunnel value) uses the standard dedup and is kept out of the `NoRouteSpike` alert.`
  - Commit Scopes: the `acme` row becomes
    `| `acme` | `internal/acme`: LE→GTS→ZeroSSL issuance chain (lego clients, DNS-01 / HTTP-01 / TLS-ALPN-01, challenge store, per-CA cooldown/backoff retry-after) |`;
    add after the `e2e` row `| `staging` | `staging/`: real-CA staging tier (LE / GTS staging through the reverse SSH tunnel) |`.
  - Standard Commands: `make lint` line becomes
    `- `make lint` — `golangci-lint` ×4 (default / `integration` / `e2e` / `staging` build tags — tagged files are`;
    add after the `make test-e2e` line
    `- `make test-staging` — `-tags=staging` suite (`-race`; real `server.Run` against Let's Encrypt staging + GTS staging through a reverse SSH tunnel; skips without `TUNNELD_STAGING_SSH_KEY`; needs Docker)`;
    the `make test-all` line becomes `- `make test-all` — `test-unit` + `test-integration` + `test-e2e` + `test-staging``;
    append to the "There is NO dotenv convention" paragraph's sentence ending `need a` / `working Docker daemon.`:
    ` The staging tier additionally reads seven `TUNNELD_STAGING_*` environment variables (GitHub secrets in CI) and skips when `TUNNELD_STAGING_SSH_KEY` is empty.`;
    in the CI sentence replace `(lint ×3,` with `(lint ×4,` and `` `test-e2e`,`` + ` and `image`` with
    `` `test-e2e`, `test-staging`,`` + ` and `image``.
  - Key Conventions / Testing: replace `e2e (`//go:build e2e`) = two in-process replicas + shared testcontainers.` with
    `e2e (`//go:build e2e`) = two in-process replicas + shared testcontainers; staging (`//go:build staging`, `staging/`) = the real server against Let's Encrypt staging + GTS staging through a reverse SSH tunnel (every CI run; skips without the key).`

Definition of Done:
- [x] `grep -rn 'DNS-01' docs/PROJECT.md docs/ARCHITECTURE.md README.md .claude/rules/project.md` shows no sentence
      that still presents DNS-01 as the only method; every replaced string above is gone from its file.

### [x] Task 8.3 — Ground-up double-check + quality gates

- [x] **Action** — re-read this plan from the top and verify EVERY action landed (US1–US8); `git diff main` adds NO
  comment line to hand-written code in any language (Go, YAML, Makefile, systemd units, sshd drop-ins, env files;
  exempt: action `# vX.Y.Z` tags) and every REMOVE instruction is applied.
  `grep -rn 'tlsalpn01\.\(ChallengeCert\|ChallengeBlocks\|NewProviderServer\)' --include='*.go' .` returns nothing;
  `grep -rn 'Eval\|TxPipelined\|Watch(' internal/acme/challenge_store.go` returns nothing;
  `grep -rn 'newGuardedListener' --include='*.go' internal/` shows only `acmehttp.go`, its test and the `:80` wiring in
  `server.go`.
- [x] **Action** — connect the Realme T70 (single adb device), then run every gate ONCE with output captured
  (agent.md §5), fix anything surfaced, and re-run: `make lint` (four tag sets), `make vet`, `make govulncheck`,
  `make build`, `make test-unit`, `make test-integration`, `make test-e2e` (MUST show `TestE2E_DeviceAttestation`
  and `TestE2E_ReferenceTunnelApp` PASS), `make test-scripts`, `make compose-config`, `make mermaid-check`
  (validates the changed §9 chart and every other chart), `make tidy` + `git diff --exit-code -- go.mod go.sum`.
- [x] **Action** — run `make test-staging` with NO `TUNNELD_STAGING_*` variable set
  (`make test-staging 2>&1 | tee /tmp/p14-test-staging-skip.log | tail -5`): the test reports SKIP, not FAIL.
- [x] **Action** — run the staging tier locally (MUST run, not skip, and pass), never echoing a secret, while first
  proving the busy-port wait (**Manual Test**): hold the node's 80/443 with the Task 7.1 smoke-test tunnel (both `-R 0.0.0.0:80` and
  `-R 0.0.0.0:443`), start the command below, confirm `/tmp/p14-test-staging.log` shows
  `remote forward ports busy; retrying in 15s`, then close the smoke tunnel so the run proceeds:
  `bash -c 'set -a; . ~/.secrets/tunneld-staging.env; set +a; TUNNELD_STAGING_SSH_KEY="$(cat ~/.secrets/tunneld-staging-ssh)" TUNNELD_STAGING_SSH_KNOWN_HOSTS="$(cat ~/.secrets/tunneld-staging-known-hosts)" TUNNELD_STAGING_GTS_ACCOUNT_KEY="$(cat ~/.secrets/gts-staging-account.key)" TUNNELD_STAGING_LE_ACCOUNT_KEY="$(cat ~/.secrets/le-staging-account.key)" make test-staging' 2>&1 | tee /tmp/p14-test-staging.log | tail -20`.
- [x] **Action** — push the branch and run CI: ALL jobs green, `test-staging` included (it MUST run with the
  secrets, not skip).
- [x] **Action** — confirm no secret value (node IP, key material, staging domain) appears in the
  repository (`git grep` for each value read from `~/.secrets`, values never printed) or in the CI logs of the run.

Definition of Done:
- [x] Every checkbox above is `[x]`; all gates green on the final code.

## Deviations

- **Decision 8 / Task 7.1 — staging domain placement.** The plan described `<staging-domain>` as a sub-zone of the
  deployment's tunnel zone. The user chose (2026-10-11) a name directly under the registered domain instead, so the
  staging tier does not depend on the still-unconfirmed tunnel zone. Decision 8 is updated; the value stays a secret.
- **Task 7.1 — DNS record metadata.** The wildcard A record was created with a Cloudflare record comment naming its
  purpose (the CI ACME staging tier), so it is identifiable among the zone's other records. No other record was
  touched.
- **Task 3.3 — context-done branch.** The planned `return nil, store.CertInfo{}, err` in `chain.run`'s context-done
  branch could hand a `ClassLocal` error to a caller outside `internal/acme` when a challenge-store failure
  coincided with cancellation, contradicting the task's DoD. The branch now returns
  `transient(fmt.Errorf("%w (CA order: %v)", ctx.Err(), err))` (still `errors.Is(err, context.Canceled)`; the
  interrupted order's error is carried as text, never as a reachable class, per the never-discard rule), and
  `TestChain_StopsWhenContextDone` gained that case and asserts the carried text (code review).
- **Out-of-plan comment removal — `internal/enroll/enroll.go`.** The `csrMatchesTunnel` comment presented a
  zone-wide DNS-01 provider (and wildcards) as the reason extra identifiers were satisfiable; with per-CA methods
  DNS-01 is optional and off by default, so the now-wrong part was removed (pure removal, re-flowed) under the
  user's comment rule (code review).
- **Never-discard-logs-or-errors rule (user mandate, 2026-10-11) — Decisions 8/9, Tasks 2.4, 3.3, 4.2, 5.2, 5.3,
  6.1, 6.2, 6.4, 7.2.** The user ruled that logs and errors are never discarded: errors are handled, returned or
  classified, and an unexpected one is at least logged; output that may hold secrets is redacted, not dropped.
  Applied in this PR (the user chose to include the pre-existing spots it touches):
  - `chain.run` / `handleFailure` log each CA's order failure (`acme CA order failed`, with `ca`, `name`, `class`,
    `err`) and each best-effort Valkey cooldown/streak error instead of dropping them; `ChainConfig.Logger`
    (defaulting to `slog.Default()`, as `Recorder` defaults to a no-op) is set by `buildACMEChain`. This exposed
    the staging LE failure cause, which the aggregated "all issuance CAs are rate-limited" error hid.
  - The HTTP-01 handler logs a failed response write; the TLS-ALPN-01 interception logs a failed close or
    deadline (returning on the latter); the `:80` guard logs a conn-rate limiter error (still fail-open), a
    backed-off accept error at Warn, and failed closes; `server.Run` logs failed listener closes, server
    shutdowns, the Valkey client close and the admin JSON encode error (`closeLogged` / `shutdownLogged`).
  - `tunneltest.LogCounter` forwards every record to a next handler; the test loggers in `internal/ban`,
    `internal/metrics`, `internal/edge`, `internal/server` and `e2e` write Debug text to stderr instead of
    discarding (`discardLogger` → `testOutputLogger` in `e2e`); the staging test streams redacted output (Task 7.2).
  - New test code checks the errors it used to drop (deadlines, store lookups, stub encodes, body drains, the
    tunnel client's `Run`). Its probe and cleanup closes go through a per-package `closeOrLog(t, c)` test helper
    (`internal/acme`, `internal/edge`, `internal/server`) that logs any close error other than `net.ErrClosed`;
    closes in goroutines that can outlive the test log through the slog test logger; `captureClientHello`
    asserts its expected handshake failure; `tunneltest.ServesCertificate` takes `t` and returns the probe error,
    which `WaitReservedHosts` and `runIntegrationServer` report on timeout (with the server's `Run` result); the
    Docker client close in `networkGateway` is logged; the staging case keeps `server.Run`'s result, failing its
    readiness waits at once on an early exit and reporting a non-nil result at shutdown (Task 7.2).
  - Tests: `TestChain_LogsEachCAFailure` and `TestChain_LogsBookkeepingErrors` added to Task 3.3;
    `TestConnRateAllow` and `TestGuardListener_AcceptErrorBackoff` assert the new log lines (Task 5.2).
- **Task 5.3 — drain closes the `:80` listener once (code review).** Logging the drain's `Shutdown` errors exposed a
  race: `serveTLS`'s cancel goroutine and the drain both closed the same listener, so a clean drain could log
  `use of closed network connection`, and the drain closed `acmeHTTPLn` underneath `guarded`. The drain now closes
  `guarded` (which closes `acmeHTTPLn`), `shutdownLogged` treats `net.ErrClosed` as a clean shutdown, and
  `serveTLS` closes its listener through `closeLogged`. Tests: `TestCloseLogged`, `TestShutdownLogged`.
- **Task 7.2 — SSH identity redaction (code review).** Streaming `ssh -v` exposed the node's host-key fingerprint,
  the CI key's fingerprint and the node's OpenSSH version in the public CI log; the redaction now covers them, and
  `TestStagingEnv_Redact` pins it.
- **Tasks 6.3 / 6.4 test helpers — errors surfaced (code review).** `metricLineValue` returns its scrape/parse error
  and `waitMetric` reports the last value and error on timeout; `presentedLeaf` includes the dial error; the
  integration echo phone logs a failed handshake or echo.
- **Task 8.3 — staging gate red, then green after Let's Encrypt staging recovered.** From 2026-10-11 ~20:00 UTC
  to ~22:00 UTC Let's Encrypt staging rejected every order with `During secondary validation: DNS problem:
  networking error looking up A/AAAA` (from CI and from the workstation, while every public resolver and the
  zone's authoritative servers answered correctly and the GTS cases passed): an outage of LE staging's remote
  validation perspectives, outside tunneld. The Task 8.3 staging/CI items were unchecked meanwhile. After LE
  recovered, CI run 38178341702 on f7f430e passed every job (`test-staging` 4/4, one last LE secondary-validation
  rejection at 21:59 UTC absorbed by the chain's retry), the local run passed 4/4 with the busy-port Manual Test
  observed, and the per-value `git grep` and CI-log scan of every `~/.secrets` value found zero occurrences (the
  run's `ssh -v` lines show only `<staging-node>`, `SHA256:<redacted>` and `remote software version <redacted>`).
