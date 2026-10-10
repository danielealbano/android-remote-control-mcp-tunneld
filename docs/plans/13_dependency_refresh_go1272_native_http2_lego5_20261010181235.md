<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 13 — Dependency refresh: Go 1.27.2, native HTTP/2, lego v5, Silo, CI + Android toolchains

## Scope

Agreed with the user — bring EVERY dependency to its latest stable release and make CI green again:

- **Go 1.27.2** + every module required by `go.mod` at its latest version; `make govulncheck` clean. Go 1.27.1
  is NOT enough: the standard-library vulnerabilities our code calls (11 reported by `govulncheck` on today's tree,
  alongside grpc GO-2026-6348, which the module refresh fixes) are fixed only in go1.26.9 / go1.27.2.
- **`golang.org/x/net/http2` → net/http's built-in HTTP/2.** The vulnerability fixes need x/net ≥ v0.60.0,
  which deprecates `http2.ConfigureServer` / `http2.Server` (`http2/server_common.go`) AND `http2.Transport` /
  `http2.ConfigureTransport(s)` (`http2/transport_common.go`, verified in x/net v0.61.0), so staticcheck SA1019
  fires in all six importing files and lint suppression is FORBIDDEN: the move is lint-forced on both sides. The
  user decided to use net/http's built-in HTTP/2 throughout ("Move", 2026-10-10).
- **lego v4.35.2 → `github.com/go-acme/lego/v5` v5.5.2.** go-acme's security policy
  (`github.com/go-acme/.github`, `security.md`): "Only the latest version of lego is supported. We will only
  release security updates for the latest version."
- **MinIO → PGSTY Silo images** (`pgsty/silo` + `pgsty/mc`, `RELEASE.2026-09-16T00-00-00Z`). The official
  `minio/minio` + `minio/mc` images are no longer published (pull access denied) — the sole cause of the
  failing integration + e2e CI jobs.
- **ALL GitHub Actions** to their latest release (commit-SHA pinned), golangci-lint v2.14.0 (Go 1.27 support
  starts at v2.13.0), Node 24 (the LTS line, also the user's local Node) + mermaid-cli 12.0.0 for
  `make mermaid-check`, and job timeouts (a CI job hung ~6 h).
- **`deploy/docker-compose.yml` images** to their latest releases.
- **`support/` Android test apps**: Gradle 9.8.1 + AGP 9.4.1 + Kotlin 2.4.21 + latest libraries (user decision
  2026-10-10: "latest", accepting that this pair is newer than Kotlin 2.4.21's documented fully-supported range
  Gradle ≤ 9.7.0 / AGP ≤ 9.3.1 — it builds cleanly); `compileSdk 37` (required by okhttp 5.5.0), `targetSdk`
  STAYS 36 (user decision 2026-10-10); APK fixtures regenerated from clean builds; adb device tests re-run (the
  Realme T70 MUST be connected for Task 8.2). Communicated to the user on 2026-10-10 as "things I'll decide unless
  you object" (no objection): pin the Gradle distribution SHA-256 in both wrappers, gitignore Kotlin's per-project
  `.kotlin/` directories, delete the deprecated `android.useAndroidX=false` (its AGP 9 deprecation warning is not
  the accepted one). The fourth item of that list, "fix a stale comment" (the okhttp line's
  `// 5.x requires compileSdk 37`), is superseded by the user's later SACRED comment rules: this change does not
  make that comment wrong, so it stays unchanged.
- **Accepted upstream warning (user decision 2026-10-10):** AGP 9.4.1 itself emits Gradle's
  `Configuration.setVisible(boolean)` deprecation warning (and Gradle's resulting "Deprecated Gradle features were
  used" summary line); it cannot be fixed from our build scripts. Every OTHER warning is still forbidden.
- **Fix the compose alert bridge** (user decision 2026-10-10): Alertmanager could never reach `ntfy-alertmanager` —
  the compose file mounts the config at `/etc/ntfy-alertmanager/config.scfg` while the image's binary reads
  `/etc/ntfy-alertmanager/config` ("Failed to read config"), and the bridge's default listen address is
  `127.0.0.1:8080` (unreachable from the Alertmanager container). Both verified on 2026-10-10 against the v1.0.1
  image and its `config/config.go` (`http-address` directive).
- Close every superseded Dependabot PR (Task 8.2).
- Branch: `chore/plan-13-dependency-refresh` (github.md `<type>/plan-<n>-<desc>`).

SACRED user rules applied to this plan and its implementation: NO comments ADDED to hand-written code (in any
language, tests included); an existing comment that a change makes wrong is REMOVED (the wrong part only — never
rewritten); existing correct comments stay untouched — an existing comment kept verbatim on a modified line (e.g.
the trailing comments on the bumped dependency lines in Task 7.2) is NOT an added comment; no nits. Exempt (user,
2026-10-10): AUTO-GENERATED files
(the Gradle wrapper `gradlew` / `gradlew.bat` regenerated in US7 keep whatever Gradle's template emits) and the
version annotations on dependency pins (the `# vX.Y.Z` tags after the action SHAs in US6 are updated with the pins).

Behaviour-preservation decisions — the migrations MUST NOT change runtime behaviour:

- **HTTP/2 clients** (phone control client, mesh, e2e `h2Client`): `MaxConnsPerHost: 1` (x/net de-duplicated
  the first dial; net/http otherwise dials one connection per concurrent request on a cold pool; a saturated
  connection still opens a second one, as x/net did) and an **ALPN guard** in `DialTLSContext` (x/net with a
  custom dialer always spoke HTTP/2; net/http silently falls back to HTTP/1.1 when the server does not negotiate
  `h2`, which cannot carry the full-duplex streams).
- **HTTP/2 servers** (control, mesh): keep HTTP/2 + HTTP/1.1 exactly as `http2.ConfigureServer` did, and set
  `TLSConfig.NextProtos` explicitly — `Serve` on a pre-built `tls.Listener` enables HTTP/2 only when the
  server's `TLSConfig.NextProtos` contains `"h2"`.
- **lego**: keep the recursive-nameserver propagation requirement OFF (the v4 default; v5 turns it on — verified
  on 2026-10-10: with it on, a ZeroSSL DNS-01 issuance timed out client-side behind a home-router resolver; with
  it off the same issuance succeeded in 30 s); apply the DNS-01 resolvers per `NewLegoClient` (same timing as
  v4's `AddRecursiveNameservers`; both process-global in lego); keep lego's log output on **stderr** (v4 used
  Go's std `log` on stderr; v5's default is a stdout `TextHandler`); the lazy per-CA build survives its first
  caller's cancellation, and its registration call is bounded by `lazyBuildTimeout` (2 min — the same bound as
  `dnsProviderTimeout`; the ACME directory fetch inside the ctx-less `lego.NewClient` is bounded by lego's own
  2-minute HTTP client timeout);
  the `ObtainForCSR` call gets a ctx DETACHED from its caller (`context.WithoutCancel`, no extra deadline — exactly
  v4's ctx-less call), because v5 uses that ctx for the propagation pre-check, validation, the challenge cleanup and
  the authorization deactivation: an aborted `/api/v1/issue` MUST still remove its `_acme-challenge` TXT records, as
  v4 did. No outer deadline is added because it would cut issuances v4 completed: lego bounds every request itself
  (2 min HTTP client timeout, `lego/client_config.go`), while its legitimate long waits — a provider's propagation
  timeout (e.g. 1 h for namecheap) and validation polling up to 100× the CA's Retry-After — are lego's own policy.
  The lego logger wiring lives in `internal/acme` (`acme.SetLogOutput`), so production code outside
  `internal/acme` never imports lego. `EnableCommonName` is NOT needed: `ObtainForCSR` sends the CSR unchanged.
- **Go version pinning**: `go.mod` declares `go 1.27.2` with no `toolchain` line; the `Dockerfile` pins
  `golang:1.27.2` (the official image sets `GOTOOLCHAIN=local`, so it MUST satisfy `go.mod`); the release
  workflow reads the version from `go.mod`.
- **Naming**: Silo is the maintained build of the open-source MinIO server and keeps its CLI and `MINIO_*`
  environment, so `StartMinIO`, the compose service `minio`, the `MINIO_*` variables and the existing comments
  stay; only the images and the docs change.

Unchanged (already latest or out of scope): `valkey/valkey:9.1-alpine` (resolves to 9.1.2; 9.2 is an rc),
`alpine:3`, `gcr.io/distroless/static:nonroot`, Pebble + challtestsrv 2.10.1, kong, testcontainers-go,
lumberjack.v2, the CI `shellcheck` install step.

No Mermaid charts are added or modified, so the §9 Mermaid-validation step does not apply;
`make mermaid-check` still runs as a quality gate (now on mermaid-cli 12).

## User Stories

- [x] **US1 — Go 1.27.2 + Go module refresh**
- [x] **US2 — Migrate to net/http's built-in HTTP/2**
- [x] **US3 — Migrate to lego v5**
- [x] **US4 — Replace the unpublished MinIO images with PGSTY Silo**
- [x] **US5 — Refresh the deploy compose images**
- [x] **US6 — Refresh CI + release workflows**
- [x] **US7 — Refresh the `support/` Android toolchains + regenerate fixtures**
- [x] **US8 — Documentation + ground-up verification**

---

## US1 — Go 1.27.2 + Go module refresh

The standard-library and x/net / grpc vulnerability fixes require go1.27.2 and the latest modules.

Acceptance criteria:
- [x] `go.mod` declares `go 1.27.2` and has NO `toolchain` line.
- [x] Every module required by `go.mod` is at its latest version within its major (checked in Task 8.2, after
      US3's re-refresh).
- [x] The `Dockerfile` builds on `golang:1.27.2`; `release.yml` takes the Go version from `go.mod`.

### [x] Task 1.1 — Bump the toolchain and every module

- [x] **Action** — run at the repo root (default `GOTOOLCHAIN=auto` downloads go1.27.2):

```sh
go get go@1.27.2 toolchain@none
go get -u -t ./...
go get -u -t -tags=integration,e2e ./...
go get -u tool
go mod tidy
```

- [x] **Action** — modify `Dockerfile` line 1:

```dockerfile
FROM golang:1.27.2 AS build
```

- [x] **Action** — modify `.github/workflows/release.yml`, the `actions/setup-go` step's `with:` (its SHA is
  bumped in US6):

```yaml
        with:
          go-version-file: go.mod
```

Definition of Done:
- [x] `golang.org/x/vuln` (the `tool` requirement) is v1.8.0 or newer; `release.yml` no longer contains
      `go-version: '1.26'`.

No new tests: the full suites + `make govulncheck` in Task 8.2 verify the bump.

---

## US2 — Migrate to net/http's built-in HTTP/2

Remove every `golang.org/x/net/http2` import (6 files) without changing behaviour (see Scope).

Acceptance criteria:
- [x] No file in any build-tag set imports `golang.org/x/net/http2`; `golang.org/x/net` is `// indirect`.
- [x] The control client and the mesh client open ONE connection for concurrent requests on a cold pool,
      open a second one only when the first is saturated, reconnect after a drop, and refuse a peer that does
      not negotiate ALPN `h2`.
- [x] The control and mesh servers serve HTTP/2 (and HTTP/1.1) on their pre-built `tls.Listener`.
- [x] Mesh PING health keeps its timings (`readIdle` → `SendPingTimeout`, `pingTimeout` → `PingTimeout`).

### [x] Task 2.1 — Phone control client transport

- [x] **Action** — modify `client/control.go`: drop the `golang.org/x/net/http2` import; field
  `tr *http2.Transport` → `tr *http.Transport`; declare `errNotHTTP2` above `newMTLSTransport`'s doc comment (the
  package has no other package-level errors; the doc comment MUST stay attached to `newMTLSTransport`); replace
  `newMTLSTransport`'s signature + body (its existing doc comment stays unchanged); add `requireH2`.

```go
var errNotHTTP2 = errors.New("client: server did not negotiate HTTP/2 (ALPN h2)")

func newMTLSTransport(dialAddr, controlHost string, caPool *x509.CertPool, getCert func() *tls.Certificate) *http.Transport {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	return &http.Transport{
		Protocols:       &protocols,
		MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
				ServerName: controlHost, RootCAs: caPool, MinVersion: tls.VersionTLS12,
				NextProtos:           []string{"h2"},
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return getCert(), nil },
			}}
			conn, err := d.DialContext(ctx, network, dialAddr)
			if err != nil {
				return nil, err
			}
			return requireH2(conn)
		},
	}
}

func requireH2(conn net.Conn) (net.Conn, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok || tc.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, errNotHTTP2
	}
	return conn, nil
}
```

Context: `Client.Close` keeps calling `c.tr.CloseIdleConnections()` (provided by `*http.Transport`).

Definition of Done:
- [x] `client/control.go` no longer imports `golang.org/x/net/http2`; the `Client` struct holds `*http.Transport`.

Tests (`client/control_test.go`, package `client`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestNewMTLSTransport_RejectsNonH2Server` | a request fails with `errors.Is(err, errNotHTTP2)` | raw `tls.Listen` + `http.Server.Serve` with `NextProtos` NIL (NOT `httptest`, which injects `http/1.1` and turns this into a handshake alert) |
| `TestNewMTLSTransport_OneConnForConcurrentColdRequests` | 8 concurrent requests on a cold transport open exactly 1 TCP connection | count `Accept`s on the listener; server advertises `h2` |
| `TestNewMTLSTransport_OpensSecondConnWhenStreamsSaturated` | with the server's `HTTP2.MaxConcurrentStreams: 2`, a 3rd held-open stream is served on a 2nd TCP connection and all 3 succeed | DETERMINISTIC: open stream 1 and wait for its response headers (the client has then read the server's SETTINGS), then open streams 2 and 3 one after another, each held open; assert accept count 2 |
| `TestNewMTLSTransport_ReconnectsAfterConnDrop` | after the server closes the live connection, a request succeeds on a NEW connection | close the server-side conn via a listener wrapper; retry the request until success within a 5 s deadline, then assert exactly 2 accepts |

### [x] Task 2.2 — Mesh client transport

- [x] **Action** — modify `internal/mesh/client.go`: drop the `golang.org/x/net/http2` import; declare
  `errPeerNotHTTP2` next to `ErrNoOwner`; replace `newH2Client`'s body (its existing doc comment stays
  unchanged); add `requirePeerH2`.

```go
var errPeerNotHTTP2 = errors.New("mesh: peer did not negotiate HTTP/2 (ALPN h2)")

func (c *Client) newH2Client() *http.Client {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	cfg := c.tlsConf()
	tr := &http.Transport{
		Protocols:       &protocols,
		HTTP2:           &http.HTTP2Config{SendPingTimeout: c.readIdle, PingTimeout: c.pingTimeout},
		MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: c.dialTimeout}, Config: cfg}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return requirePeerH2(conn)
		},
	}
	return &http.Client{Transport: tr}
}

func requirePeerH2(conn net.Conn) (net.Conn, error) {
	tc, ok := conn.(*tls.Conn)
	if !ok || tc.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, errPeerNotHTTP2
	}
	return conn, nil
}
```

Context: `c.tlsConf()` already sets `NextProtos: ["h2"]` and an empty `ServerName`; `tls.Dialer` infers SNI
from `addr` — the same SNI x/net's per-dial clone carried.

Definition of Done:
- [x] `internal/mesh/client.go` no longer imports `golang.org/x/net/http2`; `readIdle`/`pingTimeout` feed
      `HTTP2Config`.

Tests (`internal/mesh/mesh_test.go`, package `mesh`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestClient_RejectsNonH2Peer` | `OpenStream` fails with `errors.Is(err, errPeerNotHTTP2)` | raw `tls.Listen` mesh-role peer with `NextProtos` NIL (not `httptest`) |
| `TestClient_OneConnForConcurrentColdStreams` | 8 concurrent `OpenStream`s on one pooled client (pool size 1) open exactly 1 TCP connection | count `Accept`s on the peer listener |
| `TestClient_OpensSecondConnWhenStreamsSaturated` | with the peer's `HTTP2.MaxConcurrentStreams: 2`, a 3rd held-open stream is served on a 2nd TCP connection and all 3 succeed | peer `http.Server{HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 2}}`; DETERMINISTIC: open stream 1 and wait for its response headers (SETTINGS read), then streams 2 and 3 one after another, each held open; assert accept count 2 |
| `TestClient_ReconnectsAfterPeerConnDrop` | after the peer closes the live connection, an `OpenStream` succeeds on a NEW connection | listener wrapper exposing the accepted conns; retry until success within a 5 s deadline, then assert exactly 2 accepts |
| `TestClient_NewH2ClientMapsPingTimeouts` | `newH2Client`'s transport carries `HTTP2.SendPingTimeout == readIdle` and `HTTP2.PingTimeout == pingTimeout` | white-box; DIFFERENT durations for the two fields |
| `TestOpenStreamUnblocksOnDeadPeer` (existing) | still passes — PING health via `SendPingTimeout`/`PingTimeout` | unchanged |

### [x] Task 2.3 — Control + mesh servers

- [x] **Action** — modify `internal/server/serve.go`: add the two helpers above `serveTLS`'s doc comment (which MUST
  stay attached to `serveTLS`); in `serveTLS`'s doc
  comment REMOVE the now-wrong clause ` — http2.ConfigureServer was applied at the call site` (leaving
  `(enroll/control/mesh)`).

```go
func h2Protocols() *http.Protocols {
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	return &p
}

func h2NextProtos() []string { return []string{"h2", "http/1.1"} }
```

- [x] **Action** — modify `internal/server/server.go`: drop the `golang.org/x/net/http2` import; add
  `Protocols` + `NextProtos` to `controlSrv` and `meshSrv`; delete both `http2.ConfigureServer` blocks (with their
  `configure … http2` error returns); in the "Bind the public + mesh listeners LAST" comment REMOVE the
  now-wrong words ` and both http2.ConfigureServer calls` (leaving `(reserved-cert issuance)`).

```go
	controlSrv := &http.Server{Handler: phoneHandler, ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout: 4 * cfg.ControlPingInterval,
		ConnContext: phoneconn.ConnContext,
		Protocols:   h2Protocols(),
		TLSConfig: &tls.Config{GetCertificate: reserved.getCertificateFor(cfg.ControlHost),
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caObj.Pool(), MinVersion: tls.VersionTLS12,
			NextProtos: h2NextProtos()}}

	meshSrv := &http.Server{Handler: meshHandler, ReadHeaderTimeout: readHeaderTimeout,
		Protocols: h2Protocols(),
		TLSConfig: &tls.Config{GetCertificate: meshCert.getCert, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: caObj.Pool(), MinVersion: tls.VersionTLS12, NextProtos: h2NextProtos()}}
```

Context: the existing comments above `controlSrv` and `meshSrv` stay unchanged (still correct).

Definition of Done:
- [x] `grep -n 'ConfigureServer' internal/server/*.go` returns nothing.

Tests (`internal/server/serve_test.go`, package `server`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestServeTLS_ServesHTTP2OnPrebuiltListener` | `serveTLS` answers an `h2`-ALPN client with `resp.Proto == "HTTP/2.0"` and an `http/1.1`-ALPN client with `"HTTP/1.1"` | mirror `server.go`: `srv.Protocols = h2Protocols()`, `srv.TLSConfig = &tls.Config{Certificates: …, NextProtos: h2NextProtos()}` (NON-nil — a nil `TLSConfig` takes net/http's always-HTTP/2 compatibility branch and would not test the property), listener `tls.NewListener(ln, srv.TLSConfig)`; self-signed cert; cancel ctx at the end |

### [x] Task 2.4 — Test harnesses + e2e helper

- [x] **Action** — modify `client/enroll_test.go`: drop the x/net import and the `http2.ConfigureServer` block
  in `startEnrollServer` (its `tlsConf` already lists `NextProtos: ["h2","http/1.1"]`).
- [x] **Action** — modify `client/harness_test.go`: drop the x/net import and the `http2.ConfigureServer` block
  in `startTestServer`; add `NextProtos: []string{"h2", "http/1.1"}` to its `tlsConf`.
- [x] **Action** — modify `e2e/tunnel_app_test.go`: drop the x/net import, add `"errors"`; replace `h2Client`'s
  body (its existing doc comment stays unchanged):

```go
func h2Client(edge, fqdn string, roots *x509.CertPool) *http.Client {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	tr := &http.Transport{
		Protocols:       &protocols,
		MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
				ServerName: fqdn, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"},
			}}
			conn, err := d.DialContext(ctx, "tcp", edge)
			if err != nil {
				return nil, err
			}
			if tc, ok := conn.(*tls.Conn); !ok || tc.ConnectionState().NegotiatedProtocol != "h2" {
				_ = conn.Close()
				return nil, errors.New("e2e: tunnel peer did not negotiate HTTP/2")
			}
			return conn, nil
		},
	}
	return &http.Client{Transport: tr, Timeout: 90 * time.Second}
}
```

- [x] **Action** — run `go mod tidy` (x/net becomes `// indirect`).

Definition of Done:
- [x] `client/enroll_test.go`, `client/harness_test.go` and `e2e/tunnel_app_test.go` no longer import
      `golang.org/x/net/http2`.

---

## US3 — Migrate to lego v5

go-acme supports and patches only the latest lego (Scope); move `internal/acme` + its wiring to v5.5.2 with no
behaviour change.

Acceptance criteria:
- [x] No file imports `github.com/go-acme/lego/v4`; `go.mod` requires `github.com/go-acme/lego/v5 v5.5.2`.
- [x] Issuance, EAB registration, DNS-01 (incl. `--acme-dns-resolver` / `--acme-dns-skip-propagation-check`) and
      Retry-After classification behave as before.
- [x] lego's log output stays on stderr.

### [x] Task 3.1 — Switch the module

- [x] **Action** — run `go get github.com/go-acme/lego/v5@v5.5.2`.

Definition of Done:
- [x] `go.mod` lists `github.com/go-acme/lego/v5 v5.5.2`.

### [x] Task 3.2 — `internal/acme` on the v5 API + EAB test harness

- [x] **Action** — modify `internal/acme/dns_provider.go`: imports → `github.com/go-acme/lego/v5/challenge`,
  `github.com/go-acme/lego/v5/providers/dns` (code unchanged).
- [x] **Action** — modify `internal/acme/lego_client.go`:
  - imports: `legoacme ".../lego/v5/acme"`, `.../lego/v5/certificate`, `.../lego/v5/challenge`,
    `.../lego/v5/challenge/dns01`, `.../lego/v5/lego`, `.../lego/v5/registration`; drop `.../acme/api`.
  - `acmeUser` (its doc comment stays):

```go
type acmeUser struct {
	email string
	reg   *legoacme.ExtendedAccount
	key   crypto.Signer
}

func (u *acmeUser) GetEmail() string                           { return u.email }
func (u *acmeUser) GetRegistration() *legoacme.ExtendedAccount { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.Signer               { return u.key }
```

  - `LegoConfig.AccountKey`: type `crypto.PrivateKey` → `crypto.Signer` (its trailing comment stays). In the
    `// DNS-01 propagation pre-check tuning …` comment block REMOVE the now-wrong second line
    `// Empty/false preserve lego's defaults (system resolvers + authoritative-NS propagation required).`
  - `dnsChallengeOpts` body (its doc comment stays) + new `applyDNSResolvers`:

```go
func (cfg LegoConfig) dnsChallengeOpts() []dns01.ChallengeOption {
	opts := []dns01.ChallengeOption{dns01.DisableRecursiveNSsPropagationRequirement()}
	if cfg.DNSSkipPropagationCheck {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}
	return opts
}

func (cfg LegoConfig) applyDNSResolvers() {
	if len(cfg.DNSResolvers) == 0 {
		return
	}
	opts := dns01.NewOptions()
	opts.RecursiveNameservers = cfg.DNSResolvers
	dns01.SetDefaultClient(dns01.NewClient(opts))
}
```

  - `legoClient.obtainCSR` field type → `func(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error)`;
    in its comment REMOVE the now-wrong word `(ctx-less) `.
  - `NewLegoClient(ctx context.Context, cfg LegoConfig)`: call `cfg.applyDNSResolvers()` right before
    `dnsOpts := cfg.dnsChallengeOpts()`; pass `ctx` to `Registration.RegisterWithExternalAccountBinding(ctx, …)`
    and `Registration.Register(ctx, …)`.
  - `obtain` keeps its goroutine + `select` on the CALLER's ctx, and the goroutine runs the lego call on a ctx
    detached from the caller (so an abandoned issuance still cleans up its TXT records and authorizations):

```go
	go func() {
		res, err := l.obtainCSR(context.WithoutCancel(ctx), req)
		ch <- result{res, err}
	}()
```

    In the comment above it REMOVE the now-wrong first sentence `lego's ObtainForCSR takes no context (DNS-01
    propagation polling can run for minutes, bounded only by lego's internal per-request HTTP timeout).` — the rest
    stays (still correct).
  - add the lego logger wiring (lego's logger is process-global):

```go
func SetLogOutput(w io.Writer) {
	legolog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
}
```

    (imports: `io`, `log/slog`, `legolog "github.com/go-acme/lego/v5/log"`).
  - `dnsProviderTimeout` comment: REMOVE the now-wrong clause `lego's challenge.Provider interface is ctx-less, so
    this is the only place a deadline can be imposed; ` and capitalize the next word (`The record publish/remove …`).
  - `legoDNSAdapter` methods (v5's ctx-taking `challenge.Provider`):

```go
func (a *legoDNSAdapter) Present(ctx context.Context, domain, _, keyAuth string) error {
	ctx, cancel := context.WithTimeout(ctx, dnsProviderTimeout)
	defer cancel()
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return a.p.Present(ctx, info.EffectiveFQDN, info.Value)
}

func (a *legoDNSAdapter) CleanUp(ctx context.Context, domain, _, keyAuth string) error {
	ctx, cancel := context.WithTimeout(ctx, dnsProviderTimeout)
	defer cancel()
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	return a.p.CleanUp(ctx, info.EffectiveFQDN, info.Value)
}
```

  - `classifyLego`: the rate-limit branch becomes `return rateLimited(rle.RetryAfter, err)` (v5 parses Retry-After
    into a `time.Duration`; absent/invalid → 0); in its doc comment REMOVE the now-wrong word `literal `.
- [x] **Action** — modify `internal/acme/lazy.go`: `build func(ctx context.Context) (caIssuer, error)` (field +
  `newLazyCA` parameter); `NewChain` passes `func(ctx context.Context) (caIssuer, error) { return NewLegoClient(ctx, lc) }`;
  add `const lazyBuildTimeout = 2 * time.Minute`; in `resolve`'s `DoChan` func:

```go
		bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lazyBuildTimeout)
		defer cancel()
		c, err := l.build(bctx)
```

- [x] **Action** — modify `internal/config/config.go`: in the `// DNS-01 propagation pre-check tuning …` comment
  above `ACMEDNSResolvers` REMOVE the now-wrong sentence `Defaults preserve lego's standard behaviour: system
  resolvers + authoritative-NS propagation required.` (lego v5's standard behaviour also requires recursive-NS
  propagation, which tunneld turns off); the first sentence stays.
- [x] **Action** — modify `internal/acme/lazy_test.go` and `internal/acme/lego_client_test.go` imports:
  `github.com/go-acme/lego/v4/certificate` → `github.com/go-acme/lego/v5/certificate`;
  `legoacme "github.com/go-acme/lego/v4/acme"` → `legoacme "github.com/go-acme/lego/v5/acme"`.
- [x] **Action** — modify the now-wrong test comments: `internal/acme/lazy_test.go` (above
  `TestLegoClient_ObtainRespectsCtxCancel`) REMOVE the word `(ctx-less) `; `internal/acme/lego_client_test.go`
  (above `TestClassifyRateLimitedErrorHonorsRetryAfter`) REMOVE the words `literal ` and `parse and `.
- [x] **Action** — modify `internal/tunneltest/containers.go`: add the shared EAB Pebble helper. Pebble 2.10.1
  ships `/test/config/pebble-config-external-account-bindings.json` (`externalAccountBindingRequired: true` plus
  test kid→key pairs); the keys are read from the container, never hardcoded in the repo.

```go
const pebbleEABConfig = "/test/config/pebble-config-external-account-bindings.json"

type pebbleEABConfigFile struct {
	Pebble struct {
		ExternalAccountMACKeys map[string]string `json:"externalAccountMACKeys"`
	} `json:"pebble"`
}

func StartPebbleEAB(t *testing.T) (directoryURL, minicaFile string, macKeys map[string]string) {
	t.Helper()
	c := startContainer(t, testcontainers.ContainerRequest{
		Image:        pebbleImage,
		ExposedPorts: []string{"14000/tcp"},
		Cmd:          []string{"-config", pebbleEABConfig},
		Env:          map[string]string{"PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0"},
		WaitingFor: wait.ForHTTP("/dir").WithPort("14000/tcp").WithTLS(true).WithAllowInsecure(true).
			WithStartupTimeout(60 * time.Second),
	})
	var cfg pebbleEABConfigFile
	if err := json.Unmarshal(copyFromContainer(t, c, pebbleEABConfig), &cfg); err != nil {
		t.Fatalf("parse pebble EAB config: %v", err)
	}
	minica := copyFromContainer(t, c, "/test/certs/pebble.minica.pem")
	return "https://" + endpoint(t, c, "14000/tcp") + "/dir",
		writeTempFile(t, "pebble-eab-minica-*.pem", minica), cfg.Pebble.ExternalAccountMACKeys
}
```

Definition of Done:
- [x] `internal/acme` imports only `github.com/go-acme/lego/v5/…` paths; every comment REMOVE instruction above is
      applied.

Tests (`internal/acme`, package `acme`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestLegoClient_ObtainRespectsCtxCancel` (existing, adapted) | unchanged behaviour with the ctx-taking `obtainCSR` seam | fake takes `(context.Context, certificate.ObtainForCSRRequest)` |
| `TestLegoClient_ObtainDetachesCallerCancel` | after the caller's ctx is cancelled and `obtain` returned, the ctx the `obtainCSR` seam received is NOT done and carries no deadline | the fake captures its ctx and blocks until released; the caller ctx has no deadline either |
| `TestSetLogOutput_WritesToWriter` | after `SetLogOutput(&buf)`, `legolog.Info("probe")` lands in `buf` | NOT parallel; restore `legolog.Default()` in `t.Cleanup` |
| `TestLazyCA_*` (existing, adapted) | unchanged behaviour with `build func(context.Context)` | builders take `context.Context` |
| `TestLazyCA_BuildCtxSurvivesCallerButIsBounded` | the build's ctx is not cancelled when the caller's is, and carries a deadline ≤ `lazyBuildTimeout` | builder captures its ctx; cancel the caller ctx |
| `TestLegoDNSAdapter_PresentUsesDeadline` (existing, adapted) | the adapter still imposes a deadline | `Present(context.Background(), …)` |
| `TestClassifyRateLimitedErrorHonorsRetryAfter` (existing, adapted) | the `RetryAfter` duration is honored; 0 stays 0 | table on `time.Duration` (`2m → 2m`, `0 → 0`); the string "garbage header" case now lives inside lego and is dropped |
| `TestLegoConfig_DNSChallengeOpts_RecursiveCheckAlwaysOff` | without skip: exactly the recursive-disable option; with `DNSSkipPropagationCheck`: that one plus the authoritative-disable option | identify each option by `runtime.FuncForPC(reflect.ValueOf(opt).Pointer()).Name()` containing `DisableRecursiveNSsPropagationRequirement` / `DisableAuthoritativeNssPropagationRequirement` |
| `TestLegoConfig_ApplyDNSResolvers` | with resolvers `dns01.DefaultClient()` is replaced; with none it is untouched (pointer equality) | NOT parallel; `t.Cleanup(func() { dns01.SetDefaultClient(prev) })` |

Integration test (`internal/acme/eab_integration_test.go`, `//go:build integration`, package `acme_test` — it uses
only exported API):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestNewLegoClient_EABRegistration` | `NewLegoClient` registers against an EAB-REQUIRED ACME server with a valid `EABKID`/`EABHMAC`, and fails AT EAB REGISTRATION (error contains `EAB register`) with a mismatched HMAC | `tunneltest.StartPebbleEAB`; `t.Setenv("LEGO_CA_CERTIFICATES", minicaFile)`; valid = `kid-1` + `macKeys["kid-1"]`, mismatched = `kid-1` + `macKeys["kid-2"]` |

### [x] Task 3.3 — Server wiring + module re-refresh

- [x] **Action** — modify `internal/server/acmewire.go`: `loadAccountKey` returns `crypto.Signer` (it already
  returns an `*ecdsa.PrivateKey`); the first statement of `buildACMEChain` becomes `acme.SetLogOutput(os.Stderr)`
  (`os` is already imported).

- [x] **Action** — re-run the Task 1.1 `go get -u` commands (its lines 2–4) and `go mod tidy`, so the modules
  that only lego v5 brings in are at their latest too.

Definition of Done:
- [x] `go.mod` no longer lists `github.com/go-acme/lego/v4`.

Tests (`internal/server/acmewire_test.go`, package `server`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestBuildACMEChain_LegoLogsToStderr` | after `buildACMEChain`, a lego log line (`legolog.Info("probe")`) arrives on stderr | NOT parallel; replace `os.Stderr` with an `os.Pipe` writer BEFORE the call (the handler captures the `*os.File`), minimal `config.ServeCmd` with a temp `ACMEAccountDir`; restore `os.Stderr` and `legolog.Default()` in `t.Cleanup`; the `legolog` import is test-only (production code outside `internal/acme` never imports lego) |
| existing `loadAccountKey` tests | still pass with the `crypto.Signer` return type | unchanged |

---

## US4 — Replace the unpublished MinIO images with PGSTY Silo

The integration + e2e tiers and the local compose stack cannot pull the official MinIO images any more; PGSTY
Silo is the maintained build of the same server (verified 2026-10-10: `server /data`, `mc alias set`,
idempotent `mc mb`, read-after-overwrite and the "no lifecycle configuration" error all behave as tunneld needs).

Acceptance criteria:
- [x] The integration + e2e tiers start the S3 stand-in from `pgsty/silo:RELEASE.2026-09-16T00-00-00Z`.
- [x] The compose stack runs `pgsty/silo` + `pgsty/mc` (`RELEASE.2026-09-16T00-00-00Z`) with unchanged commands,
      environment and bucket-creation script.

### [x] Task 4.1 — Test containers

- [x] **Action** — modify `internal/tunneltest/containers.go`: `minioImage = "pgsty/silo:RELEASE.2026-09-16T00-00-00Z"`
  (the comment above the `const` block stays — it remains correct).

Definition of Done:
- [x] `minioImage` is the only image constant changed in the block.

### [x] Task 4.2 — Compose stack

- [x] **Action** — modify `deploy/docker-compose.yml`: `minio` service `image: pgsty/silo:RELEASE.2026-09-16T00-00-00Z`;
  `createbuckets` service `image: pgsty/mc:RELEASE.2026-09-16T00-00-00Z` (comments unchanged).

Definition of Done:
- [x] Only the two `image:` values changed in those services.

Tests: the existing `StartMinIO` users (`internal/store/lifecycle_integration_test.go`,
`internal/server/integration_test.go`, `internal/server/drain_startup_integration_test.go`, `e2e/e2e_test.go`) —
notably `TestEnsureLifecycles_MergePreservesForeignRules` (lifecycle API + `NoSuchLifecycleConfiguration`) — plus
the compose `minio` + `createbuckets` run in Task 8.2.

---

## US5 — Refresh the deploy compose images + fix the alert bridge

The observability stack in the compose file is several releases behind (Dependabot #20, #25, #26, #33, #34), and
its alert bridge has never been reachable (see Scope).

Acceptance criteria:
- [x] `deploy/docker-compose.yml` pins the latest releases below with no configuration change (release notes
      reviewed: our Prometheus config uses only `static_configs` + `rule_files`, Grafana only a plain `prometheus`
      datasource + file-provisioned dashboards, and ntfy 2.28's 1 KB title / 512 B tag caps exceed our alerts); the
      unchanged configs pass the new images' config checks and start cleanly (Task 8.2).
- [x] The bridge reads its config from the path its binary uses and listens on all interfaces (`:8080`), the
      address `alertmanager.yml`'s webhook (`http://ntfy-alertmanager:8080`) targets.

### [x] Task 5.1 — Bump the images

- [x] **Action** — modify `deploy/docker-compose.yml`:

| Service | From | To |
|---|---|---|
| `prometheus` | `prom/prometheus:v3.13.2` | `prom/prometheus:v3.15.0` |
| `alertmanager` | `prom/alertmanager:v0.34.0` | `prom/alertmanager:v0.34.1` |
| `grafana` | `grafana/grafana:13.0.6` | `grafana/grafana:13.2.3` |
| `ntfy` | `binwiederhier/ntfy:v2.27.0` | `binwiederhier/ntfy:v2.29.0` |
| `ntfy-alertmanager` | `xenrox/ntfy-alertmanager:1.0.0` | `xenrox/ntfy-alertmanager:1.0.1` |

Definition of Done:
- [x] The five `image:` lines match the "To" column; nothing else in those services changed in this task.

### [x] Task 5.2 — Fix the alert bridge

- [x] **Action** — modify `deploy/docker-compose.yml`, the `ntfy-alertmanager` service's volume:

```yaml
      - ./ntfy-alertmanager/config.scfg:/etc/ntfy-alertmanager/config:ro
```

- [x] **Action** — modify `deploy/ntfy-alertmanager/config.scfg.example`: add `http-address :8080` as the first
  directive (above `base-url http://ntfy`); REMOVE the now-wrong comment lines 1–3 (`# The bridge listens on :8080
  by default, …`, `# ntfy-alertmanager version's default differs, set its HTTP-address directive …` and the `#`
  separator line) — the default is `127.0.0.1:8080` and the directive is now set explicitly; line 4 (`# Copy this
  file to config.scfg …`) stays.

```
http-address :8080
base-url http://ntfy
```

Context: operators who already copied the example to `deploy/ntfy-alertmanager/config.scfg` (gitignored) MUST add
the same `http-address :8080` line to their copy.

Definition of Done:
- [x] The compose mount target is `/etc/ntfy-alertmanager/config`; the example's first directive is
      `http-address :8080`.

---

## US6 — Refresh CI + release workflows

Every pinned action runs on the removed Node 20 runtime, the linter predates Go 1.27, and a job once hung ~6 h
with no timeout.

Acceptance criteria:
- [x] Every `uses:` in `.github/workflows/*.yml` pins the latest release's commit SHA (Node 24 runtime).
- [x] golangci-lint v2.14.0 in CI; `make mermaid-check` runs on Node 24 with mermaid-cli 12.0.0.
- [x] Every job has a `timeout-minutes` above its normal runtime and above any inner `go test -timeout`.

### [x] Task 6.1 — Pin the latest action releases

- [x] **Action** — modify `.github/workflows/ci.yml` and `.github/workflows/release.yml`: replace every
  occurrence (SHA + trailing version comment):

| Action | New pin |
|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` |
| `actions/setup-go` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0` |
| `actions/setup-node` | `949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0` |
| `golangci/golangci-lint-action` | `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0` |
| `docker/setup-qemu-action` | `99012661954931238ded8c8b007157a8430204e1 # v4.4.0` |
| `docker/setup-buildx-action` | `f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1` |
| `docker/login-action` | `dbcb813823bdd20940b903addbd779551569679f # v4.6.0` |
| `goreleaser/goreleaser-action` | `f06c13b6b1a9625abc9e6e439d9c05a8f2190e94 # v7.2.3` |

Context: resolved via `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` (annotated tags dereferenced) on
2026-10-10; re-resolve each one at implementation time and STOP if any differs.

Definition of Done:
- [x] `grep -n 'uses:' .github/workflows/*.yml` shows only the eight SHAs above.

### [x] Task 6.2 — Tool versions + job timeouts

- [x] **Action** — modify `.github/workflows/ci.yml`: the three golangci-lint steps `version: v2.14.0`; the
  `actions/setup-node` step `node-version: '24'`; add `timeout-minutes` to every job:

| Job | `timeout-minutes` |
|---|---|
| `static-checks` | 20 |
| `build` | 15 |
| `test-unit` | 20 |
| `test-integration` | 45 |
| `test-e2e` | 35 |
| `image` | 20 |

- [x] **Action** — modify `.github/workflows/release.yml`: add `timeout-minutes: 30` to the `release` job.
- [x] **Action** — modify `scripts/mermaid-check.sh` line 30: `@mermaid-js/mermaid-cli@12.0.0`.

Definition of Done:
- [x] Every job in both workflows has `timeout-minutes`; no `v2.12.2`, `node-version: '20'` or `@11.16.0` remains.

---

## US7 — Refresh the `support/` Android toolchains + regenerate fixtures

Bring both test apps to the latest stable Gradle 9.8.1 / AGP 9.4.1 (built-in Kotlin) / Kotlin 2.4.21 /
okhttp 5.5.0 / BouncyCastle 1.86 / Ktor 3.6.0, with `compileSdk 37` and `targetSdk 36` (see Scope). The required
SDK packages (android-37.0, build-tools 36.0.0) are installed locally.

Acceptance criteria:
- [x] Both projects build from clean with those versions; the only warning is the user-accepted AGP-internal
      `Configuration.setVisible` deprecation (see Scope).
- [x] The fixtures (`fixtures/attest-probe/`, `fixtures/tunnel-app/`) are regenerated from clean builds;
      `signers.allow` is unchanged (same debug signing key).
- [x] `TestE2E_DeviceAttestation` + `TestE2E_ReferenceTunnelApp` pass on the connected device (Task 8.2).

### [x] Task 7.1 — Gradle wrapper → 9.8.1 (first pass)

- [x] **Action** — in BOTH `support/attest-probe` and `support/tunnel-app` (current Gradle 8.14.4), output
  captured per agent.md §5:

```sh
set -o pipefail
./gradlew wrapper --gradle-version 9.8.1 --distribution-type bin \
  --gradle-distribution-sha256-sum dce76f55f8e251a3a1f130eb120f30b3d271de2b76c9b0729d316b5a1b6dc01f \
  2>&1 | tee /tmp/plan13-<project>-wrapper1.log
```

Definition of Done:
- [x] Both `gradle-wrapper.properties` carry `gradle-9.8.1-bin.zip` + `distributionSha256Sum=dce76f55…dc01f`.

### [x] Task 7.2 — Build files (AGP 9, built-in Kotlin)

- [x] **Action** — modify `support/attest-probe/build.gradle.kts` and `support/tunnel-app/build.gradle.kts`
  (identical):

```kotlin
buildscript {
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21")
    }
}

plugins {
    id("com.android.application") version "9.4.1" apply false
}
```

Context: AGP 9 compiles Kotlin itself (the `org.jetbrains.kotlin.android` plugin MUST go); the `buildscript`
classpath pins the Kotlin compiler (otherwise AGP falls back to its own 2.2.10).
- [x] **Action** — modify `support/attest-probe/app/build.gradle.kts` and
  `support/tunnel-app/app/build.gradle.kts`: delete `id("org.jetbrains.kotlin.android")` from `plugins`;
  `compileSdk = 37` (`targetSdk` stays 36).
- [x] **Action** — modify `support/tunnel-app/app/build.gradle.kts` `dependencies` (all three existing comments
  stay unchanged):

```kotlin
dependencies {
    implementation("com.squareup.okhttp3:okhttp:5.5.0") // 5.x requires compileSdk 37
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("io.ktor:ktor-server-core:3.6.0")  // Netty engine + platform Conscrypt terminate TLS;
    implementation("io.ktor:ktor-server-netty:3.6.0") { // no explicit netty-* / conscrypt-android dep
        exclude(group = "io.netty", module = "netty-codec-native-quic")
    }
}
```

Context: Ktor 3.6.0 pulls `netty-codec-native-quic`'s desktop-only HTTP/3 native jars (HTTP/3 is opt-in and
unused); their duplicate license files fail `mergeDebugJavaResource`.
- [x] **Action** — modify `support/attest-probe/gradle.properties`: delete `android.useAndroidX=false`. AGP 9
  deprecates that setting (a warning) and defaults it to `true`; the flip is harmless here — the probe has no
  AndroidX/support dependency and the rebuild without the line was fully up-to-date.
- [x] **Action** — modify `.gitignore`: add `/support/attest-probe/.kotlin/` and `/support/tunnel-app/.kotlin/` to
  the respective blocks (Kotlin's per-project session directory).

Definition of Done:
- [x] Neither project references `org.jetbrains.kotlin.android`; both apps declare `compileSdk = 37` and
      `targetSdk = 36`.

### [x] Task 7.3 — okhttp 5 (non-null `Response.body`)

- [x] **Action** — modify `support/tunnel-app/app/src/main/java/com/example/tunnelapp/Enroll.kt`:
  `resp.body?.string().orEmpty()` → `resp.body.string()` (both occurrences, `getJson` + `postJson`).
- [x] **Action** — modify `support/tunnel-app/app/src/main/java/com/example/tunnelapp/Tunnel.kt`:
  `resp.body!!.source()` → `resp.body.source()`; `resp.body!!.byteStream()` → `resp.body.byteStream()`.

Definition of Done:
- [x] `grep -rn 'resp.body?\|resp.body!!' support/tunnel-app/app/src` returns nothing.

### [x] Task 7.4 — Wrapper second pass + fixtures

- [x] **Action** — in BOTH projects re-run the Task 7.1 command (now executing on Gradle 9.8.1, so `gradlew`,
  `gradlew.bat` and `gradle-wrapper.jar` are regenerated by 9.8.1 itself), teeing to
  `/tmp/plan13-<project>-wrapper2.log`.
- [x] **Action** — regenerate the fixtures from clean builds (output captured per agent.md §5; `pipefail` so a
  failed build fails the command):

```sh
set -o pipefail
{ (cd support/attest-probe && ./gradlew clean) && make attest-probe; } 2>&1 | tee /tmp/plan13-attest-probe.log
{ (cd support/tunnel-app && ./gradlew clean) && make tunnel-app; } 2>&1 | tee /tmp/plan13-tunnel-app.log
```

Definition of Done:
- [x] Both committed APKs changed (`git diff --stat fixtures/` lists both `.apk` files) and
      `fixtures/*/*.apk.sha256` match them; `git diff fixtures/*/signers.allow` is empty.

---

## US8 — Documentation + ground-up verification

The canonical docs MUST describe the new stack, and every change MUST be proven by the full quality gates on the
final code.

Acceptance criteria:
- [x] `.claude/rules/project.md`, `README.md`, `docs/PROJECT.md` and both `support/*/README.md` reflect the new
      stack.
- [x] Every superseded Dependabot PR is closed with a comment naming this plan's branch and the version it carries.

### [x] Task 8.1 — Update the docs

- [x] **Action** — modify `.claude/rules/project.md` Tech Stack — replace these four rows in full:

```markdown
| Phone control + replica mesh | `net/http` built-in HTTP/2 (mTLS) | Phone control plane (`/api/v1/control`, `/api/v1/data`, `/api/v1/issue`) + replica↔replica mesh; binary control frames per `docs/PROTOCOL.md`; the data stream is an opaque splice. |
| Durable store | AWS S3 SDK v2 (`github.com/aws/aws-sdk-go-v2`) / MinIO stand-in (PGSTY Silo build) | Plain Get/Put/Delete only (no conditional writes); name registry + conn logs + rejected-enroll evidence; write-verify name claim. |
| ACME issuance | `github.com/go-acme/lego/v5` | LE→GTS→ZeroSSL chain, DNS-01, spillover, per-CA cooldown/backoff retry-after, self-heal. |
| Integration + e2e infra | `github.com/testcontainers/testcontainers-go` | Valkey + MinIO (PGSTY Silo build) + Pebble/challtestsrv (`//go:build integration` / `e2e`); needs Docker. |
```

- [x] **Action** — modify `README.md` Deployment quickstart step 5: `for the local MinIO stand-in the compose
  creates the bucket automatically.` → `for the local MinIO stand-in (the PGSTY Silo build — the official MinIO
  images are no longer published) the compose creates the bucket automatically.`
- [x] **Action** — modify `docs/PROJECT.md` §7: `(testcontainers: Valkey, MinIO, Pebble)` →
  `(testcontainers: Valkey, MinIO via the PGSTY Silo build, Pebble)`.
- [x] **Action** — modify `support/attest-probe/README.md` and `support/tunnel-app/README.md`: the gitignored
  Gradle outputs `(`build/`, `.gradle/`)` → `(`build/`, `.gradle/`, `.kotlin/`)`.

Definition of Done:
- [x] `grep -n 'x/net/http2\|lego/v4' .claude/rules/project.md` returns nothing.

### [x] Task 8.2 — Ground-up double-check + quality gates

- [x] **Action** — re-read this plan from the top and verify EVERY action landed (US1–US8); `git diff main` adds
  NO comment line to hand-written code in any language (exempt per Scope: the regenerated
  `support/*/gradlew` / `support/*/gradlew.bat` and the action-pin `# vX.Y.Z` tags) and every REMOVE instruction
  above is applied. Then:
  `grep -rn 'golang.org/x/net/http2\|go-acme/lego/v4' --include='*.go' .` and
  `grep -rn 'minio/minio\|minio/mc' --include='*.go' --include='*.yml' .` return nothing;
  `grep -n '^go \|^toolchain' go.mod` shows only `go 1.27.2`.
- [x] **Action** — scoped latest-version check over `go.mod`'s requirements; for each module it prints run
  `go get <path>@latest`, then `go mod tidy`, until it prints nothing:

```sh
go list -m -u -f '{{if .Update}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' \
  $(go mod edit -json | python3 -c 'import json,sys; print(" ".join(r["Path"] for r in json.load(sys.stdin)["Require"]))')
```

- [x] **Action** — re-check that every NON-Go pin in this plan is still the latest stable release (the eight action
  SHAs, the compose + Silo/mc + `golang` images, the Pebble + challtestsrv test images, golangci-lint, mermaid-cli,
  Gradle, AGP, Kotlin, okhttp, BouncyCastle, Ktor); if any newer stable release exists, STOP and ask the user. Node is pinned by the user's
  choice of the 24 line (`node-version: '24'` floats within it): only Node 24 losing LTS status would be a reason
  to stop — a newer Node major (Current or LTS) is not.
- [x] **Action** — connect the Realme T70 (single adb device), then run every gate ONCE with output captured
  (agent.md §5), fix anything surfaced, and re-run: `make lint`, `make vet`, `make govulncheck` (reports no
  vulnerability affecting our code), `make build`, `make test-unit`, `make test-integration`, `make test-e2e` (MUST
  show `TestE2E_DeviceAttestation` and `TestE2E_ReferenceTunnelApp` PASS, not SKIP), `make test-scripts`,
  `make compose-config`, `make mermaid-check`, `make tidy` + `git diff --exit-code -- go.mod go.sum`.
- [x] **Action** — verify the Android warning budget on CLEAN rebuilds (Kotlin compiler and AGP task warnings are
  emitted only when the tasks actually run; plain `assembleDebug` prints only Gradle's summary line):

```sh
set -o pipefail
(cd support/attest-probe && ./gradlew clean assembleDebug --warning-mode all) 2>&1 | tee /tmp/plan13-attest-probe-warnings.log
(cd support/tunnel-app && ./gradlew clean assembleDebug --warning-mode all) 2>&1 | tee /tmp/plan13-tunnel-app-warnings.log
```

  Both logs and both `support/*/build/reports/problems/problems-report.html` MUST contain no warning other than the
  user-accepted AGP-internal `Configuration.setVisible` deprecation (and Gradle's resulting summary line) — no
  Kotlin compiler warning, no other deprecation.
- [x] **Action** — run the compose S3 stand-in with the new images and require the bucket job to succeed, in an
  isolated compose project (never touching any other stack); the command MUST exit 0 and the log MUST show the
  `createbuckets` container exiting with code 0:

```sh
set -o pipefail
timeout 300 docker compose -p plan13-silo-check --env-file deploy/.env.example -f deploy/docker-compose.yml \
  up --exit-code-from createbuckets minio createbuckets 2>&1 | tee /tmp/plan13-compose-silo.log; rc=$?
docker compose -p plan13-silo-check --env-file deploy/.env.example -f deploy/docker-compose.yml down -v
[ "$rc" -eq 0 ] && grep -E 'createbuckets-1 exited with code 0' /tmp/plan13-compose-silo.log
```

- [x] **Action** — validate the unchanged observability configs against the five bumped images (offline config
  checks, then a bounded start of the three services whose configs have no checker; containers are uniquely named
  and NOT published on any host port, so no local service is touched):

```sh
set -o pipefail
D="$PWD/deploy"
{ timeout 120 docker run --rm --entrypoint promtool -v "$D/prometheus:/etc/prometheus:ro" prom/prometheus:v3.15.0 \
    check config /etc/prometheus/prometheus.yml &&
  timeout 120 docker run --rm --entrypoint promtool -v "$D/prometheus:/etc/prometheus:ro" prom/prometheus:v3.15.0 \
    check rules /etc/prometheus/alerts.yml &&
  timeout 120 docker run --rm --entrypoint amtool -v "$D/alertmanager:/etc/alertmanager:ro" prom/alertmanager:v0.34.1 \
    check-config /etc/alertmanager/alertmanager.yml; } 2>&1 | tee /tmp/plan13-obs-config-check.log
docker run -d --name plan13-obs-grafana -e GF_SECURITY_ADMIN_PASSWORD=changeme \
  -v "$D/grafana/provisioning:/etc/grafana/provisioning:ro" grafana/grafana:13.2.3
docker run -d --name plan13-obs-ntfy --tmpfs /var/lib/ntfy \
  -v "$D/ntfy/server.yml:/etc/ntfy/server.yml:ro" binwiederhier/ntfy:v2.29.0 serve
docker run -d --name plan13-obs-ntfy-am \
  -v "$D/ntfy-alertmanager/config.scfg.example:/etc/ntfy-alertmanager/config:ro" xenrox/ntfy-alertmanager:1.0.1
sleep 30
for c in plan13-obs-grafana plan13-obs-ntfy plan13-obs-ntfy-am; do
  docker inspect -f "$c running={{.State.Running}} exit={{.State.ExitCode}}" "$c"; docker logs "$c" 2>&1
done 2>&1 | tee /tmp/plan13-obs-runtime-check.log
docker rm -f plan13-obs-grafana plan13-obs-ntfy plan13-obs-ntfy-am
```

  The three checks MUST pass; all three containers MUST report `running=true`, and their logs MUST show no
  configuration / provisioning error or fatal line (the real `config.scfg` is gitignored, so the committed
  `config.scfg.example` stands in for it, mounted at `/etc/ntfy-alertmanager/config` — the path the image's
  binary reads; `--tmpfs /var/lib/ntfy` stands in for the compose `ntfy-data` volume that `server.yml`'s
  `auth-file` / `cache-file` need). The bridge's log MUST show `Listening on :8080` (all interfaces — Task 5.2),
  not `127.0.0.1:8080`.

- [x] **Action** — build the production image (exercises the `golang:1.27.2` Dockerfile):
  `set -o pipefail; docker build -f Dockerfile -t tunneld:plan13 . 2>&1 | tee /tmp/plan13-docker-build.log`.
- [x] **Action** — push the branch and run the CI workflow on it (CI does not trigger on branch pushes):
  `gh workflow run ci.yml --ref chore/plan-13-dependency-refresh`, then `gh run watch` the run; ALL six jobs
  (`static-checks`, `build`, `test-unit`, `test-integration`, `test-e2e`, `image`) MUST finish green. The
  `release.yml` changes (pins, `go-version-file`, timeout) are NOT executed here — a run publishes a release —
  their inputs are unchanged (verified against each new action's `action.yml`) and the next `v*` tag runs them.
- [x] **Action** — once every gate above is green: for each open Dependabot PR (`gh pr list --state open --author
  app/dependabot` — expected #4, #5, #6, #7, #8, #18, #20, #25, #26, #27, #28, #29, #30, #31, #33, #34 plus any
  opened since) confirm this branch pins the same or a newer version of its dependency (if a PR targets a NEWER
  version, apply it first and re-run the gates), then close it with a comment naming this branch and the version
  it carries; confirm the list is then empty.

Definition of Done:
- [x] Every checkbox above is `[x]`; all gates green on the final code.

---

## Deviations

- **US3 Task 3.2 (`StartPebbleEAB` readiness + EAB test assertion).** The planned `wait.ForListeningPort("14000/tcp")`
  reported Pebble ready before it served (testcontainers found no shell in the image for its in-container port
  check, and the host port is accepted by docker-proxy early), so the valid-key case failed with `EOF` on the
  directory GET and the mismatched-key case passed for the wrong reason (the same connection error). The helper now
  waits with `wait.ForHTTP("/dir")` over TLS (`WithAllowInsecure` — Pebble's minica cert) with a 60 s startup
  timeout, and the test asserts the mismatched case fails at EAB registration (`EAB register` in the error).
- **US8 Task 8.2 (observability runtime check — Grafana log lines).** Grafana 13.2.3 starts and stays running with the
  committed provisioning, but logs two `level=error` lines: "Failed to read plugin provisioning files from directory
  /etc/grafana/provisioning/plugins" and "can't read alerting provisioning files from directory
  /etc/grafana/provisioning/alerting" — the repo provisions only `dashboards/` and `datasources/`. The identical two
  lines appear with the previous `grafana/grafana:13.0.6` (verified 2026-10-10), so they are not a configuration
  incompatibility introduced by the bump; reported to the user for a decision (adding empty `plugins/` + `alerting/`
  provisioning directories would silence them, outside this plan's agreed scope).
