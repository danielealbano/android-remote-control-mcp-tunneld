# tunneld — Self-Hosted Tunnel Server — Project Rules

`tunneld` is a self-hosted, abuse-resistant **HTTP tunnel server** (Go) that gives the Android MCP
app (`android-remote-control-mcp`) a stable public hostname for free. The phone opens an **outbound
WebSocket** (`wss://<name>.<tunnel-domain>/connect`); the public web side is plain HTTP(S) behind a
TLS-terminating reverse proxy (Cloudflare orange-cloud reference, Traefik origin); **N identical
stateless replicas** bridge public requests to the WebSocket-holding node over **Redis pub/sub**.
Identity is a CA-signed certificate the phone earns by CSR enrollment; every `/connect` is
authenticated at the **APPLICATION layer** (challenge-response proof-of-possession — **NOT TLS
mutual auth**), so the tunnel works through Cloudflare's proxy. Abuse is contained by layered caps,
a hot-reloadable ban/geo engine, and a strict method+path ingress allowlist.

> **STATUS: implemented.** Plan 1 (`docs/plans/1_self_hosted_tunnel_server_20260814130404.md`) is
> delivered end to end (US1–US16). Releases are cut from `v*` tags via goreleaser; multi-arch
> images are published to `ghcr.io/danielealbano/tunneld`.

## MANDATORY: Read These First

You MUST ALWAYS read these documents before ANY work, in this order:

1. **`docs/PROJECT.md`** — operational reference: what tunneld is, topology, deployment modes,
   caps, ban/geo engine, observability, non-goals. **Entry-level read.**
2. **`docs/ARCHITECTURE.md`** — system map: package layout, the three ingress edges, request
   lifecycle across replicas, `/connect` lifecycle, bandwidth model, Redis state, shutdown.
   **Entry-level read.**
3. **`docs/PROTOCOL.md`** — the wire protocol: enrollment, the `/connect` challenge-response, the
   WS binary frames, the Redis envelopes, liveness, and the security invariants. **CANONICAL wire
   contract** — the Go client in `client/` and the future Kotlin client MUST both conform; golden
   byte fixtures live in `internal/wire/testdata/`. **ESSENTIAL.**
4. **`docs/plans/1_self_hosted_tunnel_server_20260814130404.md`** — the decision record (every
   design decision was agreed with the user there). CANONICAL when a design detail is disputed.

You MUST ALSO follow `go.md`, `github.md`, `agent.md`, and `development_pipeline.md`. It is
ABSOLUTELY MANDATORY to pass ALL quality gates before any work is considered done.

`PROJECT.md` and `ARCHITECTURE.md` are the higher-level entry points; `PROTOCOL.md` is the wire
contract; the plan is the in-depth record. Cross-reference rather than duplicating across
documents. This rule file MUST stay accurate but CONCISE — it references the canonical docs, it
does NOT duplicate them.

---

## Tech Stack (decided)

| Concern | Choice | Notes |
|---|---|---|
| Language | **Go (see `go.mod` for the pinned version)**, `CGO_ENABLED=0` for released artifacts | Static binary; distroless `nonroot` runtime image. |
| CLI / env config | `github.com/alecthomas/kong` | One `tunneld` binary: `serve` / `version`; every flag has a `TUNNELD_*` env twin (`kong.DefaultEnvars`); `Validate()` enforces every cross-field invariant at startup. |
| WebSocket | `github.com/coder/websocket` | Context-first; binary frames per `docs/PROTOCOL.md`; native control pings for keepalive. |
| Cross-replica transport | Redis pub/sub via `github.com/redis/go-redis/v9` | Channels `req:{node}` / `resp:{reqid}`; routing `route:{name}`. **Transient state ONLY** — see invariants. |
| Ban/geo LPM table | `github.com/gaissmai/bart` + `go4.org/netipx` | Longest-prefix-match over `netip`; atomic snapshot swap on reload; DB-IP Country Lite CSV range→prefix expansion. |
| Metrics | `github.com/prometheus/client_golang` | Custom registry on the INTERNAL listener only; NO per-tunnel labels. |
| Logging | `log/slog` fan-out + `gopkg.in/natefinch/lumberjack.v2` | Repeatable composite `--log` sinks; `std` splits by severity (info+ → stdout, warn+ → stderr). |
| Unit-test Redis | `github.com/alicebob/miniredis/v2` | In-process; unit AND integration tiers. |
| E2E infra | `github.com/testcontainers/testcontainers-go` | Redis + Traefik + two tunneld replicas; `//go:build e2e`. |
| Edge / deployment | Traefik v3 + Cloudflare (orange-cloud reference) + Docker Compose | `deploy/`: traefik, tunneld-1/2, redis, prometheus, grafana, alertmanager, ntfy (+bridge), fetcher. Grey-cloud (Traefik as internet edge) is the privacy-max alternative. |
| Release | goreleaser (`v*` tags) | linux amd64+arm64 archives + multi-arch image `ghcr.io/danielealbano/tunneld`. |
| Source control | **GitHub**, `danielealbano/android-remote-control-mcp-tunneld` | See `github.md`. |

---

## Hard Project Invariants — ABSOLUTE RULES

These come from `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md`, and the Plan 1 decision record. They
MUST NOT be relaxed without explicit user direction.

### Identity & authentication — SACRED
- **There is NO TLS mutual auth ANYWHERE** — no `clientAuth`/`passTLSClientCert` in Traefik, no
  client-cert header parsing in tunneld. `/connect` authentication is the APPLICATION-layer
  challenge-response over the WebSocket (ECDSA-P256 possession proof over
  `"tunneld-connect-v1" ‖ nonce`), and CN == Host `<name>` is enforced. This is what makes the
  tunnel Cloudflare-proxyable. You MUST NEVER reintroduce TLS client certificates.
- Enrollment accepts **ECDSA P-256 keys ONLY** (`400 unsupported_key_type` otherwise); the server
  ignores ALL CSR subject/extension fields except the public key and assigns the name itself.
- Any request carrying a client-cert / mTLS-indicating header on the PUBLIC side is rejected `400`.
- **The edge performs NO authentication on forwarded requests** (standing user decision): the app
  is the sole authenticator; a token-less `POST /mcp` MUST be forwarded so the app's own `401`
  carries the RFC 9728 `WWW-Authenticate` discovery header. The ingress MUST NEVER inspect the
  `Authorization` header or answer `401` itself.
- **Revocation is the ban engine ONLY** (no CRL): `tunnel-name` / `tunnel-fingerprint` bans are
  enforced at `/connect` (after auth, before bind), at public ingress (on the resolved route), and
  live via the ban-reload `EvictBanned` hook. All three points MUST stay wired.

### Source-IP trust — SACRED
- The IP for ban checks, rate limits, and quotas comes ONLY from the MANDATORY, defaultless
  `--client-ip-header`, via the single `internal/clientip.TrustedIP` helper: the **RIGHT-MOST**
  comma-separated token, NEVER the left-most (client-controlled) `X-Forwarded-For` entry. An
  absent/unparseable header is rejected `400 missing_client_ip` — **fail-closed, never defaulted**.
- The trust boundary is the deployment layer, not an in-process CIDR allowlist: orange-cloud =
  origin reachable ONLY from Cloudflare (Traefik `IPAllowList` of Cloudflare ranges and/or
  Authenticated Origin Pulls) so `Cf-Connecting-Ip` is trustworthy; grey-cloud = Traefik is the
  internet edge with `X-Real-Ip`. **Never publish tunneld's port** — the replicas are reachable
  only on the compose network.

### Ingress discipline
- **The ban check is the FIRST handler-level check on ALL THREE ingress edges** (public, `/enroll`,
  `/connect` — before the WS upgrade), keyed on the trusted client IP. Only the fail-closed
  client-IP extraction (and Go's `MaxHeaderBytes` backstop during header parsing) may precede it.
- The public surface is an exact method+path **allowlist** (`internal/ingress/allowlist.go`) —
  everything else is `404`; `GET /mcp` is `405` at the edge (`Allow: POST, DELETE`; SSE
  unsupported); `/s/{token}` is matched by `^/s/[0-9a-f]{64}$`. The allowlist's source of truth is
  the app's route code — reconcile there, never invent entries.
- `/connect` on a per-tunnel host is a RESERVED path owned by the WebSocket manager; it MUST NEVER
  reach the allowlist. A non-upgrade `/connect` request is `426`.
- Client-supplied `X-Forwarded-*`/`Forwarded` are stripped and re-added from proxy-set values;
  hop-by-hop headers are stripped in BOTH directions.
- Caps are UNIFORM: NO per-path exceptions, NO ad-hoc higher caps (product decision — the tunnel is
  a free service for MCP control traffic). Operators raise the `--limit-*` values, never the code.

### Redis state — SACRED
- **NO permanent Redis state, EVER.** Every key (routing, rate-limit windows, concurrency
  counters, per-tunnel `tcnt:{name}` counters) carries a TTL set **atomically in the SAME Lua
  script** as its INCR/HINCRBY/SET — never a separate `EXPIRE` call. The enrolled certificate
  (held by the phone) is the ONLY persistent identity. There is no database.
- Route teardown/refresh (`Unbind`/`Heartbeat`) is **owner-conditional on the per-connection
  `connID`**, never node-only — a stale connection MUST NOT clobber a re-bound route.

### Wire protocol — FROZEN BY `docs/PROTOCOL.md`
- `wire.ChunkSize` = **32768** bytes; both peers set the WS read limit to `ChunkSize + 64 KiB`.
- Empty body = ZERO body-chunk frames (canonical, both directions); receivers tolerate zero-length
  chunks; dispatch happens ONLY on `*_END`. Bodies are RAW bytes — never base64.
- ANY wire change MUST update `docs/PROTOCOL.md`, the golden fixtures in
  `internal/wire/testdata/`, and the Go client in `client/` together (the future Kotlin client
  conforms to the spec, not to the Go source).

### Cloudflare Free constraints — enforced by `Validate()`
- `--ping-interval` ≤ 90 s (Cloudflare's 100 s WS idle timeout); `--limit-request-timeout` < 100 s
  (Cloudflare's 524 origin timeout). Do NOT weaken these checks.

### Bandwidth model
- Per-tunnel, per-direction token buckets are **per-PROCESS** (user decision — cross-replica
  exactness was REJECTED: it would put a synchronous Redis call per 32 KiB slice on the data
  plane). The ingress paced body-reader and the WS leg share ONE `BucketRegistry` instance; the
  `PacedByNode` guard prevents double-draining the same bytes (byte ACCOUNTING is still recorded
  for every chunk). Client-side egress is deliberately unpaced.
- The blocking `WaitN` MUST NEVER be held under the connection write mutex.

### Observability
- Prometheus metrics live on the INTERNAL listener ONLY (never proxied) and MUST NOT carry
  per-tunnel labels (cardinality); the per-tunnel view is `/admin/tunnels` from the TTL'd Redis
  counters, written ASYNCHRONOUSLY by the recorder's background flusher — never synchronously on
  the data plane.
- Cap-hit logging is deduplicated (first hit per `(tunnel, reason)` immediately, then ≤1
  summary/min) — attacker-driven log flooding MUST stay impossible.
- NEVER log secrets, key material, or tunnel payloads.

### Repository hygiene
- **Placeholder values ONLY in-repo**: domains (`example.test`, `free.example.com`), country codes
  (`XX`/`YY` — NEVER a real country code or name anywhere), secrets (`changeme`). Real values live
  in the operator's private `.env` / `tunneld.env` / ban files.
- The DB-IP Country Lite **CC BY 4.0 attribution** in the README MUST be preserved.
- No AI attribution anywhere (per `agent.md`).

---

## Non-goals (MUST NOT build)

- No database / persistent server-side identity store. No server-side request authentication
  (the app authenticates). No per-path cap exceptions or bulk-transfer support. No CRL (bans are
  the only revocation). No cross-replica exact bandwidth accounting. No server-side response
  cache. No SSE on `/mcp` (`GET /mcp` = `405`). No idle disconnect (pings are liveness-only).
- The Android (Kotlin) client integration is **out of scope** of this repo — it lives with the app.

---

## Commit Scopes

All commits MUST use one of the scopes below. A commit spanning multiple scopes uses `tunneld`.

| Scope | Applies to |
|---|---|
| `tunneld` | Top-level binary (`cmd/tunneld`) / cross-cutting changes |
| `config` | `internal/config`: kong flag surface, `Validate()`, size/bitrate parsing |
| `logging` | `internal/logging`: slog fan-out, composite `--log` sinks |
| `ban` | `internal/ban`: parser, LPM engine, DB-IP expansion, watcher |
| `limit` | `internal/limit`: rate windows, enroll quota, global stream counter, batch-credit bandwidth, ACME budget |
| `ca` | `internal/ca`: CA loader, identity + mesh-role signing, name generation, fingerprint |
| `router` | `internal/router`: Redis routing registry (route bind/heartbeat/unbind/lookup) + node registry |
| `store` | `internal/store`: durable S3/MinIO name registry (write-verify claim), connection logs, rejected-enroll evidence, lifecycles |
| `attest` | `internal/attest`: Android key-attestation verifier (KeyDescription parse, roots/status refreshers, signer allowlist) |
| `acme` | `internal/acme`: LE→GTS→ZeroSSL issuance chain (lego clients, DNS-01, cooldown/backoff, LE budget) |
| `enroll` | `internal/enroll`: attested enrollment service + HTTP handler, single-use nonce |
| `wire` | `internal/wire`: v2 control-frame codec + mesh stream header |
| `phoneconn` | `internal/phoneconn`: phone control plane (HTTP/2 + mTLS, bind, dial-back, renewal, eviction) |
| `edge` | `internal/edge`: raw :443 SNI edge (ClientHello peek + JA4), bridge, connection policy |
| `mesh` | `internal/mesh`: replica↔replica mTLS HTTP/2 mesh (per-pair pools, connID-checked delivery) |
| `server` | `internal/server`: assembly (`Run`), SNI-edge + listener wiring, lifecycle |
| `metrics` | `internal/metrics`: registry, internal HTTP server, PromRecorder |
| `admin` | `internal/admin`: per-tunnel counters + `/admin/tunnels` |
| `caplog` | `internal/caplog`: deduped cap-hit logger |
| `observ` | `internal/observ`: the Recorder interface |
| `tunneltest` | `internal/tunneltest`: shared test fakes (Recorder, Store) |
| `client` | `client/`: the Go tunnel client library |
| `e2e` | `e2e/`: testcontainers harness + scenarios |
| `deploy` | `deploy/`: compose, Traefik, observability provisioning, fetcher |
| `scripts` | `deploy/scripts/` + `scripts/`: fetch/gen-ca/dev-tooling scripts |
| `ci` | `.github/workflows/` |
| `make` | `Makefile` |
| `docs` | `docs/` (PROJECT, ARCHITECTURE, PROTOCOL, plans) + `README.md` |
| `deps` | dependency-only updates (`go.mod`, `go.sum`) |

```
fix(phoneconn): supersede a stale connection on rebind without clobbering the route
```

---

## Standard Commands

The `Makefile` is the authoritative command surface:

- `make build` — `bin/tunneld` (version ldflags)
- `make lint` — `golangci-lint` ×3 (default / `integration` / `e2e` build tags — tagged files are
  invisible to an untagged run) + `shellcheck` + `compose-config`
- `make vet` — `go vet`
- `make govulncheck` — vulnerability scan (pinned via the `go.mod` `tool` directive, never `@latest`)
- `make test-unit` — unit tests (`-short -race -count=1`)
- `make test-integration` — `-tags=integration` suite (`-race`; in-process real server + miniredis)
- `make test-e2e` — `-tags=e2e` testcontainers suite (`-race`; needs Docker)
- `make test-all` — `test-unit` + `test-integration` + `test-e2e`
- `make test-scripts` — POSIX harness for the `deploy/scripts/` fetch/gen-ca scripts
- `make compose-config` — validates `deploy/docker-compose.yml` (placeholder env from
  `deploy/.env.example`)
- `make mermaid-check` — validate all Mermaid blocks in `README.md` + `docs/` via `mmdc`
- `make tidy` — `go mod tidy`

There is NO dotenv convention for tests in this repo: unit and integration tests are self-contained
(miniredis, httptest, temp CA files); e2e needs only a working Docker daemon. CI
(`.github/workflows/ci.yml`) runs `static-checks` (lint ×3, govulncheck, tidy-drift, shellcheck,
script tests, compose config, mermaid-check), `build`, `test-unit`, `test-integration`, `test-e2e`,
and `image`; releases run from `.github/workflows/release.yml` on `v*` tags.

---

## Key Conventions

- **Go layering per `go.md`**: interface-first at the consumer site (`observ.Recorder` is THE
  example — US6/US7/US8 handlers depend on it, `metrics.PromRecorder` implements it), constructor
  DI (all wiring happens in `server.Run` — no package globals), `context.Context` first on any
  I/O, `errgroup` for the process's goroutine groups.
- **Every goroutine has a shutdown path**: conn read-pump/heartbeat/keepalive tied to the conn
  ctx; `ServeNode` and the flusher on the drain ctx; shutdown order is public-listener drain →
  drain-cancel → WS teardown (see `docs/ARCHITECTURE.md`).
- **Config via kong flags + `TUNNELD_*` env twins**, validated fail-fast in `Validate()`. NO
  hardcoded secrets or environment-specific values; byte sizes are BINARY (`1mb` = 1048576),
  bitrates are DECIMAL bits (`1mbit` = 125000 B/s) — two distinct parsers.
- **`internal/clientip.TrustedIP` is the ONLY code path that derives the abuse-control IP.** Never
  add another.
- **Rejection reasons are the literal `tunneld_rejections_total{reason}` labels** — every
  registered reason label has exactly the writers the architecture doc lists; never abbreviate or
  invent reason strings at call sites.
- **Testing**: unit = miniredis/httptest/fake clock, no sockets where avoidable; integration
  (`//go:build integration`) = the REAL assembled server (`server.Run`) on real ports + miniredis;
  e2e (`//go:build e2e`) = testcontainers (Redis + Traefik + two replicas). Shared fakes live in
  `internal/tunneltest` (capturing Recorder, FakePhone).
- **Logging with `log/slog`** through the fan-out handler; identifiers on every line; deduped
  cap-hit events via `internal/caplog`.

---

## Rule Map

| Concern | Rule file |
|---|---|
| Agnostic agent behavior, git, plans, reviews, subagents | `agent.md` |
| Plan-driven development pipeline (write → review → implement → PR) + Mermaid validation | `development_pipeline.md` |
| Go language conventions | `go.md` |
| GitHub (`gh` CLI, branches, PRs) (tooling) | `github.md` |
| Project context (this file) | `project.md` |
