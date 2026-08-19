# tunneld — Self-Hosted Tunnel Server — Project Rules

`tunneld` is a self-hosted, abuse-resistant **end-to-end-encrypted tunnel server** (Go) that gives the
Android MCP app (`android-remote-control-mcp`) a stable public hostname. External clients establish TLS
**directly with the phone**, which holds a publicly-trusted (WebPKI) certificate for
`<name>.<tunnel-domain>`. tunneld is the internet edge on **raw TCP `:443`** (there is NO reverse proxy):
it peeks each ClientHello (SNI/ALPN/version/JA4), routes on SNI, and splices the **opaque encrypted byte
stream** to the phone over an internal mTLS **mesh** — it can NEVER read tunnel traffic. Run **one
replica per host**; **Valkey** holds transient control state (TTL'd), a plain **S3** bucket holds the
durable state (name registry, connection logs, rejected-enroll evidence). Identity is earned by
**two-phase attested enrollment** (Android hardware key attestation → identity mTLS cert → server-run
ACME public cert). Abuse is contained by layered caps and a hot-reloadable ban/geo engine.

> **STATUS: Plan 3 (E2E) implemented.** Plan 3 (`docs/plans/3_e2e_encrypted_tunneling_20260817175922.md`)
> replaces the Plan-1 HTTP/WebSocket-proxy architecture end to end. Releases are cut from `v*` tags via
> goreleaser; multi-arch images are published to `ghcr.io/danielealbano/tunneld`.

## MANDATORY: Read These First

You MUST ALWAYS read these documents before ANY work, in this order:

1. **`docs/PROJECT.md`** — operational reference: what tunneld is, topology, identity/auth,
   caps, ban/geo engine, state + retention, observability, non-goals. **Entry-level read.**
2. **`docs/ARCHITECTURE.md`** — system map: package layout, the raw `:443` SNI edge, the public
   connection lifecycle (fast path + mesh), enrollment/issuance/renewal, bandwidth model, Valkey +
   S3 state, shutdown. **Entry-level read.**
3. **`docs/PROTOCOL.md`** — the wire protocol: two-phase enrollment, the mTLS `/issue` endpoint, the
   v2 control frames, the opaque data splice, the mesh stream header, and the security invariants.
   **CANONICAL wire contract** — the Go client in `client/` and the future Kotlin client MUST both
   conform. **ESSENTIAL.**
4. **`docs/plans/3_e2e_encrypted_tunneling_20260817175922.md`** — the decision record (every design
   decision was agreed with the user there, incl. the `## Deviations` log). CANONICAL when a design
   detail is disputed.

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
| CLI / env config | `github.com/alecthomas/kong` | One `tunneld` binary: `serve` / `version`; every flag has a `TUNNELD_*` env twin (`kong.DefaultEnvars`, `--s3-*` → `TUNNELD_S_3_*`); `Validate()` enforces every cross-field invariant at startup. |
| Phone control + replica mesh | `golang.org/x/net/http2` (mTLS) | Phone control plane (`/control`, `/data`, `/issue`) + replica↔replica mesh; binary control frames per `docs/PROTOCOL.md`; the data stream is an opaque splice. |
| Control plane (transient) | Valkey via `github.com/redis/go-redis/v9` | Routing `route:{name}` + node registry + rate/concurrency/nonce/ACME-cooldown. **TTL'd transient state ONLY** — see invariants. |
| Durable store | AWS S3 SDK v2 (`github.com/aws/aws-sdk-go-v2`) / MinIO stand-in | Plain Get/Put/Delete only (no conditional writes); name registry + conn logs + rejected-enroll evidence; write-verify name claim. |
| ACME issuance | `github.com/go-acme/lego/v4` | LE→GTS→ZeroSSL chain, DNS-01, spillover, per-CA cooldown/backoff retry-after, self-heal. |
| Attestation | Android hardware key attestation (`internal/attest`) | Seven-point predicate + key binding; roots/status refreshers; signer-digest allowlist. |
| Ban/geo LPM table | `github.com/gaissmai/bart` + `go4.org/netipx` | Longest-prefix-match over `netip`; atomic snapshot swap on reload; DB-IP Country Lite CSV range→prefix expansion. |
| Metrics | `github.com/prometheus/client_golang` | Custom registry on the INTERNAL listener only; NO per-tunnel labels. |
| Logging | `log/slog` fan-out + `gopkg.in/natefinch/lumberjack.v2` | Repeatable composite `--log` sinks; `std` splits by severity (info+ → stdout, warn+ → stderr). |
| Unit-test Valkey | `github.com/alicebob/miniredis/v2` | In-process; UNIT tier only. |
| Integration + e2e infra | `github.com/testcontainers/testcontainers-go` | Valkey + MinIO + Pebble/challtestsrv (`//go:build integration` / `e2e`); needs Docker. |
| Edge / deployment | NO proxy — raw `:443` + Docker Compose | `deploy/`: one `tunneld` on :443, valkey, minio (+bucket-create), fetcher, prometheus/grafana/alertmanager/ntfy on `127.0.0.1`-only ports. |
| Release | goreleaser (`v*` tags) | linux amd64+arm64 archives + multi-arch image `ghcr.io/danielealbano/tunneld`. |
| Source control | **GitHub**, `danielealbano/android-remote-control-mcp-tunneld` | See `github.md`. |

---

## Hard Project Invariants — ABSOLUTE RULES

These come from `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md`, and the Plan 3 decision record. They
MUST NOT be relaxed without explicit user direction.

### End-to-end encryption — SACRED
- **tunneld relays OPAQUE TLS bytes and MUST NEVER read, terminate, or inspect tunnel traffic.** The
  phone terminates TLS with its own WebPKI cert. There is NO HTTP request forwarding, NO method/path
  allowlist on relayed traffic, and NO `X-Forwarded-*` handling. The public edge is a raw `:443` SNI
  splice; `wire.ChunkSize` = 32768 is the paced-copy slice size, NOT a framed protocol.

### Identity & authentication — SACRED
- **Two-phase attested enrollment.** Phase 1 (`/enroll`, server-TLS): attestation (seven-point
  predicate) + key binding → the server assigns a random name and signs a bootstrap identity (mTLS)
  cert. Phase 2 (mTLS `/issue` on `--control-host`): the phone submits a TLS CSR for
  `<name>.<tunnel-domain>`; the server re-verifies attestation and issues the public WebPKI cert via
  ACME (regenerating identity + public certs together). Renewal is the SAME `/issue` endpoint.
- **The server assigns the name (random, base32) and writes it into the identity-cert CN** (the CSR
  subject is ignored); the public cert is issued for the server-dictated `<name>.<tunnel-domain>` — at
  issuance the name is read from the **mTLS client-cert CN** and the TLS CSR MUST request exactly that.
  Enrollment accepts **ECDSA P-256 keys ONLY**.
- **mTLS with role separation.** The phone authenticates with its identity cert over the control
  connection; the replica mesh uses distinct **mesh-role** certs (SAN = node id, verified by chain +
  role, NOT hostname). There is **NO TLS mutual auth on the PUBLIC side** (the edge relays opaque TLS).
  The phone control listener REJECTS a mesh-role cert; the mesh listener REJECTS an identity-role cert.
- **Revocation is the ban engine ONLY** (no CRL): `tunnel-name` / `tunnel-fingerprint` bans are enforced
  at the phone control connection, at the public SNI edge (on the resolved route), and live on ban reload
  via BOTH the `EvictBanned` hook (phone control conn) AND the `EvictBannedStreams` hook (in-flight public
  splices, `close_reason=ban-evict`). All these points MUST stay wired.

### Source-IP + ingress — SACRED
- The IP for ban checks, rate limits, and quotas is the **peer address of the raw TCP connection** (the
  edge is the internet edge — there is no proxy and no `--client-ip-header`).
- **The ban check is the FIRST handler-level check on every ingress edge** (public SNI, `/enroll`,
  `/control`), keyed on that IP. **Never publish** the mesh (`:9443`) or internal (`:9090`) ports —
  only the raw edge `:443` is public.
- The public edge dispatches by SNI: `<name>.<tunnel-domain>` → route+splice; `--enroll-host` /
  `--control-host` → local termination; anything else → close (`no-route`). Caps are UNIFORM — NO
  per-path exceptions. Operators raise the `--limit-*` values, never the code.

### Valkey (transient) + S3 (durable) state — SACRED
- **NO permanent Valkey state, EVER.** Every key (routing, node registry, rate-limit windows,
  concurrency counters, per-tunnel `tcnt:{name}`, enrollment nonces, ACME cooldown/backoff) carries a
  TTL set **atomically in the SAME Lua script** as its INCR/HINCRBY/SET. Route teardown/refresh is
  **owner-conditional on the per-connection `connID`** — a stale connection MUST NOT clobber a re-bound
  route.
- **The ONLY durable server-side state is S3** (`internal/store`): the name registry, connection logs,
  and rejected-enroll evidence, via plain Get/Put/Delete (NO conditional writes — runs on any plain S3).
  Name uniqueness is the **write-verify claim** (GET-absent → PUT nonce under a hard timeout, SDK
  retries disabled → settle wait > the PUT timeout → GET-verify). Lifecycle expiry (logs 90d,
  rejected-enroll 30d) is applied programmatically at startup.

### Wire protocol — FROZEN BY `docs/PROTOCOL.md`
- v2 control frames: `[type:1][payloadLen:4 BE][payload JSON]` (OPEN/PING/PONG/RENEW_NUDGE — the type
  values are frozen); the data stream is an OPAQUE unframed splice (`wire.ChunkSize` = 32768 is the
  pacing slice). A mesh stream identifies itself via the `X-Tunnel`/`X-Conn-Id`/`X-Stream-Id` request
  headers (replica↔replica only — not part of the phone contract). ANY wire change MUST update
  `docs/PROTOCOL.md` and the Go client in `client/` together (the future Kotlin client conforms to the
  spec, not to the Go source).

### Bandwidth model
- Per-tunnel, per-direction pacing draws from ONE global Valkey token bucket (`bw:{name}:{dir}`) in
  **~1 MB batches** into a per-stream local credit — the data plane hits the control plane ~once/MB
  (a synchronous per-32 KiB-slice Valkey call was REJECTED). An empty bucket blocks the copy in short
  refill waits; a Valkey ERROR fails open. Byte ACCOUNTING (day/week) is still recorded per chunk; an
  exhausted window refuses NEW streams at admission. The blocking refill wait MUST NEVER be held under
  a connection write mutex. The global stream-counter key `conc:{name}` carries TTL = 3 ×
  `--limit-conn-idle`, refreshed by a `PEXPIRE` piggybacked on the per-chunk accounting script (a
  no-op on a missing key, so a torn-down counter is never resurrected).

### Observability
- Prometheus metrics live on the INTERNAL listener ONLY (never published) and MUST NOT carry
  per-tunnel labels (cardinality); the per-tunnel view is `/admin/tunnels` from the TTL'd Valkey
  counters, written ASYNCHRONOUSLY by the recorder's background flusher — never synchronously on
  the data plane.
- Cap-hit logging is deduplicated (first hit per `(tunnel, reason)` immediately, then ≤1
  summary/min) — attacker-driven log flooding MUST stay impossible. EXCEPTION: `no-route` (whose tunnel
  value is attacker-controlled raw SNI) is metric + Debug-line ONLY — it MUST NEVER key the dedup map.
- Connection-log S3 writes are ASYNC (`store.AsyncConnLog`): enqueue is O(1) and MUST NEVER block an
  admission/splice/teardown path; a bounded 5000-event queue + 8 workers + per-item exponential retry
  drain it; a full queue drops-newest and increments `tunneld_connlog_dropped_total`; shutdown drains
  the queue (bounded) so `server-shutdown` end events land.
- NEVER log secrets, key material, or tunnel payloads.

### Repository hygiene
- **Placeholder values ONLY in-repo**: domains (`example.test`, `free.example.com`), country codes
  (`XX`/`YY` — NEVER a real country code or name anywhere), secrets (`changeme`). Real values live
  in the operator's private `.env` / `tunneld.env` / ban files.
- The DB-IP Country Lite **CC BY 4.0 attribution** in the README MUST be preserved.
- No AI attribution anywhere (per `agent.md`).

---

## Non-goals (MUST NOT build)

- No database / persistent server-side identity store (the phone holds its cert). No reverse proxy
  (tunneld IS the raw `:443` edge). No authentication of relayed traffic (it is opaque TLS; the app
  authenticates). No HTTP request inspection / method-path allowlist on relayed traffic. No per-path cap
  exceptions or bulk-transfer support. No CRL (bans are the only revocation). No cross-replica exact
  bandwidth accounting. No server-side content storage or caching. No TLS mutual auth on the public side.
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
| `limit` | `internal/limit`: rate windows, enroll quota, global stream counter, batch-credit bandwidth, ACME cooldown |
| `ca` | `internal/ca`: CA loader, identity + mesh-role signing, name generation, fingerprint |
| `router` | `internal/router`: Valkey routing registry (route bind/heartbeat/unbind/lookup) + node registry |
| `store` | `internal/store`: durable S3/MinIO name registry (write-verify claim), connection logs, rejected-enroll evidence, lifecycles |
| `attest` | `internal/attest`: Android key-attestation verifier (KeyDescription parse, roots/status refreshers, signer allowlist) |
| `acme` | `internal/acme`: LE→GTS→ZeroSSL issuance chain (lego clients, DNS-01, per-CA cooldown/backoff retry-after) |
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
| `deploy` | `deploy/`: compose, MinIO/Valkey, observability provisioning, fetcher |
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
- `make test-integration` — `-tags=integration` suite (`-race`; real `server.Run` + testcontainers Valkey/MinIO/Pebble; needs Docker)
- `make test-e2e` — `-tags=e2e` suite (`-race`; two in-process replicas + testcontainers; adb-gated attestation test skips without a device; needs Docker)
- `make test-all` — `test-unit` + `test-integration` + `test-e2e`
- `make test-scripts` — POSIX harness for the `deploy/scripts/` fetch/gen-ca scripts
- `make compose-config` — validates `deploy/docker-compose.yml` (placeholder env from
  `deploy/.env.example`)
- `make mermaid-check` — validate all Mermaid blocks in `README.md` + `docs/` via `mmdc`
- `make tidy` — `go mod tidy`

There is NO dotenv convention for tests in this repo: unit tests are self-contained (miniredis,
httptest, temp CA files); the integration + e2e tiers provision everything via testcontainers and need a
working Docker daemon. CI
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
  ctx; the mesh/edge/flusher goroutines on the drain ctx; shutdown order is raw-`:443` listener close →
  server drains → schedulers/watchers unwind (see `docs/ARCHITECTURE.md`).
- **Config via kong flags + `TUNNELD_*` env twins** (`--s3-*` → `TUNNELD_S_3_*`), validated fail-fast in
  `Validate()`. NO hardcoded secrets or environment-specific values; byte sizes are BINARY
  (`1mb` = 1048576), bitrates are DECIMAL bits (`1mbit` = 125000 B/s) — two distinct parsers.
- **The abuse-control IP is the raw-TCP peer address** (tunneld is the internet edge — no proxy header).
- **Rejection reasons are the literal `tunneld_rejections_total{reason}` labels** — every
  registered reason label has exactly the writers the architecture doc lists; never abbreviate or
  invent reason strings at call sites.
- **Testing**: unit = miniredis/httptest/fake clock, no sockets where avoidable; integration
  (`//go:build integration`) = the REAL assembled server (`server.Run`) + testcontainers
  Valkey/MinIO/Pebble; e2e (`//go:build e2e`) = two in-process replicas + shared testcontainers. Shared
  fakes + the containers harness live in `internal/tunneltest`.
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
