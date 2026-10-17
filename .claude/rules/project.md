# tunneld — Self-Hosted Tunnel Server — Project Rules

`tunneld` is a self-hosted, abuse-resistant **end-to-end-encrypted tunnel server** (Go) that gives the
Android MCP app (`android-remote-control-mcp`) a stable public hostname. External clients establish TLS
**directly with the phone**, which holds a publicly-trusted (WebPKI) certificate for
`<name>.<tunnel-domain>`. tunneld is the internet edge on **raw TCP `:443`** (there is NO reverse proxy):
it peeks each ClientHello (SNI/ALPN/version/JA4), routes on SNI, and splices the **opaque encrypted byte
stream** to a connection the phone dials back to the entry node (the replicas' mTLS **mesh** carries
control RPCs only) — it can NEVER read tunnel traffic. Run **one
replica per host**; **Valkey** holds transient control state (TTL'd), a plain **S3** bucket holds the
durable state (name registry, connection logs, rejected-enroll evidence). Identity is earned by
**two-phase attested enrollment** (Android hardware key attestation → identity mTLS cert → server-run
ACME public cert). Abuse is contained by layered caps and a hot-reloadable ban/geo engine.

> **STATUS: Plan 3 (E2E) implemented; Plan 16 (entry-node dial-back, wire v2) implemented; Plan 17 (ACME
> issuance budgets, phone liveness and issuance retries) implemented.** Plan 3
> (`docs/plans/3_e2e_encrypted_tunneling_20260817175922.md`) replaces the Plan-1 HTTP/WebSocket-proxy
> architecture end to end; Plan 16 (`docs/plans/16_entry_node_dial_back_20261014192454.md`) replaces its
> dial-back/data path; Plan 17 (`docs/plans/17_acme_budgets_and_client_resilience_20261015170942.md`) adds the
> ACME issuance budgets and the phone liveness and issuance-retry rules. Releases are cut from `v*` tags via goreleaser; multi-arch images are published to
> `ghcr.io/danielealbano/tunneld`.

## MANDATORY: Read These First

You MUST ALWAYS read these documents before ANY work, in this order:

1. **`docs/PROJECT.md`** — operational reference: what tunneld is, topology, identity/auth,
   caps, ban/geo engine, state + retention, observability, non-goals. **Entry-level read.**
2. **`docs/ARCHITECTURE.md`** — system map: package layout, the raw `:443` SNI edge, the public
   connection lifecycle (entry-node dial-back), enrollment/issuance/renewal, bandwidth model, Valkey +
   S3 state, shutdown. **Entry-level read.**
3. **`docs/PROTOCOL.md`** — the wire protocol: two-phase enrollment, the mTLS `/api/v1/issue` endpoint, the
   control frames, the dial-back upgrade, the mesh control RPCs, and the security invariants.
   **CANONICAL wire contract** — the Go client in `client/` and the future Kotlin client MUST both
   conform. **ESSENTIAL.**
4. **`docs/plans/3_e2e_encrypted_tunneling_20260817175922.md`** — the decision record (every design
   decision was agreed with the user there, incl. the `## Deviations` log). CANONICAL when a design
   detail is disputed — except the dial-back/data path, whose decision record is
   **`docs/plans/16_entry_node_dial_back_20261014192454.md`**, and the name claim: the user replaced Plan 3's
   write-verify claim with the Valkey claim lock on 2026-10-16 (described in `docs/ARCHITECTURE.md` §6).

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
| Phone control + replica mesh | `net/http` built-in HTTP/2 (mTLS) | Phone control plane (`/api/v1/control`, `/api/v1/issue`) + replica↔replica mesh control RPCs; binary control frames per `docs/PROTOCOL.md`; the data path is an HTTP/1.1-upgraded dial-back connection (`/api/v1/data`) carrying an opaque splice. |
| Control plane (transient) | Valkey via `github.com/redis/go-redis/v9` | Routing `tunnel:{name}` + node registry + rate/concurrency/nonce/ACME-cooldown. **TTL'd transient state ONLY** — see invariants. |
| Durable store | AWS S3 SDK v2 (`github.com/aws/aws-sdk-go-v2`) / MinIO stand-in (PGSTY Silo build) | Plain Get/Put/Delete only (no conditional writes); name registry + conn logs + rejected-enroll evidence; Valkey-locked name claim. |
| ACME issuance | `github.com/go-acme/lego/v5` | LE→GTS→ZeroSSL chain, DNS-01 / HTTP-01 / TLS-ALPN-01 per CA (answered by tunneld's own listeners from Valkey-shared challenge state), spillover, optional CAs, per-account Valkey issuance budgets + wait-until/backoff, several GTS accounts looked up by key, self-heal. |
| Attestation | Android hardware key attestation (`internal/attest`) | Seven-point predicate + key binding; roots/status refreshers; signer-digest allowlist. |
| Ban/geo LPM table | `github.com/gaissmai/bart` + `go4.org/netipx` | Longest-prefix-match over `netip`; atomic snapshot swap on reload; DB-IP Country Lite CSV range→prefix expansion. |
| Metrics | `github.com/prometheus/client_golang` | Custom registry on the INTERNAL listener only; NO per-tunnel labels. |
| Logging | `log/slog` fan-out + `gopkg.in/natefinch/lumberjack.v2` | Repeatable composite `--log` sinks; `std` splits by severity (info+ → stdout, warn+ → stderr). |
| Unit-test Valkey | `github.com/alicebob/miniredis/v2` | In-process; UNIT tier only. |
| Integration + e2e infra | `github.com/testcontainers/testcontainers-go` | Valkey + MinIO (PGSTY Silo build) + Pebble/challtestsrv (`//go:build integration` / `e2e` / `staging`); needs Docker. The `staging` tier also uses real LE / GTS staging through a reverse SSH tunnel. |
| Edge / deployment | NO proxy — raw `:443` + Docker Compose | `deploy/`: one `tunneld` on :443 (+ :80 for ACME HTTP-01 and plain dial-backs), valkey, minio (+bucket-create), fetcher; `deploy/prometheus/` + `deploy/grafana/` are the operator-run monitoring configs (not in compose). |
| Release | goreleaser (`v*` tags) | linux amd64+arm64 archives + multi-arch image `ghcr.io/danielealbano/tunneld`. |
| Source control | **GitHub**, `danielealbano/android-remote-control-mcp-tunneld` | See `github.md`. |

---

## Hard Project Invariants — ABSOLUTE RULES

These come from `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md`, and the Plan 3 decision record (Plan 16 for the
dial-back/data path). They
MUST NOT be relaxed without explicit user direction.

### Engineering posture — simplest correct design
- tunneld is a self-hosted, free service with small (4–8 KB) payloads, not a high-precision accounting
  system. Prefer, in order: a single atomic command → a plain pipeline with self-healing TTLs
  (`EXPIRE NX`, or an existence-guarded `HINCRBY`+`EXPIRE NX`) → a `SETNX` lock around a real critical
  section → anything heavier only if none of those is correct. Never use Lua / WATCH / MULTI-EXEC to force
  "provable" atomicity on a rare, self-healing race. The data-plane limiter fails **open**; abuse caps fail **safe** (an over-count
  denies, never breaches). A simpler design is acceptable only while it converges to correct within
  bounded time, leaves no persistently-wrong state, and opens no security/abuse gap — otherwise it is a
  bug, not a trade.

### End-to-end encryption — SACRED
- **tunneld relays OPAQUE TLS bytes and MUST NEVER read, terminate, or inspect tunnel traffic.** The
  phone terminates TLS with its own WebPKI cert. There is NO HTTP request forwarding, NO method/path
  allowlist on relayed traffic, and NO `X-Forwarded-*` handling. The public edge is a raw `:443` SNI
  splice to the phone's dial-back connection to the ENTRY node — no data crosses nodes; `wire.ChunkSize` = 16384 is the paced-copy read-slice size, NOT a framed protocol. A ClientHello whose first ALPN protocol is `acme-tls/1` is an ACME TLS-ALPN-01 validation addressed to tunneld — answered locally with its challenge certificate and NEVER spliced (it carries no tunnel traffic).

### Identity & authentication — SACRED
- **Two-phase attested enrollment.** Phase 1 (`/api/v1/enroll`, server-TLS): attestation (seven-point
  predicate) + key binding → the server assigns a random name and signs a bootstrap identity (mTLS)
  cert. Phase 2 (mTLS `/api/v1/issue` on `--control-host`): the phone submits a TLS CSR for
  `<name>.<tunnel-domain>`; the server re-verifies attestation and issues the public WebPKI cert via
  ACME (regenerating identity + public certs together). Renewal is the SAME `/api/v1/issue` endpoint.
- **The server assigns the name (random, base32) and writes it into the identity-cert CN** (the CSR
  subject is ignored); the public cert is issued for the server-dictated `<name>.<tunnel-domain>` — at
  issuance the name is read from the **mTLS client-cert CN** and the TLS CSR MUST request exactly that.
  Enrollment accepts **ECDSA P-256 keys ONLY**.
- **mTLS with role separation.** The phone authenticates with its identity cert over the control
  connection, and on every dial-back when `--dialback-mtls` (default on); splices end when the control
  connection they were opened through closes; the replica mesh uses distinct **mesh-role** certs (SAN = node id, verified by chain +
  role, NOT hostname). There is **NO TLS mutual auth on the PUBLIC side** (the edge relays opaque TLS).
  The phone control listener REJECTS a mesh-role cert; the mesh listener REJECTS an identity-role cert.
- **Revocation is the ban engine ONLY** (no CRL): `tunnel-name` / `tunnel-fingerprint` bans are enforced
  at the phone control connection, at the public SNI edge (on the resolved route), and live on ban reload
  via BOTH the `EvictBanned` hook (phone control conn) AND the `EvictBannedStreams` hook (in-flight public
  splices, `close_reason=ban-evict`). All these points MUST stay wired.

### Source-IP + ingress — SACRED
- The IP for ban checks, rate limits, and quotas is the **peer address of the raw TCP connection** (the
  edge is the internet edge — there is no proxy and no `--client-ip-header`).
- **The ban check is the FIRST handler-level check on every ingress edge** (public SNI, the plain `:80` listener (ACME HTTP-01 + plain dial-backs), `/api/v1/enroll`,
  `/api/v1/control`), keyed on that IP. A peer address that does not parse as an IP cannot be ban-checked, so
  every ingress edge REFUSES it before the ban gate (fail closed, Debug-logged). **Never publish** the mesh (`:9443`) or internal (`:9090`) ports —
  only the raw edge `:443` and the plain `:80` listener (ACME HTTP-01 + plain dial-backs) are public.
- The public edge answers a ClientHello whose first ALPN protocol is `acme-tls/1` locally (TLS-ALPN-01), then dispatches by SNI: `<name>.<tunnel-domain>` → route+splice; `--enroll-host` /
  `--control-host` → local termination; anything else → close (`no-route`). Caps are UNIFORM — NO
  per-path exceptions. Operators raise the `--limit-*` values, never the code.

### Valkey (transient) + S3 (durable) state — SACRED
- **NO permanent Valkey state, EVER.** Every key (routing `tunnel:{name}`, node registry + the `nodes` id
  set, rate-limit windows, the `conc:{name}` stream-cap sorted set, the per-second `bw:`/`pkt:` bandwidth windows and the per-direction
  `traf:{name}:{dir}:day/week:{n}` traffic windows, enrollment nonces, ACME cooldown/backoff, the per-account 429 mark `acme-429:` (`SET … EX`, longer than any order lives), the ACME challenge keys `acme:alpn:` / `acme:http:`, the per-name
  locks, the name-claim lock `lock:claim:` (TTL `--registry-claim-settle`, never released), the reserved-host issuance lock `lock:acme-self:` and the shared reserved-host cert `acme:self-cert:` — TTL = until the cert's NotAfter; it holds the private key, so Valkey stays private, the ACME issuance budgets (`acme-budget:` via `HSET` + pipelined `PEXPIRE`, TTL = time to refill + 1 h; `acme:inflight:` via `ZADD` + pipelined `EXPIRE NX` + `EXPIRE GT`, TTL = deadline + 1 min, never shortened; `lock:acme-budget:` a `SETNX` lock, 2 s TTL)) gets a TTL in the SAME round-trip as its mutation — via `SET … EX`, a `SETNX … EX` lock, a
  pipelined `EXPIRE NX` right after the `INCR`, or a pipelined `PEXPIRE` (the `conc:{name}` and `nodes` sets); the per-account ACME wait-until uses a pipelined `EXPIRE GT` + `SET NX EX` so it is never shortened. `EXPIRE NX` self-heals a skipped TTL on the next
  same-window write, so a plain pipeline is the correct, simpler tool for the self-healing transient
  counters. Per the engineering posture, this uses **NO Lua / WATCH / MULTI-EXEC** — a single command, a
  self-healing pipeline, or a `SETNX` lock covers every case.
- **Route ownership is deterministic and clobber-free.** Create/delete of the `tunnel:{name}` routing key
  is serialized by a per-name `SETNX` lock, and delete is conditional on the stored per-connection
  `connID`, so a stale connection can NEVER clobber a re-bound route. The heartbeat only refreshes the TTL
  (`PEXPIRE`) and never rewrites the value; the byte counters co-located in `tunnel:{name}` are written
  existence-guarded (`HINCRBY` + `EXPIRE NX`) so a post-disconnect flush never resurrects a dead route.
- **Live-vs-identity invariant.** `conc:{name}` (concurrent streams) is a sorted set with one member per live
  public connection (its dial-back token) scored by its expiry: expired members are pruned at admission, a
  release removes only its own member — no lock, no reset on reconnect. Identity-scoped cumulative quotas
  (`traf:` day/week traffic, issuance/`--issue-per-week`) MUST PERSIST across reconnects — a tunnel MUST NOT
  reset its quota just by reconnecting.
- **The ONLY durable server-side state is S3** (`internal/store`): the name registry, connection logs,
  and rejected-enroll evidence, via plain Get/Put/Delete (NO conditional writes — runs on any plain S3).
  Name uniqueness is the **Valkey claim lock**: `SET lock:claim:{name} NX EX` (taken → new name; never
  released; TTL `--registry-claim-settle` > the claim deadline) → GET-absent → PUT the record, all under one
  `--registry-claim-timeout` deadline started before the lock, SDK retries disabled. Retention (logs 90d, rejected-enroll
  30d) is a one-time lifecycle setup on the bucket — tunneld never touches bucket configuration (see
  `docs/PROJECT.md` §5). Connection logs are only SPOOLED on the node
  (`--conn-log-dir`, one process per directory) until uploaded — a transient buffer, not a store.

### Wire protocol — FROZEN BY `docs/PROTOCOL.md`
- Control frames: `[type:1][payloadLen:4 BE][payload JSON]` (OPEN/PING/PONG/RENEW_NUDGE — the type
  values are frozen); `OPEN{token, addr, use_https, use_mtls}`; the phone answers with a NEW connection to
  `addr` carrying a `GET /api/v1/data` HTTP/1.1 upgrade with the token (`101`, then an OPAQUE unframed splice;
  `wire.ChunkSize` = 16384 is the pacing slice). The mesh carries control RPCs only (`renew`, `terminate`,
  `open`, `evict` — replica↔replica, not part of the phone contract). ANY wire change MUST update
  `docs/PROTOCOL.md` and the Go client in `client/` together (the future Kotlin client conforms to the
  spec, not to the Go source).

### Unified per-window limit model
- Every read charges ONE unified `Charge` against ALL four per-window counters in a single plain pipelined
  round-trip (`INCRBY`/`INCR` + `EXPIRE … NX` — **NO Lua**, **NO `TxPipeline`**): the per-second byte
  window `bw:{name}:{dir}:{unix_second}`, the per-second packet window `pkt:{name}:{dir}:{unix_second}`,
  and the **per-direction** day/week traffic windows `traf:{name}:{dir}:day:{unix_day}` /
  `traf:{name}:{dir}:week:{unix_week}` (`unix_day = unix_second/86400` UTC-midnight days,
  `unix_week = unix_day/7` epoch-aligned 7-day blocks — clock-aligned; the reset is computed from the
  clock, no `PTTL`). `Charge` returns an action: **Proceed** (under all caps), **Wait** (over a cap whose
  window resets within `maxPacingWait` = **5 s** → wait, then forward — that wait IS the pacing), or
  **Kill** (over a cap whose window resets beyond 5 s → end the stream, with the window label for the
  metric). `Kill` takes precedence over `Wait`. `EXPIRE NX` self-heals a skipped TTL on the next
  same-window write (so strict atomicity is unwarranted for these transient windows); a Valkey ERROR
  yields `Proceed` (fail-open). Each key's TTL is its window plus a fixed **1 h** margin (per-second = 3 s,
  day = 25 h, week = 7 d + 1 h). The read slice is `wire.ChunkSize` = 16384, so the per-second overshoot is
  bounded by `byteCap + N_concurrent × 16 KiB` / `pktCap + N_concurrent`. `--limit-packets` (default 100)
  is a loose tiny-packet-flood backstop; the byte rate is the primary limit. An exhausted day/week window
  also refuses NEW streams at admission (`TrafficExhausted`, read-only). The blocking wait MUST NEVER be
  held under a connection write mutex. The global stream-cap key `conc:{name}` is a sorted set (member =
  the public connection's dial-back token, score = its expiry in unix ms); the `Charge` pipeline refreshes the
  stream's own member (`ZADD XX`, never resurrecting a released one) and the key TTL = 3 × `--limit-conn-idle`.
  See the live-vs-identity invariant above.

### Observability
- Prometheus metrics live on the INTERNAL listener ONLY (never published) and MUST NOT carry
  per-tunnel labels (cardinality); the per-tunnel view is the paginated `GET /api/v1/admin/tunnels/list`
  name list + `POST /api/v1/admin/tunnels/stats` (per-tunnel node/bytes/conc/bw/day/week, composed from the
  routing key + the TTL'd Valkey windows; the byte counters are written ASYNCHRONOUSLY by the recorder's
  background flusher — never synchronously on the data plane).
- Cap-hit logging is deduplicated (first hit per `(tunnel, reason)` immediately, then ≤1
  summary/min) — attacker-driven log flooding MUST stay impossible. EXCEPTION: `no-route` (whose tunnel
  value is attacker-controlled raw SNI) is metric + Debug-line ONLY — it MUST NEVER key the dedup map. `acme-http-miss` (an unmatched `:80` request; empty tunnel value) uses the standard dedup and is kept out of the `NoRouteSpike` alert. Go HTTP-server errors (failed TLS handshakes) go through slog: Debug on the public enroll/control/`:80` servers, Warn on mesh/internal.
- Connection logs are SPOOLED and uploaded per node (`store.ConnLogSpool`): enqueue is O(1) and MUST NEVER
  block an admission/splice/teardown path (a 5000-event channel → ONE writer appending JSON lines to a local
  file in `--conn-log-dir`); files rotate at clock-aligned 5-minute windows / 16 MiB / shutdown and a
  separate uploader puts each as `tunnel-logs/<yyyy>/<mm>/<dd>/<file-start>-<node-id>.jsonl` (all tunnels
  mixed; key from the file name, so re-uploads overwrite), deleting it locally ONLY after the upload
  succeeds. An S3 outage loses nothing below the 1 GiB spool cap; `tunneld_connlog_dropped_total` counts
  events lost to a full channel, a failed append, the cap, still being queued at the shutdown deadline, or
  arriving after shutdown; every Warn on this path is rate-bounded. Shutdown rotates + uploads within
  `--shutdown-grace`; leftovers upload at the next start.
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
- The Android (Kotlin) client integration is **out of scope** of this repo — it lives with the app. Three
  on-device test apps under `support/` are the only exceptions, and none is the client: a minimal
  **attestation test probe** (`support/attest-probe/`) driving the adb-gated `TestE2E_DeviceAttestation`
  gate, a complete **reference tunnel client** (`support/tunnel-app/`) — a faithful Kotlin
  implementation of the phone side of `docs/PROTOCOL.md` — driving the adb-gated
  `TestE2E_ReferenceTunnelApp` gate, and the **soak app** (`support/soak-app/`, N emulated phones on one
  device) with its Go load client `support/soak-client/` (`docs/PROJECT.md` §7), driving the adb-gated
  `TestE2E_SoakApp` gate and manual soak runs.

---

## Commit Scopes

All commits MUST use one of the scopes below. A commit spanning multiple scopes uses `tunneld`.

| Scope | Applies to |
|---|---|
| `tunneld` | Top-level binary (`cmd/tunneld`) / cross-cutting changes |
| `config` | `internal/config`: kong flag surface, `Validate()`, size/bitrate parsing |
| `logging` | `internal/logging`: slog fan-out, composite `--log` sinks |
| `ban` | `internal/ban`: parser, LPM engine, DB-IP expansion, watcher |
| `limit` | `internal/limit`: rate windows, enroll quota, global stream counter, per-second bandwidth+packet windows, ACME issuance budgets + wait-until |
| `ca` | `internal/ca`: CA loader, identity + mesh-role signing, name generation, fingerprint |
| `router` | `internal/router`: Valkey routing registry (route bind/heartbeat/unbind/lookup) + node registry |
| `store` | `internal/store`: durable S3/MinIO name registry, connection logs, rejected-enroll evidence |
| `attest` | `internal/attest`: Android key-attestation verifier (KeyDescription parse, roots/status refreshers, signer allowlist) |
| `acme` | `internal/acme`: LE→GTS→ZeroSSL issuance chain (lego clients, DNS-01 / HTTP-01 / TLS-ALPN-01, challenge store, per-account issuance budgets + wait-until/backoff, budgeted HTTP transport, several GTS accounts looked up by key) |
| `enroll` | `internal/enroll`: attested enrollment service + HTTP handler, single-use nonce |
| `wire` | `internal/wire`: control-frame codec + dial-back constants |
| `phoneconn` | `internal/phoneconn`: phone control plane (HTTP/2 + mTLS, bind, dial-back upgrade, renewal, eviction) |
| `edge` | `internal/edge`: raw :443 SNI edge (ClientHello peek + JA4), bridge, connection policy |
| `mesh` | `internal/mesh`: replica↔replica mTLS HTTP/2 control RPCs (per-pair pools) |
| `server` | `internal/server`: assembly (`Run`), SNI-edge + listener wiring, lifecycle |
| `metrics` | `internal/metrics`: registry, internal HTTP server, PromRecorder |
| `admin` | `internal/admin`: tunnels list + batch-stats composer (over router + limit) |
| `caplog` | `internal/caplog`: deduped cap-hit logger |
| `observ` | `internal/observ`: the Recorder interface |
| `tunneltest` | `internal/tunneltest`: shared test fakes (Recorder, Store) |
| `client` | `client/`: the Go tunnel client library |
| `e2e` | `e2e/`: testcontainers harness + scenarios |
| `staging` | `staging/`: real-CA staging tier (LE / GTS staging through the reverse SSH tunnel) |
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
- `make lint` — `golangci-lint` ×4 (default / `integration` / `e2e` / `staging` build tags — tagged files are
  invisible to an untagged run) + `shellcheck` + `compose-config`
- `make vet` — `go vet`
- `make govulncheck` — vulnerability scan (pinned via the `go.mod` `tool` directive, never `@latest`)
- `make test-unit` — unit tests (`-short -race -count=1`)
- `make test-integration` — `-tags=integration` suite (`-race`; real `server.Run` + testcontainers Valkey/MinIO/Pebble; needs Docker)
- `make test-e2e` — `-tags=e2e` suite (`-race`; two in-process replicas + testcontainers; adb-gated attestation test skips without a device; needs Docker)
- `make test-staging` — `-tags=staging` suite (`-race`; real `server.Run` against Let's Encrypt staging + GTS staging through a reverse SSH tunnel; skips without `TUNNELD_STAGING_SSH_KEY`; needs Docker)
- `make test-all` — `test-unit` + `test-integration` + `test-e2e` + `test-staging`
- `make test-scripts` — POSIX harness for the `deploy/scripts/` fetch/gen-ca scripts
- `make compose-config` — validates `deploy/docker-compose.yml` (placeholder env from
  `deploy/.env.example`)
- `make mermaid-check` — validate all Mermaid blocks in `README.md` + `docs/` via `mmdc`
- `make tidy` — `go mod tidy`
- `make tunnel-app` / `make soak-app` — run the app's JVM unit tests (`testDebugUnitTest`) and build its APK fixture (into `fixtures/tunnel-app/` / `fixtures/soak-app/`); `make soak-client` — the soak load client (`docs/PROJECT.md` §7)

There is NO dotenv convention for tests in this repo: unit tests are self-contained (miniredis,
httptest, temp CA files); the integration + e2e tiers provision everything via testcontainers and need a
working Docker daemon. The staging tier additionally reads seven `TUNNELD_STAGING_*` environment variables (GitHub secrets in CI) and skips when `TUNNELD_STAGING_SSH_KEY` is empty. CI
(`.github/workflows/ci.yml`) runs `static-checks` (lint ×4, govulncheck, tidy-drift, shellcheck,
script tests, compose config, mermaid-check), `build`, `test-unit`, `test-integration`, `test-e2e`, `test-staging`,
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
  Valkey/MinIO/Pebble; e2e (`//go:build e2e`) = two in-process replicas + shared testcontainers; staging (`//go:build staging`, `staging/`) = the real server against Let's Encrypt staging + GTS staging through a reverse SSH tunnel (every CI run; skips without the key). Shared
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
