<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 15 — Multi-node platform prerequisites

Generic platform changes needed before the multi-node deployment. Per the user's direction this plan is
intentionally HIGH-LEVEL (work to do + acceptance criteria, no code). Deployment specifics (hosts, IPs,
domains, keys, storage provider) are NOT part of the repo and NOT part of this plan. No release tag is
created by this plan.

## [x] US1 — Valkey Sentinel support

Why: the deployment runs a redundant Valkey behind Sentinel; tunneld today connects to one node only.

- [x] A `--redis-url` whose query carries `master_name=` makes tunneld use the go-redis Sentinel failover
      client (`ParseFailoverURL` + `NewFailoverClient`, go-redis v9.23.0): the URL host and repeated `addr=`
      are the sentinels, the URL `user:password@` authenticates to the SENTINELS, and the `username=` /
      `password=` query parameters authenticate to the MASTER.
- [x] Any other `--redis-url` behaves exactly as today (except that a malformed query is now rejected — see
      Deviations); an unparseable URL (plain or Sentinel) still fails fast at startup.

### [x] Task 1.1 — Valkey client selection

- [x] `internal/config`: one shared plain-vs-Sentinel `--redis-url` parser, used by BOTH
      `ServeCmd.Validate()` (today it calls `redis.ParseURL`, which rejects `master_name`) and `server.Run`
      (`internal/server` already imports `internal/config`); the `--redis-url` help text documents the
      Sentinel form and where each credential goes.
- [x] `internal/server/server.go`: build the single-node or Sentinel failover client through that parser.
- [x] Tests: unit — parser (plain URL, Sentinel URL, Sentinel URL with `password=`, malformed plain and
      Sentinel URLs) and `Validate()` accepting a Sentinel URL / rejecting a malformed one; integration —
      tunneld against a testcontainers Valkey master + Sentinel.
- [x] Docs: `docs/ARCHITECTURE.md` §10 (Configuration).

DoD: [x] a Sentinel URL passes `Validate()` and connects through the master Sentinel reports; a plain URL is
unchanged.

## [x] US2 — Connection logs batched as JSONL

Why: one S3 object per start/end event is one write per event; batching cuts writes and objects (decision
recorded with the user).

- [x] Each node buffers connection-log events per tunnel per UTC day and writes ONE JSONL object (one event
      per line) when 100 events are buffered or 5 minutes after the buffer's first event, and at shutdown.
- [x] Object key `tunnel-logs/<name>/<yyyy>/<mm>/<dd>/<first-event-ts-nanos>-<node-id>.jsonl` — still under
      `tunnel-logs/`, so the 90-day lifecycle rule is unchanged. A connection's start and end MAY land in
      different objects.
- [x] Unchanged behaviour: enqueue is O(1) and never blocks an admission/splice/teardown path; at most 5000
      buffered events per node; a full buffer drops the newest event (`tunneld_connlog_dropped_total` +1);
      a failed write is retried with the current schedule (5 attempts, 1/2/4/8 s backoff); when retries are
      exhausted the batch is dropped, `tunneld_connlog_dropped_total` grows by the number of events it
      carried, and a Warn is logged with the tunnel, day and node identifiers and the final write error; the
      shutdown flush is bounded.

### [x] Task 2.1 — Batching writer

- [x] `internal/store`: replace the per-event object writes of `AsyncConnLog` (and `event.go`'s per-event key)
      with the per-tunnel/day batcher.
- [x] `internal/server`: wire the node id into the batcher.
- [x] Tests: unit — batch key layout + chronological sort (replacing `TestLogKeyLayoutAndSort`), count
      trigger, time trigger (fake clock), per-tunnel and day-rollover split, shutdown flush, drop-on-full +
      metric, retry after a failed write, retries-exhausted batch drop (metric by event count + Warn with the
      error); integration — JSONL objects land in MinIO under the exact key; update the integration/e2e
      assertions that read per-event objects.
- [x] Docs: `docs/PROJECT.md` §5/§6, `docs/ARCHITECTURE.md` §6/§8 and §9 (shutdown text + its Mermaid chart),
      `.claude/rules/project.md` (Observability).

DoD: [x] connection logs land as JSONL batches with the key above; no event path blocks.

## [x] US3 — Reserved-host certs shared through Valkey

Why: today every node orders its own `--enroll-host` / `--control-host` certs (N nodes = N orders per host
per renewal); the existing `lock:acme-self:<host>` only serializes the orders.

- [x] Holding `lock:acme-self:<host>`, a node first reads the shared cert from Valkey
      (`acme:self-cert:<host>`: cert chain + key + metadata). If it is valid and not due for renewal it is
      used with NO ACME order.
- [x] Otherwise the node issues the cert and publishes it to Valkey with TTL = time until the cert's NotAfter
      (no permanent Valkey state) BEFORE releasing the lock, so the next lock holder finds it.
- [x] At startup and at each renewal check a node takes the shared cert only when its NotAfter is later than
      the cert it already holds (never a downgrade); the local disk cache stays the fallback when Valkey is
      unavailable.
- [x] Every cert a node takes — issued or read from Valkey — is also persisted to its local disk cache.

### [x] Task 3.1 — Shared cert store

- [x] `internal/server/reserved.go` (+ a small Valkey accessor next to the existing ACME challenge store):
      read-before-order, publish-before-unlock, take-if-newer, persist-on-take.
- [x] Tests: unit (miniredis) — shared hit under the lock orders nothing; miss orders + publishes with the TTL
      before unlocking; startup and renewal-check pick-up of a newer shared cert (and NO pick-up of an older
      one); a cert taken from Valkey (startup / renewal check) is persisted to the disk bundle; Valkey error
      falls back to the disk cache; e2e — two replicas obtain exactly ONE order per host.
- [x] Docs: `.claude/rules/project.md` (Valkey key list: `acme:self-cert:`), `docs/PROJECT.md` §5 (Valkey
      keys), `docs/ARCHITECTURE.md` §1 (startup cert load), §3 (reserved-host flow) and §5 — including that
      the reserved-host private key lives in Valkey (TTL'd), so Valkey must stay private.

DoD: [x] a multi-replica deployment issues each reserved-host cert once per renewal cycle.

## [x] US4 — Release config on goreleaser `dockers_v2`

Why: goreleaser reports that `dockers` + `docker_manifests` are being phased out and will eventually be
replaced by `dockers_v2`.

- [x] `.goreleaser.yaml` uses one `dockers_v2` entry (platforms `linux/amd64`, `linux/arm64`) for
      `ghcr.io/danielealbano/tunneld` with tags `{{ .Version }}` and `latest` and the same OCI labels;
      `dockers` and `docker_manifests` are removed.
- [x] `Dockerfile.goreleaser` copies the per-platform binary (`ARG TARGETPLATFORM` +
      `COPY $TARGETPLATFORM/tunneld`).
- [x] The per-arch `-amd64` / `-arm64` tags are no longer published (user decision); the multi-arch tags
      cover both platforms.

### [x] Task 4.1 — Migrate the release config

- [x] Update `.goreleaser.yaml` + `Dockerfile.goreleaser`; `release.yml` needs no change (it runs goreleaser
      `~> v2`, which supports `dockers_v2`).

DoD: [x] the release config uses `dockers_v2` only.

## [x] Task 5 — Ground-up verification

- [x] Re-read this plan and every change from the ground up; docs and `.claude/rules/project.md` match.
- [x] Quality gates: `make lint`, `make vet`, `make govulncheck`, `make build`, `make test-unit`,
      `make test-scripts`, `make mermaid-check`, `go mod tidy` drift, `make test-integration`,
      `make test-e2e`, `make test-staging`.
- [x] Validate every touched Mermaid chart (`make mermaid-check`, per development_pipeline.md §9).
- [x] `goreleaser check` reports no deprecation; a local `--snapshot` release builds both platform images.
- [x] All checkboxes ticked; deviations recorded below.

## Deviations

- Task 1.1: besides unparseable URLs, the shared parser rejects a Sentinel URL with an empty `master_name`,
  with `route_by_latency` / `route_randomly` (go-redis `NewFailoverClient` panics on them — they need the
  cluster client) and with `replica_only` (it routes every command to read-only replicas; tunneld writes).
  Why: these are startup-fatal or write-breaking misconfigurations, so they fail fast in `Validate()`.
- Task 1.1 (found in the Task 5 ground-up re-read): `net/url` parse errors embed the whole URL, so a
  malformed `--redis-url` printed its password in the startup error (go-redis's own parser did the same
  before). The shared parser now returns only the underlying parse cause; a unit test asserts no parse error
  carries the password. Why: secrets must never be logged. Code review then showed `net/url` and go-redis
  also echo password FRAGMENTS (an unescaped `/`, `?`, `#`, `&` or `%` splits them into other fields), so
  every parse error is now emitted with EVERY token that appears in the URL (raw, percent-decoded or
  Go-quoted, any length) replaced by `[redacted]` — locating the password inside a malformed URL is not
  reliable, so all URL-derived text is hidden; the redacted cause (the error's structure) is kept, never
  dropped, prefixed with `--redis-url:`.
- Task 1.1: a plain (non-Sentinel) `--redis-url` with a malformed query pair (e.g. a bad `%`-escape) is now
  REJECTED; go-redis's own parser silently dropped such pairs. Why: the shared parser must read the query
  strictly to detect `master_name`, and silently dropping a malformed setting is a discarded error — fail
  fast in `Validate()` instead.
