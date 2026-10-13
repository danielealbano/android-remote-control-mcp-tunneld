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

## [x] US2 — Connection logs spooled locally, uploaded as per-node JSONL objects

Why: the deployment targets thousands of connections; S3 writes must not scale with tunnels or connections,
and an S3 outage must not lose connection logs (decision recorded with the user — see Deviations).

- [x] New required flag `--conn-log-dir` (`TUNNELD_CONN_LOG_DIR`), a directory on a persistent volume.
      `Validate()` requires it (and, if it exists, that it is a directory); `server.Run` creates it (0o700) if
      missing and takes an exclusive `flock` on `<dir>/.lock` — a second process using the same directory
      fails fast; the lock is released on every `Run` return path. Spool files are 0o600.
- [x] Enqueue stays O(1) and never blocks an admission/splice/teardown path: events go to a bounded in-memory
      channel (5000 events); ONE writer goroutine appends each event as one JSON line straight to the active
      spool file (no user-space buffer). A full channel, a refused post-shutdown event, or a failed append
      drops the event (`tunneld_connlog_dropped_total` +1 each). A failed or short append is repaired before
      the next write: the file is truncated back to its pre-write offset, and if that fails too the file is
      rotated out and the next event opens a new file — a partial line never sits mid-file.
- [x] Files follow clock-aligned UTC 5-minute windows (…:00, …:05, …) and are opened only when their first
      event arrives (no empty files). The active file is named `<file-start>-<node-id>.jsonl.part`, where
      `<file-start>` is the UTC time the file was opened with NANOSECOND precision
      (`20060102T150405.000000000Z`) — a second file in the same window (16 MiB split, clock step)
      practically never gets the same name; start times strictly increase within a process, the file is opened
      `O_CREATE|O_EXCL`, and an existing name advances the start time by 1 ns until it is free, so neither a
      ready file nor an already-uploaded object is ever overwritten. It is fsynced and renamed to `.jsonl` (ready) when its window ends, when it reaches
      16 MiB, and at shutdown. The object key is derived from the file name ONLY —
      `tunnel-logs/<yyyy>/<mm>/<dd>/<file-start>-<node-id>.jsonl` (all tunnels mixed, every line carries
      `tunnel`; still under `tunnel-logs/`, so the 90-day lifecycle is unchanged; window alignment keeps every
      object inside one UTC day) — so a re-upload after a crash overwrites the same object.
- [x] A separate uploader goroutine (never blocking the writer) uploads ready files oldest-first and deletes
      each one locally ONLY after its upload succeeds. A pass stops at the first S3 failure (one Warn per pass
      with the file and the error) and is retried every minute; once uploads succeed the backlog drains
      continuously. A file that cannot be read locally is logged and skipped for that pass (it never blocks
      newer files). Local I/O errors (append, truncate, fsync, rename, delete, list) are logged at most once
      per minute; a failed fsync still rotates and uploads the file (best effort — the page-cache content is
      uploaded).
- [x] An S3 outage drops nothing while the spool is below its 1 GiB cap; at the cap, new events are dropped
      (`tunneld_connlog_dropped_total` +1 each) with at most one Warn per window. Only files matching the
      spool naming pattern are counted, recovered or uploaded (`.lock`, `lost+found` etc. are ignored).
- [x] Startup recovery (before the writer starts, never blocking the listeners): each leftover `.part` file
      is truncated to its last newline (a Warn reports any dropped bytes) and renamed to `.jsonl`; an empty
      one is removed. Leftover ready files simply head the uploader's oldest-first queue.
- [x] Shutdown (where the conn-log queue was drained before): intake stops, the writer rotates the active
      file, and the uploader runs until the spool is empty or `--shutdown-grace` expires — what remains stays
      on disk for the next start. The writer and uploader goroutines stop on EVERY `Run` return path, and the
      flush is bounded by the single shutdown deadline (no second full grace period).

### [x] Task 2.1 — Spool writer + uploader

- [x] `internal/config`: `--conn-log-dir` (required for serve; must be a directory if it exists).
- [x] `internal/store`: replace the in-memory per-tunnel batcher (`AsyncConnLog`, `ConnLogBatch`,
      `PutConnLogBatch`, `event.go`'s batch key) with the spool writer + uploader and an S3 upload of one spool
      file under its derived key; update `internal/tunneltest/store.go`'s fake to the new store surface.
- [x] `internal/server`: create + lock `--conn-log-dir`, wire the node id, keep the shutdown order (spool
      flushed where the conn-log queue was drained), make the early-return cleanup a no-op once the normal
      shutdown has flushed, and name the `tunneld_connlog_dropped_total` wiring so it is unit-testable.
- [x] `internal/metrics`: `tunneld_connlog_dropped_total` help text → events dropped (channel full, append
      failure, spool cap, post-shutdown).
- [x] `deploy/` + `README.md` + `.gitignore`: compose bind mount `./conn-logs:/conn-logs`,
      `TUNNELD_CONN_LOG_DIR=/conn-logs` in `tunneld.env.example`, the writable-mount comments
      (`docker-compose.yml`, `.env.example`), the quickstart `mkdir`, and `/deploy/conn-logs/` ignored (the
      spool holds source IPs and identity fingerprints).
- [x] Tests: unit (temp dir, fake clock, fake uploader) — append + clock-aligned window rotation, size
      rotation (a new nanosecond-named file), key derivation from the file name + chronological sort, no empty
      files, an existing name advancing by 1 ns (the size-rotation test advances its fake clock), fsync
      + rename on rotation, a failed fsync still rotating + uploading, a short append repaired (the next line
      intact) and an unrepairable one rotating to a new file, oldest-first upload then delete, a failed upload kept + retried with a Warn
      carrying file + error, a locally unreadable file skipped without blocking newer files, spool-cap drop +
      metric + one Warn per window, channel-full drop, post-shutdown event refused + counted (no panic),
      recovery of a torn `.part` (truncated + Warn) and an empty `.part` (removed), non-spool entries ignored,
      shutdown rotate + upload, a shutdown upload past the deadline leaving the file while `Drain` returns on
      time, the dropped-metric wiring, `--conn-log-dir` validation, directory created if missing, a held lock
      failing fast, and writer + uploader goroutines stopping on every `Run` return; integration — the JSONL
      object lands in MinIO under the exact key after drain, and a leftover spool file present at `server.Run`
      boot ends up in MinIO; update the integration/e2e assertions that read connection logs, and make every
      `ServeCmd` builder set `--conn-log-dir` to its own temp dir (the integration, e2e and staging harnesses,
      the unit `lifecycleConfig`, the `cmd/tunneld` dispatch test, the config `validCfg` base); a second `Run`
      on the same directory succeeds once the first has returned (lock released).
- [x] Docs: `docs/PROJECT.md` §5/§6/§7, `docs/ARCHITECTURE.md` §1/§6/§8/§9 (shutdown text + its Mermaid
      chart)/§10, `.claude/rules/project.md` (durable state + Observability).

DoD: [x] connection logs land as per-node 5-minute JSONL objects; no event path blocks; an S3 outage loses
nothing below the spool cap; a process crash loses at most the torn last line (a host crash can also lose
the un-fsynced tail since the last rotation).

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
  every `net/url` / go-redis parse error is now emitted with EVERY token that appears in the URL (raw,
  percent-decoded or Go-quoted, any length) AND every delimiter character that occurs in the URL replaced by
  `[redacted]` (adjacent replacements merged) — locating the password inside a malformed URL is not
  reliable, so all URL-derived text is hidden; the redacted cause (the error's structure) is kept, never
  dropped, prefixed with `--redis-url:`. tunneld's own Sentinel-option errors carry no URL text and are
  emitted verbatim.
- Task 1.1: a plain (non-Sentinel) `--redis-url` with a malformed query pair (e.g. a bad `%`-escape) is now
  REJECTED; go-redis's own parser silently dropped such pairs. Why: the shared parser must read the query
  strictly to detect `master_name`, and silently dropping a malformed setting is a discarded error — fail
  fast in `Validate()` instead.
- US2 REDESIGNED (user decision, 2026-10-13, after code review #3): the in-memory per-tunnel/day batcher
  counted not-yet-due batches against the 5000-event bound, so a node with many quiet tunnels dropped events
  even with healthy S3; the deployment targets thousands of connections. The user chose a local spool
  (`--conn-log-dir`) uploaded as per-node, 5-minute JSONL objects (all tunnels mixed) over per-tunnel objects.
  The batcher already committed on this branch is replaced. Confirmed by the user (2026-10-13): the key uses
  the file's NANOSECOND start time instead of the window start (`<file-start>-<node-id>`, no sequence
  suffix — a second file in one window, from a 16 MiB split or a clock step, practically never collides, and
  an exclusive create advancing 1 ns on an existing name guarantees a ready file is never overwritten);
  windows are clock-aligned UTC 5-minute windows; an exclusive `flock` on `<dir>/.lock` makes a second
  process on the same `--conn-log-dir` fail fast; values — 16 MiB size rotation, 1 GiB spool cap, 1-minute
  upload retry, 5000-event channel. Code review #3's CR-002 (double shutdown grace) and
  CR-005 (untested dropped-metric wiring) are resolved inside the rewritten Task 2.1.
- Task 2.1 (deploy): the writable-mount comments in `docker-compose.yml` / `.env.example` were NOT extended
  to mention `./conn-logs` — the user's standing rule forbids adding comments to code/config; the new bind
  mount and `TUNNELD_CONN_LOG_DIR` lines carry no comment, the README quickstart `mkdir` and `.gitignore`
  carry the change. Why: the comment rule overrides the plan item.
- Task 2.1 (server): `--conn-log-dir` is created (0o700) and `flock`ed inside `store.NewConnLogSpool`, which
  `server.Run` calls during construction — the store owns the spool directory; `Run` still triggers it and
  releases it on every return path via the idempotent `Drain`.
- Task 2.1 (store): file start times also STRICTLY increase within a process (each new file starts at least
  1 ns after the previous one). Why: the size-rotation unit test showed that with a clock that does not
  advance, a file already uploaded and deleted freed its name, so the next file reused it and overwrote the
  object; the local existence check alone cannot see uploaded files.
- Code review #4 fixes (2026-10-13): (a) Task 2.1 — each conn-log upload gets a deadline of 30 s + its size at
  128 KiB/s and runs on an S3 HTTP client without the general 30 s cap, so a 16 MiB file is not doomed on
  links below ~4.5 Mbit/s and cannot block newer files forever; (b) Task 2.1 — `Drain` always waits for the
  writer; events still queued at the deadline are dropped, counted and logged, so the lock is never released
  under a running writer; (c) Task 2.1 — a suppressed local-I/O count (with the last op/path/error) is
  reported once the minute has passed and at `Drain`; (d) Task 3.1 — every shared-cert Valkey read is bounded
  (5 s), so an unreachable Valkey cannot hold the startup bind for minutes. Why: each closes a failure mode
  the review found (no silent loss, bounded startup/shutdown, convergence).
- Code review #5 fixes (2026-10-13): (a) Task 1.1 — the redaction also hides delimiter characters that
  occur in the URL (merged runs), since password punctuation such as `:[]()` was echoed between redacted
  tokens; tunneld's own Sentinel-option errors are no longer passed through the redactor (they were
  mangled); (b) Task 2.1 — `PutConnLogFile`'s uncapped upload client and request shape are unit-tested, the
  stale "teardown paths write conn logs" part of the S3 client comment is removed, the drop causes in the
  docs and the metric help include events still queued at the shutdown deadline, the timing-dependent
  spool/server tests now wait for the state they assert and check deadlines structurally, and the normal
  `Run` return is checked for stopped spool goroutines and a released lock; (c) Task 3.1 — the docs state
  that an unreachable Valkey delays the startup bind by at most 5 s per reserved host. Why: each closes a
  review finding (no credential fragment in logs, actionable errors, accurate docs, deterministic tests).
