<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 11 — Lua-free Valkey state model + merged tunnel key + admin surface

Remove ALL Lua (13 scripts) and confirm ZERO WATCH/MULTI/EXEC from the Valkey layer, replacing each with a
single command, a self-healing pipeline, or a `SETNX` lock — per the **Engineering posture** now in
`project.md` ("simplest correct design"). Merge the per-tunnel byte counters into the routing key as
`tunnel:{name}`, fixing the write-after-disconnect phantom. Enrich the node registry and replace the
top-N tunnels endpoint with a frontend-driven paginated list + batch stats.

Design authority: the conversation that produced this plan, and the updated `project.md` invariants
(Engineering posture; "NO permanent Valkey state"; "Route ownership is deterministic and clobber-free").
No wire/`PROTOCOL.md` change — every change is server-side Valkey state; the v1 control frames are untouched.

## Cross-cutting rules for EVERY story
- **Posture-compliant:** NO `redis.NewScript`, NO `.Eval*`, NO `TxPipeline`/`Watch`/MULTI. Only single
  commands, plain `Pipeline()`, or `SET … NX … EX` locks. A reviewer MUST fail any residual Lua/tx.
- **Every key TTL'd in the same round-trip** as its mutation (`SET EX`, `SETNX EX`, or pipelined
  `EXPIRE NX`/`PEXPIRE`). No un-TTL'd key may be created.
- **Fail-open** on the data-plane limiter (a Valkey error → Proceed); **fail-safe** on caps (over-count
  denies, never breaches).
- Tests move with the code: every removed script's `*_test.go` behavior MUST be preserved against the new
  implementation (same observable outcomes), NOT deleted.
- **Unused-import hygiene:** every file that loses its last `redis.NewScript` MUST drop the now-unused
  `github.com/redis/go-redis/v9` import IF it no longer references the `redis` package identifier — KEEP
  the import where `redis.Nil` / `redis.UniversalClient` / `redis.SliceCmd` etc. still appear
  (`registry.go`, `window.go`, `issuance.go`, and `concurrency.go` — it now uses `redis.Nil` — keep it;
  `route_e2e.go`, `acme_cooldown.go`, `enroll/nonce.go`, `router/lock.go`, and the new `limit/lock.go` do
  NOT import `redis`). `make lint`/`go build` MUST be clean.

---

## US1 — Rebuild the route registry without Lua (per-name lock + connID) — [ ]

**Why:** the four route-guard Lua scripts (`bindRouteScript`, `selfHealRouteScript`, `heartbeatScript`,
`unbindScript`) exist only to make route ownership atomic. Replace them with a per-name `SETNX` lock around
create/delete + a connID check + a TTL-only heartbeat, keeping the SACRED "a stale connection MUST NEVER
clobber a re-bound route" guarantee deterministically. Rename the key `route:{name}` → `tunnel:{name}`
(project.md target); fields stay `{node, fingerprint, connID}` (byte counters arrive in US2).

**Acceptance criteria:**
- [ ] `internal/router` contains ZERO `redis.NewScript`.
- [ ] The routing key is `tunnel:{name}`; the lock key is `lock:{name}` (`SET … NX PX`), always TTL'd.
- [ ] Bind is last-writer-wins under the lock; heartbeat is `PEXPIRE`-only (never rewrites the value);
      unbind deletes only if the stored `connID` matches, under the lock; self-heal re-binds under the lock.
- [ ] A stale-connection unbind/heartbeat cannot delete or resurrect a newer owner's route (existing
      router + phoneconn tests still pass with the new implementation).
- [ ] `LookupRoute`, `phoneconn.Manager`, `internal/edge`, and `server.go` compile and behave unchanged
      against the renamed key.

### Task 1.1 — Add the per-name lock primitive to `internal/router` — [ ]
- [ ] **Create** `internal/router/lock.go` — a minimal cross-node lock used by bind/unbind/self-heal.
```go
package router

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

// lockTTL bounds a create/delete critical section (a single SET or HGET+DEL — microseconds). It is far
// larger than the section, so the lock cannot expire mid-section; on a process crash it self-clears.
const lockTTL = 5 * time.Second

func lockKey(name string) string { return "lock:" + name }

// mintToken returns a random lock-holder token (best-effort release checks it).
func mintToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// acquire takes the per-name lock (SET NX PX). ok=false means another create/delete holds it — the caller
// retries briefly. The token is returned for release.
func (r *Registry) acquire(ctx context.Context, name string) (token string, ok bool, err error) {
	token = mintToken()
	set, err := r.rdb.SetNX(ctx, lockKey(name), token, lockTTL).Result()
	if err != nil {
		return "", false, err
	}
	return token, set, nil
}

// release drops the lock only if we still hold it. Best-effort: a GET+DEL race is negligible because the
// section is microseconds and the TTL is seconds, and the lock self-expires regardless (posture: no Lua).
func (r *Registry) release(ctx context.Context, name, token string) {
	if v, err := r.rdb.Get(ctx, lockKey(name)).Result(); err == nil && v == token {
		_ = r.rdb.Del(ctx, lockKey(name)).Err()
	}
}

// withLock runs fn while holding the per-name lock, retrying acquisition on contention up to a short
// bound (the section is microseconds; contention is rare). A Valkey error acquiring is returned to the
// caller (bind/unbind decide fail direction).
func (r *Registry) withLock(ctx context.Context, name string, fn func() error) error {
	const attempts = 50
	for i := 0; i < attempts; i++ {
		token, ok, err := r.acquire(ctx, name)
		if err != nil {
			return err
		}
		if ok {
			defer r.release(ctx, name, token)
			return fn()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ErrLockContended
}
```
- [ ] **Modify** `internal/router/registry.go` — add `var ErrLockContended = errors.New("router: route lock contended")` alongside the existing sentinels; the key builder becomes `func key(name string) string { return "tunnel:" + name }`.

**DoD:** lock helpers compile; `lockTTL` and `lockKey` documented; no Lua introduced.

### Task 1.2 — Rewrite bind/heartbeat/unbind/self-heal without Lua — [ ]
- [ ] **Modify** `internal/router/registry.go` — replace `heartbeatScript`/`unbindScript` and `Heartbeat`/`Unbind`:
```go
// Heartbeat refreshes tunnel:{name}'s TTL ONLY (PEXPIRE — never rewrites the value), and ONLY while this
// connID still owns the route: it reads connID first, and issues the PEXPIRE only on an ownership match, so a
// stale/superseded connection can NEVER extend the current owner's route lifetime (owner-conditional TTL,
// preserving the old script's semantics). Three-state result: absent key → Missing (caller self-heals); a
// different connID → NotOwner (no refresh); our connID → PEXPIRE → Refreshed (or Missing if it vanished
// between the read and the refresh). No lock needed — a spurious PEXPIRE can at worst extend the CORRECT
// (already re-bound) owner's TTL, which is harmless (it never changes the value/owner).
func (r *Registry) Heartbeat(ctx context.Context, name, connID string) (HeartbeatResult, error) {
	owner, err := r.rdb.HGet(ctx, key(name), "connID").Result()
	if errors.Is(err, redis.Nil) {
		return HeartbeatMissing, nil // key gone (or a byte-only orphan with no connID) → self-heal
	}
	if err != nil {
		return HeartbeatMissing, err
	}
	if owner != connID {
		return HeartbeatNotOwner, nil // superseded — do NOT refresh the new owner's TTL
	}
	ok, err := r.rdb.PExpire(ctx, key(name), r.ttl).Result()
	if err != nil {
		return HeartbeatMissing, err
	}
	if !ok {
		return HeartbeatMissing, nil // key expired between the read and the refresh → self-heal
	}
	return HeartbeatRefreshed, nil
}

// Unbind deletes tunnel:{name} ONLY while it still belongs to connID, serialized by the per-name lock so
// no concurrent bind can interleave between the connID read and the DEL (deterministic — replaces the CAS
// Lua). A stale connection reads a different connID and declines to delete.
func (r *Registry) Unbind(ctx context.Context, name, connID string) error {
	return r.withLock(ctx, name, func() error {
		owner, err := r.rdb.HGet(ctx, key(name), "connID").Result()
		if errors.Is(err, redis.Nil) {
			return nil // already gone
		}
		if err != nil {
			return err
		}
		if owner != connID {
			return nil // superseded by a newer bind — never clobber it
		}
		return r.rdb.Del(ctx, key(name)).Err()
	})
}
```
- [ ] **Modify** `internal/router/route_e2e.go` — replace `bindRouteScript`/`selfHealRouteScript` and `BindRoute`/`BindRouteIfAbsentOrOwner`:
```go
// BindRoute claims tunnel:{name} for (node, fingerprint, connID), serialized by the per-name lock. Rules
// (preserved from the old script): a DIFFERENT stored fingerprint → ErrNameHeldByOther; a stored connID
// equal to ours → ErrConnIDCollision (re-roll signal). Otherwise last-writer-wins: HSET the fields + set
// the TTL. Heartbeat/Unbind stay connID-conditional.
func (r *Registry) BindRoute(ctx context.Context, name, nodeID, fingerprint, connID string) error {
	return r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "fingerprint", "connID").Result()
		if err != nil {
			return err
		}
		if fp, _ := vals[0].(string); fp != "" && fp != fingerprint {
			return ErrNameHeldByOther
		}
		if cid, _ := vals[1].(string); cid == connID {
			return ErrConnIDCollision
		}
		pipe := r.rdb.Pipeline()
		pipe.HSet(ctx, key(name), "node", nodeID, "fingerprint", fingerprint, "connID", connID)
		pipe.PExpire(ctx, key(name), r.ttl)
		_, err = pipe.Exec(ctx)
		return err
	})
}

// BindRouteIfAbsentOrOwner is the self-heal variant: bind only if the key is absent or still owned by this
// connID (same fingerprint), under the lock. A different connID (same fingerprint) → NotOwner; a different
// fingerprint → Conflict.
func (r *Registry) BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, fingerprint, connID string) (SelfHealResult, error) {
	var res SelfHealResult
	err := r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "node", "fingerprint", "connID").Result()
		if err != nil {
			return err
		}
		node, _ := vals[0].(string)
		fp, _ := vals[1].(string)
		cid, _ := vals[2].(string)
		if node == "" { // absent → bind
			res = SelfHealBound
			return bindHSet(ctx, r, name, nodeID, fingerprint, connID)
		}
		if fp != fingerprint {
			res = SelfHealConflict
			return ErrNameHeldByOther
		}
		if cid != connID {
			res = SelfHealNotOwner
			return nil
		}
		res = SelfHealBound
		return bindHSet(ctx, r, name, nodeID, fingerprint, connID)
	})
	return res, err
}

// bindHSet writes the three routing fields + TTL in one pipeline (shared by bind + self-heal).
func bindHSet(ctx context.Context, r *Registry, name, nodeID, fingerprint, connID string) error {
	pipe := r.rdb.Pipeline()
	pipe.HSet(ctx, key(name), "node", nodeID, "fingerprint", fingerprint, "connID", connID)
	pipe.PExpire(ctx, key(name), r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}
```
- [ ] Delete the four `redis.NewScript` vars and their now-unused imports.

**DoD:** `internal/router` has ZERO `NewScript`; `Heartbeat`/`Unbind`/`BindRoute`/`BindRouteIfAbsentOrOwner` keep their signatures and three-state result enums; `SelfHealConflict` still returns `ErrNameHeldByOther`.

### Task 1.3 — Preserve behavior in callers and tests — [ ]
- [ ] **Verify** `internal/phoneconn/manager.go` `register`/`heartbeatLoop`/teardown are unchanged (the `Router` interface signatures are stable) — reconcile only if a signature shifted.
- [ ] **Verify** `internal/edge/bridge.go` (LookupRoute×2) and `internal/server/server.go:333` (admin renew LookupRoute) compile against the renamed key (LookupRoute signature is unchanged).
- [ ] **Modify** `internal/router/route_e2e.go` `LookupRoute` — no logic change; it still `HMGet`s `node,fingerprint,connID` from `key(name)` (now `tunnel:{name}`).
- [ ] **Modify** `internal/router/registry_test.go` — update every hardcoded key literal `route:abc` → `tunnel:abc` (lines ~75/116/128) and reconcile the existing tests (`TestHeartbeatRefreshesTTL`, `TestUnbindIsConnConditional`, etc.) with the new lock-serialized/`PEXPIRE`-only behavior so they still assert the same observable outcomes.
- [ ] **Modify** stale comments naming the old key: `internal/router/registry.go` package doc (`route:{name} stores …`) and the `HeartbeatMissing` const comment (`no route:{name}`) → `tunnel:{name}`; `internal/phoneconn/manager.go:234` and `internal/phoneconn/manager_test.go:41` (`route:{name} TTL-expire`) → `tunnel:{name}`.

**Tests (US1):**

| Test | Verifies |
|---|---|
| `TestRegistry_BindHeartbeatUnbind_OwnerLifecycle` | bind → heartbeat Refreshed → unbind removes the key |
| `TestRegistry_StaleUnbind_DoesNotClobberRebind` | conn-1 binds, conn-2 rebinds (last-writer-wins), conn-1 Unbind is a no-op; route still resolves to conn-2 |
| `TestRegistry_Heartbeat_NotOwnerAndMissing` | superseded connID → NotOwner AND the owner's TTL is NOT refreshed (owner-conditional PEXPIRE — preserves `TestHeartbeatIsConnConditional`); absent key → Missing |
| `TestRegistry_BindRoute_FingerprintConflictAndConnIDReroll` | different fingerprint → ErrNameHeldByOther; same connID → ErrConnIDCollision |
| `TestRegistry_SelfHeal_AbsentOwnerConflict` | absent→Bound, same-fp-other-conn→NotOwner, other-fp→Conflict |
| `TestRegistry_Lock_ContentionSerializes` (miniredis) | two concurrent binds for one name serialize; final state is a single coherent owner |
| `TestRegistry_NoLuaScripts` | `grep`-style guard: source of `internal/router` contains no `NewScript` (compile-time/asserted in a small test or left to `make lint` — see US6) |

---

## US2 — Merge the byte counters into the route key as `tunnel:{name}` — [ ]

**Why:** one entity per tunnel; kill the write-after-disconnect phantom (an `HINCRBY` on a gone key used to
resurrect it with a fresh 1h TTL). Counters live-and-die with the route; a post-disconnect flush is a safe
no-op or a bounded, non-routable, self-expiring orphan (option A).

**Acceptance criteria:**
- [ ] `tunnel:{name}` hash carries `bytes_in`/`bytes_out` alongside `node/fingerprint/connID`.
- [ ] A fresh bind (new connID) resets the byte fields to 0 (live-scoped), NEVER touching `traf:` quotas.
- [ ] The recorder flush is existence-guarded: `HINCRBY tunnel:{name}` + `EXPIRE NX` (short TTL) — it never
      creates a routable key (LookupRoute keys on `node`) and never leaves an un-TTL'd key.
- [ ] The `tcnt:` WRITER (`admin.incrScript` + `admin.Store.Incr`) is gone; the recorder writes only via
      `router.AddTraffic`. (The `tcnt:` READ surface `admin.Store.TopN` is retained until US5 — see US5 — so `tcnt:` is not fully removed until then.)

### Task 2.1 — Reset the byte fields ONLY on a fresh (new-connID) bind — [ ]
- [ ] **Modify** `internal/router/route_e2e.go` `bindHSet` — take a `resetBytes` flag so ONLY a fresh owner zeroes the live byte counters; a same-connID self-heal preserves the ongoing session's counters:
```go
// bindHSet writes the three routing fields + TTL (shared by bind + self-heal). resetBytes zeroes the
// live-scoped byte counters on a FRESH owner (new connID) so a reconnect within the TTL window never sums
// onto the old session; a same-connID self-heal passes resetBytes=false to keep the ongoing counters.
// The identity-scoped traf: day/week quotas are separate keys and are NEVER touched here.
func bindHSet(ctx context.Context, r *Registry, name, nodeID, fingerprint, connID string, resetBytes bool) error {
	fields := []any{"node", nodeID, "fingerprint", fingerprint, "connID", connID}
	if resetBytes {
		fields = append(fields, "bytes_in", 0, "bytes_out", 0)
	}
	pipe := r.rdb.Pipeline()
	pipe.HSet(ctx, key(name), fields...)
	pipe.PExpire(ctx, key(name), r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}
```
- [ ] `BindRoute` (Task 1.2) is always a fresh owner → call `bindHSet(..., true)` (replaces its inline `HSet`).
- [ ] `BindRouteIfAbsentOrOwner` (Task 1.2): the **absent** branch is a fresh owner → `bindHSet(..., true)`; the **same-connID** branch is the ongoing session self-healing → `bindHSet(..., false)` (no byte reset).

**DoD:** exactly the fresh-owner paths (new connID / absent) zero the byte fields; the same-connID self-heal does NOT; no path touches `traf:`/`conc:`.

### Task 2.2 — Existence-guarded byte flush in `internal/router` — [ ]
- [ ] **Create** `internal/router/traffic.go` — the write the recorder calls:
```go
package router

import (
	"context"
	"time"
)

// orphanTTL bounds a byte-only key that a post-disconnect flush may create on a gone route: it is
// non-routable (LookupRoute keys on `node`) and self-expires. Live routes keep their own r.ttl.
const orphanTTL = 30 * time.Second

// AddTraffic adds bytes to tunnel:{name} WITHOUT resurrecting a dead route: HINCRBY on a live key updates
// it (EXPIRE NX no-ops, the route's own TTL stands); HINCRBY on a gone key creates a byte-only, non-routable
// key that EXPIRE NX gives a short TTL so it self-expires. Off the data plane (recorder flusher only).
func (r *Registry) AddTraffic(ctx context.Context, name string, bytesIn, bytesOut int64) error {
	pipe := r.rdb.Pipeline()
	if bytesIn != 0 {
		pipe.HIncrBy(ctx, key(name), "bytes_in", bytesIn)
	}
	if bytesOut != 0 {
		pipe.HIncrBy(ctx, key(name), "bytes_out", bytesOut)
	}
	pipe.ExpireNX(ctx, key(name), orphanTTL) // no-op on a live route (already has a TTL); caps an orphan
	_, err := pipe.Exec(ctx)
	return err
}
```

**DoD:** `AddTraffic` never issues `HSET`/`SET` of `node`; the only TTL it sets is `EXPIRE NX` (never overriding a live route's TTL).

### Task 2.3 — Point the recorder flush at `router.AddTraffic`; remove `incrScript`/`Incr` — [ ]
- [ ] **Modify** `internal/metrics/recorder.go` — replace the `*admin.Store` dependency with a small consumer interface implemented by `*router.Registry`:
```go
// TrafficSink is the existence-guarded per-tunnel byte counter (router.Registry.AddTraffic). Defined at the
// consumer site; a nil sink is a no-op (metrics-only test wiring).
type TrafficSink interface {
	AddTraffic(ctx context.Context, name string, bytesIn, bytesOut int64) error
}
```
  - `PromRecorder.admin *admin.Store` → `traffic TrafficSink`; `NewPromRecorder(m, cl, sink, log)`.
  - `flush` calls `p.traffic.AddTraffic(ctx, name, e.bytesIn, e.bytesOut)` ONCE per tunnel (both deltas in one call); on error, re-accumulate BOTH deltas and retry next flush (keep the existing re-queue semantics).
  - Drop the now-unused `internal/admin` import from `recorder.go`.
  - Update the now-stale doc comments on `RunFlusher` ("drains … into the **admin.Store**") and `flush` ("A failed **Incr** re-accumulates … transient **admin.Store** error") to name `router.AddTraffic` / `TrafficSink`.
- [ ] **Modify** `internal/server/server.go:105` — pass `reg` (the `*router.Registry`) as the recorder's `TrafficSink`: `rec := metrics.NewPromRecorder(m, capLogger, reg, logger)`. **KEEP** `adminStore := admin.NewStore(rdb, time.Hour)` (:103) and its pass into `metrics.Handler` (:212) UNCHANGED — the `admin.Store`/`TopN` read surface is still consumed by `metrics.Handler` until US5 replaces it (deleting it here would break the build). This is the ONLY sequential-ordering-safe split.
- [ ] **Modify** `internal/admin/tunnels.go` — delete ONLY `incrScript` and `Incr` (their sole caller, the recorder, no longer calls them). `Store`, `NewStore`, `TopN`, `TunnelStat` REMAIN until US5 rewrites the admin read surface. KEEP the `redis` import — `Store.rdb` is a `redis.UniversalClient`, so it is still referenced.
- [ ] **Modify** `internal/metrics/metrics_test.go` — reconcile with the recorder dependency swap: construct `NewPromRecorder` with a `TrafficSink` (a small fake recording `(name, in, out)`, or `*router.Registry` against miniredis) instead of `*admin.Store`. Reconcile EVERY test coupled to the deleted `admin.Store.Incr` / `TopN`-via-flush path: `TestPromRecorderFlushesTcnt` (asserts `store.TopN` after `rec.flush` — the flush now writes `tunnel:{name}` via `AddTraffic`) → replace with the new `TestPromRecorder_FlushCallsAddTraffic`; `TestRunFlusherCadenceAndFinalFlush` → assert the sink received the aggregated deltas; `TestAdminTunnelsHandler` (seeds via `store.Incr`) → seed the underlying key with raw `rdb.HSet` (no `Incr`). The `Handler(...)` test calls stay on the CURRENT `Handler` signature at US2 (updated in US4/US5).
- [ ] **Modify** `internal/admin/tunnels_test.go` — remove the `Incr`/`tcnt:`-assertion tests (their production writer is deleted). The retained `TopN` tests (`TestAdminTopNSortsByBytes`, `TestAdminTopN_DedupAndEmptySkip`) seed exclusively via `s.Incr`, which is gone — reseed them with raw `rdb.HSet("tcnt:"+name, "bytes_in", …, "bytes_out", …)` so they compile + pass until US5 rewrites the file.
- [ ] **Modify** `internal/observ/recorder.go` — update the `Recorder`/`Bytes` doc comments that name `tcnt:{name}` to the merged `tunnel:{name}` byte counters.

**DoD:** `internal/admin` no longer holds a `NewScript`; the recorder writes only via `AddTraffic`; `internal/metrics` + `internal/admin` unit tests COMPILE and pass at US2; the tree COMPILES at US2 (admin.Store/TopN still referenced by metrics.Handler until US5).

### Task 2.4 — Docs — [ ]
- [ ] **Modify** `docs/ARCHITECTURE.md` — in the state section replace `route:{name}` + `tcnt:{name}` with the merged `tunnel:{name}` (fields + reset-on-bind + existence-guarded flush; byte counters are live-scoped). In the §5 state heading, replace the "single Lua, or a pipelined EXPIRE NX" TTL wording with the requirement-level model: every key gets a TTL in the SAME round-trip via `SET EX` / a `SETNX` lock / a pipelined `EXPIRE NX` — **NO Lua / WATCH / MULTI-EXEC**.
- [ ] **Modify** `docs/PROJECT.md` §5 (State + retention) — replace "set atomically in the same Lua script (or SET EX), or via a pipelined EXPIRE NX" with the same requirement-level model; rename any `route:{name}` / `tcnt:{name}` reference to `tunnel:{name}`.

**Tests (US2):**

| Test | Verifies |
|---|---|
| `TestRegistry_BindResetsByteFields` | rebind zeroes `bytes_in/out`; a stale-session delta does not carry over |
| `TestRegistry_AddTraffic_LiveKeyIncrements` | on a bound route, `AddTraffic` bumps fields, route TTL unchanged (EXPIRE NX no-op) |
| `TestRegistry_AddTraffic_GoneKey_NonRoutableSelfExpiring` | after unbind, `AddTraffic` creates a key with no `node` (LookupRoute ok=false) and a TTL (`PTTL>0`) |
| `TestPromRecorder_FlushCallsAddTraffic` | flusher aggregates deltas and calls `AddTraffic` once per tunnel; re-queues on error |

---

## US3 — Replace the limiter & enroll Lua with plain commands + a serializing issuance lock — [ ]

**Why:** remove the remaining 8 Lua scripts (7 in `internal/limit` + 1 in `internal/enroll`). Concurrency →
a per-name `SETNX` lock over a `conc:{name}` `{connID, count}` hash (every acquire/release checks ownership,
so a straggler release from a superseded connection is a no-op and a fresh connection resets structurally —
this retires `ResetStreams`/reset-on-bind). Issuance → a `SETNX` serializing lock + success-only counter
(deletes the inflight hash + its heartbeat). Window / ACME-cooldown → `INCR`+`EXPIRE NX`/`PEXPIRE` pipelines.
Enroll nonce → plain `DEL`.

**Acceptance criteria:**
- [ ] `internal/limit` and `internal/enroll` contain ZERO `redis.NewScript`.
- [ ] Concurrency cap never breaches: `conc:{name}` is a lock-guarded `{connID, count}` hash; every
      acquire/release verifies ownership, so a straggler release from a superseded connection is a no-op and
      a fresh connection resets the counter at its first acquire (no separate reset-on-bind). `DEL`-at-zero is
      race-free under the lock. A crash mid-op self-clears via the lock TTL + the `conc:` key TTL.
- [ ] `ResetStreams` and the `phoneconn.StreamResetter` interface + its wiring are removed (reset is now
      structural via the stored connID); `Charge`'s `conc:` TTL refresh on the data plane is unchanged.
- [ ] At most one in-flight issuance per tunnel (serialized by `iss_lock:{name}`); the success counter
      `iss:{name}` increments ONLY on a successful issuance; a crashed order releases the lock within its TTL.
- [ ] `iss_inflight:{name}`, `issuanceBeginScript`, `issuanceHeartbeatScript`, `recordIssuanceScript`,
      `allowScript`, `bumpFailuresScript`, `consumeNonceScript` are gone.

### Task 3.1 — Concurrency: lock-guarded `{connID, count}` hash (ownership-checked) — [ ]
- [ ] **Create** `internal/limit/lock.go` — the per-name concurrency lock + the shared `mintToken` (also used by the issuance lock, Task 3.2):
```go
package limit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

const concLockTTL = 5 * time.Second

// ErrConcLockContended is returned when the per-name concurrency lock cannot be taken within the retry bound.
var ErrConcLockContended = errors.New("limit: concurrency lock contended")

func concKey(name string) string     { return "conc:" + name }
func concLockKey(name string) string { return "conclock:" + name }

// mintToken returns a random lock-holder token (best-effort release checks it). Shared by the concurrency
// lock here and the issuance lock (Task 3.2).
func mintToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// withConcLock runs fn while holding conclock:{name} (SET NX EX), retrying briefly on contention (the
// section is a couple of hash ops — microseconds). Released only if still held (best-effort token check);
// self-clears via the TTL on a crash. NO Lua.
func (l *Limiter) withConcLock(ctx context.Context, name string, fn func() error) error {
	token := mintToken()
	const attempts = 50
	for i := 0; i < attempts; i++ {
		ok, err := l.rdb.SetNX(ctx, concLockKey(name), token, concLockTTL).Result()
		if err != nil {
			return err
		}
		if ok {
			defer func() {
				if v, gerr := l.rdb.Get(ctx, concLockKey(name)).Result(); gerr == nil && v == token {
					_ = l.rdb.Del(ctx, concLockKey(name)).Err()
				}
			}()
			return fn()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ErrConcLockContended
}
```
- [ ] **Modify** `internal/limit/concurrency.go` — remove both scripts; rewrite acquire/release as ownership-checked ops on the `conc:{name}` hash `{connID, count}` under the lock (keeps the `redis` import for `redis.Nil`):
```go
// AcquireStream reserves one of maxN concurrent-stream slots for (name, connID). conc:{name} is a hash
// {connID, count} guarded by the per-name lock so every op verifies ownership. A fresh owner (stored connID
// differs, or the key is absent) RESETS the counter — a new phone connection's prior streams are dead, so
// this acquire is the only live stream (this replaces the old reset-on-bind). The owner path HINCRBYs and,
// if over cap, rolls back and denies (fail-safe — never breaches). Global across replicas (every edge reads
// the same connID from the route). Every write sets the TTL in the same lock section.
func (l *Limiter) AcquireStream(ctx context.Context, name, connID string, maxN int) (bool, error) {
	var admit bool
	err := l.withConcLock(ctx, name, func() error {
		owner, herr := l.rdb.HGet(ctx, concKey(name), "connID").Result()
		if herr != nil && !errors.Is(herr, redis.Nil) {
			return herr
		}
		var c int64
		if errors.Is(herr, redis.Nil) || owner != connID {
			if e := l.rdb.HSet(ctx, concKey(name), "connID", connID, "count", 1).Err(); e != nil {
				return e
			}
			c = 1
		} else if c, herr = l.rdb.HIncrBy(ctx, concKey(name), "count", 1).Result(); herr != nil {
			return herr
		}
		if c > int64(maxN) { // over cap → roll back this slot (DEL a fresh reset, else DECR)
			if c == 1 {
				_ = l.rdb.Del(ctx, concKey(name)).Err()
			} else {
				_ = l.rdb.HIncrBy(ctx, concKey(name), "count", -1).Err()
			}
			admit = false
			return nil
		}
		admit = true
		return l.rdb.PExpire(ctx, concKey(name), l.streamTTL).Err()
	})
	if err != nil {
		return false, err
	}
	return admit, nil
}

// ReleaseStream frees a slot for (name, connID): under the lock it decrements ONLY if this connID still owns
// the counter — a straggler release from a superseded connection is a NO-OP (it can never corrupt the new
// owner's count). At zero the key is DELeted (safe under the lock — no acquire can interleave). NO Lua.
func (l *Limiter) ReleaseStream(ctx context.Context, name, connID string) error {
	return l.withConcLock(ctx, name, func() error {
		owner, err := l.rdb.HGet(ctx, concKey(name), "connID").Result()
		if errors.Is(err, redis.Nil) {
			return nil // already gone
		}
		if err != nil {
			return err
		}
		if owner != connID {
			return nil // superseded — not ours to decrement
		}
		c, err := l.rdb.HIncrBy(ctx, concKey(name), "count", -1).Result()
		if err != nil {
			return err
		}
		if c <= 0 {
			return l.rdb.Del(ctx, concKey(name)).Err()
		}
		return l.rdb.PExpire(ctx, concKey(name), l.streamTTL).Err()
	})
}
```
- [ ] **Remove** `ResetStreams` from `internal/limit/limiter.go` (reset is now structural — a fresh connID resets at its first acquire). Its only caller is the test `TestResetStreams_DeletesConcOnly` in `limiter_test.go` — delete that test (the structural reset is covered by `TestLimiter_AcquireStream_FreshConnIDResets`).
- [ ] `internal/limit/limiter.go` `Charge` — its `PExpire(ctx, "conc:"+name, …)` (line ~100) is UNCHANGED: it still refreshes the current owner's hash-key TTL per read; the data plane needs NO connID and NO lock.
- [ ] **Modify** the callers to thread `connID` (the edge already has it from `LookupRoute`): `internal/edge/edge.go` interface → `AcquireStream(ctx, name, connID string, maxN int) (bool, error)` and `ReleaseStream(ctx, name, connID string) error`; `internal/edge/bridge.go` (acquire at ~149/153, release at ~172) → pass the `connID` resolved by `LookupRoute` at ~116 for this stream, and its paired release uses the SAME `connID`.
- [ ] **Remove** the reset-on-bind wiring in `internal/phoneconn`: delete the `StreamResetter` interface (manager.go:35-37), the `Streams` field on `Manager` + `Config`, its `NewManager` assignment, and the `m.streams.ResetStreams(...)` block in `register()` (manager.go:180-184) with its comment.
- [ ] **Modify** `internal/server/server.go` — stop passing the limiter as `phoneconn.Config.Streams`.
- [ ] **Modify** the tests that reference the changed `AcquireStream`/`ReleaseStream` signatures or the removed `ResetStreams`/`StreamResetter` — ALL of them (each must compile + pass at US3):
  - `internal/limit/concurrency_test.go` — reconcile to the ownership-checked model: fresh-connID reset at acquire, straggler-release no-op, `DEL`-at-zero, cap never breached.
  - `internal/limit/limiter_test.go` — thread `connID` into `TestAcquireReleaseStreamGlobalCap`, `TestCharge_RefreshesConcTTLOnlyIfExists`, `TestAcquireStream_UsesDerivedTTL` (old signatures); delete `TestResetStreams_DeletesConcOnly` (per the bullet above). Note `Charge`'s conc-TTL-refresh test still holds (Charge is unchanged), but seed `conc:{name}` as a hash where it asserts on the key.
  - `internal/limit/window_test.go:79` — `AcquireStream(ctx, "tunnel-x", 4)` → add the `connID` arg.
  - `internal/edge/bridge_test.go:127` — `AcquireStream(ctx, name, cfg.Concurrent)` → add the `connID` arg.
  - `internal/edge/fixes_test.go:603-617` — the `countingLimiter` fake's `AcquireStream(ctx, name, maxN)` / `ReleaseStream(ctx, name)` → update to the new signatures so it still satisfies the edge `StreamLimiter` interface.
  - `internal/phoneconn/manager_test.go` (+ any integration/e2e wiring that passed `Streams`) — remove the `StreamResetter`/`Streams` references and any reset-on-bind assertion.

**DoD:** `conc:{name}` is a lock-guarded `{connID, count}` hash; a straggler release from a superseded connection is a no-op; a fresh connection resets at its first acquire (no `ResetStreams`); `DEL`-at-zero is race-free under the lock; the cap never breaches; `Charge` (data plane) is unchanged; `internal/limit` + `internal/phoneconn` + edge compile and all affected tests pass.

### Task 3.2 — Issuance: serializing lock + success-only counter — [ ]
- [ ] **Modify** `internal/limit/issuance.go` — delete `issuanceBeginScript`, `issuanceHeartbeatScript`, `recordIssuanceScript`, the `iss_inflight` hash + its `inflightKey`, and `newOrderID`'s slot semantics; rewrite around a lock:
```go
const (
	issLockTTL   = 15 * time.Second // 3 missed 5s beats; a crashed order releases within this
	issLockBeat  = 5 * time.Second  // IssuanceHeartbeatLoop refresh cadence
	issWindowTTL = 7 * 24 * time.Hour
)

func issuanceKey(name string) string   { return "iss:" + name }
func issLockKey(name string) string    { return "iss_lock:" + name }

// IssuanceBegin serializes issuance per tunnel via a SETNX lock (only one in-flight order per tunnel — the
// only real case) and gates against the weekly success cap under that lock. Returns the lock token as
// orderID for HeartbeatLoop/End. ok=false = another order in flight OR cap reached.
func (l *Limiter) IssuanceBegin(ctx context.Context, name string, maxN int) (ok bool, orderID string, err error) {
	token := mintToken()
	got, err := l.rdb.SetNX(ctx, issLockKey(name), token, issLockTTL).Result()
	if err != nil {
		return false, "", err
	}
	if !got {
		return false, "", nil // another issuance in flight
	}
	n, err := l.rdb.Get(ctx, issuanceKey(name)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		l.releaseIssLock(ctx, name, token)
		return false, "", err
	}
	if n >= maxN {
		l.releaseIssLock(ctx, name, token) // over cap — release and refuse
		return false, "", nil
	}
	return true, token, nil
}

// IssuanceHeartbeatLoop refreshes the lock TTL every issLockBeat until ctx is done, so a live (slow ACME)
// order keeps the lock; a crash stops the refresh and the lock self-expires.
func (l *Limiter) IssuanceHeartbeatLoop(ctx context.Context, name, orderID string) {
	t := time.NewTicker(issLockBeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Refresh the lock TTL while we still hold it. The GET(value==orderID) then PEXPIRE is a benign,
			// rare TOCTOU: if the lock expired and another order re-acquired it between the two commands, the
			// PEXPIRE extends the new holder's TTL — harmless and self-healing under the posture. Best-effort;
			// a failure is logged.
			if v, err := l.rdb.Get(ctx, issLockKey(name)).Result(); err == nil && v == orderID {
				if err := l.rdb.PExpire(ctx, issLockKey(name), issLockTTL).Err(); err != nil {
					l.logger.Warn("issuance lock refresh failed (lock may expire; a retry could then start)",
						"tunnel", name, "err", err)
				}
			}
		}
	}
}

// IssuanceEnd releases the lock (success AND failure — failed orders never burn the window).
func (l *Limiter) IssuanceEnd(ctx context.Context, name, orderID string) error {
	l.releaseIssLock(ctx, name, orderID)
	return nil
}

func (l *Limiter) releaseIssLock(ctx context.Context, name, token string) {
	if v, err := l.rdb.Get(ctx, issLockKey(name)).Result(); err == nil && v == token {
		_ = l.rdb.Del(ctx, issLockKey(name)).Err()
	}
}

// IssuanceRecord increments the rolling-7d success counter (called ONLY after a public cert issues,
// under the still-held lock). INCR + EXPIRE NX (TTL anchored at the first success in the window).
func (l *Limiter) IssuanceRecord(ctx context.Context, name string) error {
	pipe := l.rdb.Pipeline()
	pipe.Incr(ctx, issuanceKey(name))
	pipe.ExpireNX(ctx, issuanceKey(name), issWindowTTL)
	_, err := pipe.Exec(ctx)
	return err
}
```
- [ ] Reuse `mintToken()` from Task 3.1's `internal/limit/lock.go` (do NOT redefine it); delete the old `newOrderID` if it is now unused.
- [ ] **Verify** `internal/enroll/enroll.go` (lines 236/247/253/285) — the call shape (Begin → defer End → go HeartbeatLoop → Record on success) is unchanged; only the semantics behind the methods changed. Reconcile only if a signature shifted. **Also update the now-stale inflight-slot comments/log** to the SETNX-lock model: `enroll.go:232-233` ("reserve an in-flight slot … The slot is freed on BOTH success and failure, refreshed by a heartbeat") → "acquire the per-tunnel issuance lock … released on success AND failure … self-expires on crash"; the `enroll.go:248` `Warn("issuance slot release failed (slot self-expires)", …)` message → lock wording; and the stale inflight-slot comments in `internal/enroll/enroll_fixes_test.go` (~lines 515/531-532/555) and `internal/limit/limiter_test.go:154` ("a fresh Begin (no in-flight slots) is refused").
- [ ] **Modify** `internal/limit/limiter.go:32` — the `WithLogger` doc "used for the issuance-slot heartbeat failure surface" → "issuance-lock refresh failure surface".

- [ ] **Modify** `internal/limit/issuance_test.go` — remove ALL references to deleted symbols: the `l.issuanceHeartbeat(...)` method call, the `issuanceHeartbeatScript` var, `inflightKey(...)`, and the `issuanceSlotTTL`/`issuanceKeyTTLMargin`/`issuanceHeartbeatEvery` consts. Rewrite the suite against the new lock-based `IssuanceBegin`/`IssuanceHeartbeatLoop`/`IssuanceEnd`/`IssuanceRecord` (mapping to the US3 issuance test rows: serialize-one-per-tunnel, success-only counter, lock self-expiry).

**DoD:** at most one order per tunnel; `iss:{name}` counts successes only; a crashed order self-releases within `issLockTTL`; no `iss_inflight` key remains; `issuance_test.go` compiles + passes.

### Task 3.3 — Window + ACME-cooldown + nonce → plain commands — [ ]
- [ ] **Modify** `internal/limit/window.go` — remove `allowScript`; `Allow` uses a pipeline:
```go
func (l *Limiter) Allow(ctx context.Context, scope string, ip netip.Addr, limit int, window time.Duration) (bool, time.Duration, error) {
	now := l.now()
	winStart := now.Truncate(window)
	k := fmt.Sprintf("rl:%s:%s:%d", scope, ip.String(), winStart.Unix())
	pipe := l.rdb.Pipeline()
	c := pipe.Incr(ctx, k)
	pipe.ExpireNX(ctx, k, window*2) // TTL on the first hit; self-heals on the next same-window write
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}
	if int(c.Val()) > limit {
		return false, winStart.Add(window).Sub(now), nil
	}
	return true, 0, nil
}
```
- [ ] **Modify** `internal/limit/acme_cooldown.go` — remove `bumpFailuresScript`; `BumpCAFailures` pipelines `INCR` + `PEXPIRE(window)` (resets the streak window each hit):
```go
func (l *Limiter) BumpCAFailures(ctx context.Context, ca string, window time.Duration) (int, error) {
	pipe := l.rdb.Pipeline()
	c := pipe.Incr(ctx, failuresKey(ca))
	pipe.PExpire(ctx, failuresKey(ca), window)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return int(c.Val()), nil
}
```
- [ ] **Modify** `internal/enroll/nonce.go` — remove `consumeNonceScript`; `consumeNonce` uses `DEL` directly (a single atomic command returns the delete count):
```go
func (s *Service) consumeNonce(ctx context.Context, nonce []byte) (bool, error) {
	n, err := s.rdb.Del(ctx, nonceKey(hex.EncodeToString(nonce))).Result()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
```

- [ ] **Modify** stale "Lua" doc comments in `internal/limit` that become false once the scripts are gone: `internal/limit/limiter.go:15` (the `Limiter` struct doc: "set atomically in the same Lua script (or SET EX…)") → describe the pipelined `INCR`/`INCRBY` + `EXPIRE NX`/`PEXPIRE` self-healing model (NO Lua); `internal/limit/window.go:25` (`Allow`'s doc: "the INCR and its PEXPIRE … are a single Lua script (atomic — no un-TTL'd key)") → describe the pipeline with `EXPIRE NX` self-heal. (`limiter.go:83` already reads "no Lua" and is correct.)
- [ ] **Modify** `internal/limit/window_test.go` + `internal/limit/acme_cooldown_test.go` + `internal/enroll/nonce_test.go` (where present) — reconcile any assertion referencing the removed scripts/behaviors; delete the stale `// iss_inflight:` comment at `window_test.go:85` (US6 Task 6.1 greps for `iss_inflight`). Confirm the window/cooldown/nonce tests pass against the new pipeline/`DEL` implementations.

**DoD:** `internal/limit` and `internal/enroll` have ZERO `NewScript`; `Over` (read-only) is unchanged; all `internal/limit` + `internal/enroll` tests compile + pass; no stale `iss_inflight` reference remains in Go source.

### Task 3.4 — Docs — [ ]
- [ ] **Modify** `docs/ARCHITECTURE.md` — review the abuse-control / issuance text and align any wording this story changed. NOTE (anchors): §4 (per-window model) already states "NO Lua, NO TxPipeline"; the two-phase issuance §3 describes only the enrollment *flow* (no inflight-slot mechanic). Edit ONLY any issuance-slot/heartbeat or Lua-atomicity phrasing actually present (if none, record it in `## Deviations`), and update any `conc:{name}` description to the lock-guarded `{connID, count}` hash with ownership-checked acquire/release (fresh-connID reset at acquire; NO reset-on-bind).
- [ ] **Modify** `.claude/rules/project.md` — the "Live-vs-identity reset invariant" bullet ("`conc:{name}` … RESET (`DEL`) when the phone (re)binds … The bind-time reset hits `conc:{name}` ONLY …") → restate: `conc:{name}` is a lock-guarded `{connID, count}` hash whose reset is STRUCTURAL — a fresh connection resets it at its first acquire because the stored connID differs; there is NO bind-time `DEL`. The identity-scoped `traf:` day/week quotas STILL persist across reconnects. Also update the "Unified per-window limit model" description of the "global stream-counter key `conc:{name}`" (now a lock-guarded `{connID, count}` hash, connID-owned; `Charge`'s `PEXPIRE` still refreshes its TTL per read; the "RESET (`DEL`) on phone (re)bind" clause is removed).
- [ ] **Modify** `docs/PROJECT.md` — update any `conc:{name}` reset-on-bind description to the structural per-connection reset.

**Tests (US3):**

| Test | Verifies |
|---|---|
| `TestLimiter_AcquireStream_CapNeverBreached` | same-connID acquires at cap: admitted `count` ≤ cap; the over-cap acquire rolls back (DECR / DEL on a fresh reset) and denies |
| `TestLimiter_AcquireStream_FreshConnIDResets` | an acquire with a NEW connID overwrites `{connID, count}` to `{new, 1}` — the prior connection's count is discarded (structural reset) |
| `TestLimiter_AcquireStream_SetsTTL` | `conc:{name}` always carries a TTL after an admitted acquire |
| `TestLimiter_ReleaseStream_StragglerNoOp` | a release whose connID ≠ the stored owner is a no-op (does not decrement the new owner's count) |
| `TestLimiter_ReleaseStream_DeleteAtZero` | an owner release to `count≤0` DELs the key; under the lock this cannot race a concurrent acquire |
| `TestLimiter_Issuance_SerializesOnePerTunnel` | second `IssuanceBegin` while one holds the lock → ok=false |
| `TestLimiter_Issuance_CapCountsSuccessesOnly` | `Record` only on success; a failed order (End without Record) does not burn the window |
| `TestLimiter_Issuance_LockSelfExpires` (miniredis fast-forward) | no HeartbeatLoop → lock gone after `issLockTTL`; a new Begin then succeeds |
| `TestLimiter_Allow_IncrExpireNX` | first hit sets TTL; over-limit denies with retry-after to the boundary |
| `TestLimiter_BumpCAFailures_ResetsWindow` | streak increments and TTL is (re)set each call |
| `TestService_ConsumeNonce_SingleUse` | first consume true, second false; absent → false |

---

## US4 — Enrich the node registry and expose `/api/v1/admin/nodes` — [ ]

**Why:** operators need to see which replicas are up and their status.

**Acceptance criteria:**
- [ ] `node:{id}` stores TTL'd JSON `{advertise, hostname, version, started_at, last_heartbeat}` (still TTL =
      `RouteTTL`, refreshed at `RouteTTL/3` by the existing `heartbeatNode`).
- [ ] `GET /api/v1/admin/nodes` on the INTERNAL listener returns the live nodes (crashed nodes drop off by TTL).
- [ ] No new goroutine, no lock — a plain `SET … EX` per heartbeat (single command, self-healing).

### Task 4.1 — Richer node value — [ ]
- [ ] **Modify** `internal/router/nodes.go` — `node:{id}` value becomes JSON; `RegisterNode`/`RefreshNode` take the richer payload; `Nodes()`/`LookupNode` parse it:
```go
// NodeInfo is the node-registry value (JSON in node:{id}). Advertise remains the mesh dial address that
// LookupNode returns to the edge; the rest is ops metadata for /api/v1/admin/nodes.
type NodeInfo struct {
	Advertise     string `json:"advertise"`
	Hostname      string `json:"hostname"`
	Version       string `json:"version"`
	StartedAt     string `json:"started_at"`     // RFC3339
	LastHeartbeat string `json:"last_heartbeat"` // RFC3339, stamped on each (Register|Refresh)Node
}
```
  - `RegisterNode(ctx, nodeID string, info NodeInfo, ttl)` and `RefreshNode(...)` `json.Marshal` + `SET EX`.
  - `LookupNode` unmarshals and returns `info.Advertise` (edge dial path unchanged).
  - `Nodes(ctx) (map[string]NodeInfo, error)` unmarshals each value (SCAN, `COUNT` ~100, dedupe as today).
  - `LastHeartbeat` is stamped by the CALLER into the `NodeInfo` it passes (`heartbeatNode` sets it to
    the current time); `RegisterNode`/`RefreshNode` just `json.Marshal` the given value — the registry needs
    no clock of its own.
- [ ] **Modify** `internal/server/schedulers.go` `heartbeatNode` — build a `NodeInfo` (advertise = `cfg.MeshAdvertise`, hostname = `nodeHost`, version, `started_at` = process start, `last_heartbeat` = now) and pass it to Register/Refresh. Extend the `heartbeatNode` signature to carry `nodeHost`, `version`, `nodeStart` (already available in `server.Run`).
- [ ] **Modify** `internal/server/server.go:271` — update the `heartbeatNode(...)` call with the new args.
- [ ] **Modify** `internal/router/nodes_test.go` — reconcile with the new signatures: the existing tests call `RegisterNode(ctx,"nodeA","10.0.0.1:9443",…)` / `RefreshNode(…,"a:1",…)` (string advertise) and compare `nodes["a"] != "10.0.0.1:9443"` (string). Rewrite to pass a `NodeInfo` and assert on `NodeInfo` fields (these become / are replaced by the new `TestRegistry_RegisterAndListNodes_JSON` and `TestRegistry_Node_TTLExpiry`).
- [ ] **Modify** `internal/server/schedulers_test.go` — update the `heartbeatNode(ctx, reg, "node-t", "10.0.0.1:9443", 30*time.Millisecond, logger)` call (`TestHeartbeatNodeSurvivesTransientError`, ~line 91) to the new `heartbeatNode` signature (added `nodeHost`, `version`, `nodeStart` args).

**DoD:** the edge's `LookupNode`→advertise path is byte-for-byte unchanged; `Nodes()` returns parsed metadata; `internal/router` compiles + all its tests pass at US4.

### Task 4.2 — `/api/v1/admin/nodes` endpoint (additive) — [ ]
- [ ] **Modify** `internal/metrics/server.go` `Handler` — ADD a `NodeSource` parameter + the `/api/v1/admin/nodes` route, WITHOUT touching the existing `adminSrc`/`TopN` `/api/v1/admin/tunnels` route (that route is replaced in US5). New signature: `Handler(reg *prometheus.Registry, rdb, adminSrc AdminSource, nodeSrc NodeSource, log)`.
```go
// NodeSource is the node-registry read surface (implemented by *router.Registry).
type NodeSource interface {
	Nodes(ctx context.Context) (map[string]router.NodeInfo, error)
}
// ... inside Handler:
mux.HandleFunc("/api/v1/admin/nodes", func(w http.ResponseWriter, r *http.Request) {
	nodes, err := nodeSrc.Nodes(r.Context())
	if err != nil {
		log.Warn("admin nodes failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodes)
})
```
- [ ] **Modify** `internal/server/server.go:212` — add the new `NodeSource` arg: `metrics.Handler(m.Registry(), rdb, adminStore, reg, logger)`. The existing `adminStore`/`TopN` tunnels route stays until US5.
- [ ] **Modify** `internal/metrics/metrics_test.go` — update every `Handler(...)` test call to the new additive signature (pass a fake/`nil`-safe `NodeSource`); add a `TestHandler_AdminNodes` (httptest) per the US4 test table.

**DoD:** `/api/v1/admin/nodes` returns the node map; the existing `/api/v1/admin/tunnels` TopN route still works and the tree + tests COMPILE at US4; the mesh (`:9443`) and internal (`:9090`) ports remain unpublished.

### Task 4.3 — Docs — [ ]
- [ ] **Modify** `docs/ARCHITECTURE.md` + `docs/PROJECT.md` — document the enriched node registry + `/api/v1/admin/nodes`.

**Tests (US4):**

| Test | Verifies |
|---|---|
| `TestRegistry_RegisterAndListNodes_JSON` | Register/Refresh round-trip; `Nodes()` parses all fields; `LookupNode` returns advertise |
| `TestRegistry_Node_TTLExpiry` (miniredis fast-forward) | a node not refreshed drops from `Nodes()` after TTL |
| `TestHandler_AdminNodes` (httptest) | endpoint returns the node JSON; error → 500 |

---

## US5 — Split the tunnels admin endpoint into paginated list + batch stats — [ ]

**Why:** frontend-driven, no backend ranking, scales to many tunnels, richer metrics — and the old `TopN`
was removed in US2.

**Acceptance criteria:**
- [ ] `GET /api/v1/admin/tunnels?cursor=&count=` returns ONE `SCAN` step: `{names:[…], cursor:"…"}` (cursor
      "0" = complete). No looping the whole keyspace in one request; no ranking.
- [ ] `POST /api/v1/admin/tunnels/stats` with `{names:[…]}` returns per-name `{node, bytes_in, bytes_out,
      conc, bw_in, bw_out, day_in, day_out, week_in, week_out}` via computed keys, batched (never per-name,
      never a metric-keyspace SCAN): route meta via an `HMGET` pipeline over `tunnel:*`, and the limit
      windows via one pipeline (`MGET` the `bw:`/`traf:` strings + `HMGET` each `conc:` hash `count`).
- [ ] `bw` window TTL is 3s (so the last-complete-second bucket is reliably readable).
- [ ] Stats read GLOBAL shared counters (cross-replica aggregate); the endpoint enriches only the names asked for.

### Task 5.1 — per-second window TTL 2s → 3s — [ ]
- [ ] **Modify** `internal/limit/limiter.go:63` — `bwWindowTTL = 3 * time.Second` (comment: 3× the 1s window so the previous complete second is still readable by the admin bandwidth view).

**DoD:** `Charge` uses the single `bwWindowTTL` constant for BOTH the `bw:` and `pkt:` `ExpireNX` calls, so this change moves BOTH per-second windows to 3s — this is intended and benign: a per-second counter simply lingers 1s longer before cleanup, with zero counting/enforcement impact (the windows are clock-aligned, not TTL-driven). Do NOT split the constant.

### Task 5.2 — Tunnel list (paginated SCAN) in `internal/router` — [ ]
- [ ] **Modify** `internal/router/registry.go` — add a single-step scan:
```go
// ScanTunnels returns ONE SCAN step over tunnel:{name} keys: the batch of names and the next cursor
// (0 = iteration complete). The caller (admin endpoint) exposes the cursor to the client for pagination —
// no request ever materializes the whole keyspace. count is the SCAN COUNT hint (~100).
func (r *Registry) ScanTunnels(ctx context.Context, cursor uint64, count int64) (names []string, next uint64, err error) {
	keys, next, err := r.rdb.Scan(ctx, cursor, "tunnel:*", count).Result()
	if err != nil {
		return nil, 0, err
	}
	for _, k := range keys {
		names = append(names, k[len("tunnel:"):])
	}
	return names, next, nil
}

// TunnelMeta batch-reads node + byte counters for the given names (one pipeline of HMGETs). Names with no
// live route (no `node` field) are omitted.
func (r *Registry) TunnelMeta(ctx context.Context, names []string) (map[string]TunnelMetaInfo, error) {
	if len(names) == 0 {
		return map[string]TunnelMetaInfo{}, nil
	}
	pipe := r.rdb.Pipeline()
	cmds := make([]*redis.SliceCmd, len(names))
	for i, n := range names {
		cmds[i] = pipe.HMGet(ctx, key(n), "node", "bytes_in", "bytes_out")
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	out := make(map[string]TunnelMetaInfo, len(names))
	for i, n := range names {
		v, _ := cmds[i].Result()
		node, _ := v[0].(string)
		if node == "" {
			continue // no live route (or a byte-only orphan) — not reported
		}
		out[n] = TunnelMetaInfo{Node: node, BytesIn: atoiVal(v[1]), BytesOut: atoiVal(v[2])}
	}
	return out, nil
}
```
  where `TunnelMetaInfo{Node string; BytesIn, BytesOut int64}` and `atoiVal(any) int64` (reuse the parse helper pattern).

**DoD:** `ScanTunnels` does exactly one `SCAN`; `TunnelMeta` is one pipeline; both never SCAN the metric keyspaces.

### Task 5.3 — Per-tunnel windows (computed keys) in `internal/limit` — [ ]
- [ ] **Modify** `internal/limit/limiter.go` — add a batch stats read that computes the exact keys (reusing `chargeKeys` math) and does ONE `MGET`:
```go
// TunnelStat is the live per-tunnel window snapshot for the admin stats endpoint.
type TunnelStat struct {
	Conc    int64 `json:"conc"`
	BwIn    int64 `json:"bw_in"`   // bytes in the last COMPLETE second (sec-1)
	BwOut   int64 `json:"bw_out"`
	DayIn   int64 `json:"day_in"`
	DayOut  int64 `json:"day_out"`
	WeekIn  int64 `json:"week_in"`
	WeekOut int64 `json:"week_out"`
}

// TunnelWindows batch-reads conc + last-complete-second bandwidth + day/week traffic for names, computing
// every key from name + clock (no metric-keyspace SCAN) and doing ONE MGET. These are GLOBAL shared
// counters, so the values are the cross-replica aggregate.
func (l *Limiter) TunnelWindows(ctx context.Context, names []string) (map[string]TunnelStat, error) {
	if len(names) == 0 {
		return map[string]TunnelStat{}, nil
	}
	sec := l.now().Unix()
	prev := strconv.FormatInt(sec-1, 10) // last complete second
	d := strconv.FormatInt(sec/86400, 10)
	w := strconv.FormatInt(sec/86400/7, 10)
	const perName = 6 // six string windows; conc:{name} is a HASH, read via HMGET below (MGET can't read a hash)
	keys := make([]string, 0, len(names)*perName)
	for _, n := range names {
		keys = append(keys,
			"bw:"+n+":in:"+prev, "bw:"+n+":out:"+prev,
			"traf:"+n+":in:day:"+d, "traf:"+n+":out:day:"+d,
			"traf:"+n+":in:week:"+w, "traf:"+n+":out:week:"+w,
		)
	}
	// One pipeline: an MGET over the string windows + a per-name HMGET of the conc:{name} hash "count" field.
	pipe := l.rdb.Pipeline()
	concCmds := make([]*redis.SliceCmd, len(names))
	for i, n := range names {
		concCmds[i] = pipe.HMGet(ctx, "conc:"+n, "count") // HMGET on a missing key/field → [nil], no error
	}
	mget := pipe.MGet(ctx, keys...)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	vals := mget.Val()
	out := make(map[string]TunnelStat, len(names))
	for i, n := range names {
		b := i * perName
		var conc int64
		if cv := concCmds[i].Val(); len(cv) > 0 {
			conc = atoiCap(cv[0]) // atoiCap treats nil / non-string as 0
		}
		out[n] = TunnelStat{
			Conc: conc, BwIn: atoiCap(vals[b]), BwOut: atoiCap(vals[b+1]),
			DayIn: atoiCap(vals[b+2]), DayOut: atoiCap(vals[b+3]),
			WeekIn: atoiCap(vals[b+4]), WeekOut: atoiCap(vals[b+5]),
		}
	}
	return out, nil
}
```
  (`atoiCap` already exists in `limiter.go`.)

**DoD:** one pipeline (`MGET` over the six string windows + a per-name `HMGET` of the `conc:{name}` hash `count` — the `conc` value MUST come from the hash, NOT the `MGET`, since `conc:{name}` is a hash); keys computed from `chargeKeys` math (no drift); empty `names` → empty map (no zero-key `MGET`).

### Task 5.4 — The two endpoints; retire the old top-N surface — [ ]
- [ ] **Modify** `internal/metrics/server.go` — REMOVE the `AdminSource`/`TopN` interface and its `/api/v1/admin/tunnels` route; ADD a `TunnelSource` consumer interface and the two new handlers (keep the US4 `NodeSource` param). Final signature: `Handler(reg *prometheus.Registry, rdb, tunnelSrc TunnelSource, nodeSrc NodeSource, log)` (the old `adminSrc AdminSource` arg is dropped):
```go
// TunnelSource is the admin tunnels read surface (implemented by internal/admin composing router + limit).
type TunnelSource interface {
	List(ctx context.Context, cursor uint64, count int64) (names []string, next uint64, err error)
	Stats(ctx context.Context, names []string) (map[string]admin.TunnelStats, error)
}
```
  - `GET /api/v1/admin/tunnels`: parse `cursor` (default 0) + `count` (default 100, clamp ≤500), call `List`, return `{"names":…, "cursor":"<next>"}`.
  - `POST /api/v1/admin/tunnels/stats`: enforce method POST (else 405); cap the request body with `http.MaxBytesReader` (else 413); decode `{names:[…]}` (bound ≤500 else 400), call `Stats`, return the map.
- [ ] **Rewrite** `internal/admin/tunnels.go` — delete the residual `Store`, `NewStore`, `TopN`, and old `TunnelStat` (kept alive since US2); replace with a thin composer implementing `TunnelSource`. Merge into `TunnelStats{Node, BytesIn, BytesOut + the seven window fields}`. Define small consumer interfaces to avoid an import cycle: `type tunnelMetaReader interface { ScanTunnels(ctx, cursor uint64, count int64) ([]string, uint64, error); TunnelMeta(ctx, names []string) (map[string]router.TunnelMetaInfo, error) }` and `type tunnelWindowReader interface { TunnelWindows(ctx, names []string) (map[string]limit.TunnelStat, error) }`; `func NewTunnels(meta tunnelMetaReader, win tunnelWindowReader) *Tunnels`. `Stats` calls `TunnelMeta` + `TunnelWindows` for the requested names and merges. **Merge rule (explicit):** the result includes a name ONLY if `TunnelMeta` returned it (i.e. it has a live `node`); a listed name whose route is gone but whose windows still hold data (a byte-only orphan, or a just-disconnected tunnel) is OMITTED — so `/stats` reports live tunnels only, consistent with the merged-key live-scoped model. `List` delegates to `ScanTunnels`.
- [ ] **Modify** `internal/server/server.go` — remove `adminStore := admin.NewStore(...)` (:103); construct `adminTunnels := admin.NewTunnels(reg, lim)` and update :212 to `metrics.Handler(m.Registry(), rdb, adminTunnels, reg, logger)`.
- [ ] **Modify** `internal/metrics/metrics_test.go` — replace the `AdminSource`/`TopN`-based `Handler` test calls with the final signature (a `TunnelSource` fake + the `NodeSource` fake); cover the list + `/stats` handlers per the US5 test table.
- [ ] **Rewrite** `internal/admin/tunnels_test.go` — the `Store`/`TopN`/`TunnelStat` tests (reseeded in US2) reference symbols deleted here; replace the whole file with tests for the new `Tunnels`/`List`/`Stats` composer (fake `tunnelMetaReader` + `tunnelWindowReader`), asserting the merge rule (live-only; windows-only names omitted).

**DoD:** the old top-N behavior and `admin.Store`/`NewStore`/`TopN` are gone; `metrics.Handler` no longer takes `AdminSource`; the tree + `internal/admin` + `internal/metrics` tests compile + pass; list is one SCAN step; stats is one pipeline+MGET; `/stats` reports live tunnels only; both are frontend-driven.

### Task 5.5 — Docs — [ ]
- [ ] **Modify** `docs/ARCHITECTURE.md` + `docs/PROJECT.md` + `.claude/rules/project.md` (Observability section) — replace the single `/api/v1/admin/tunnels` top-N description with the list + `/stats` split and the enriched fields.
- [ ] **Modify** the per-second window TTL numeral everywhere it is stated, to match the `bwWindowTTL` code change in T5.1: `docs/ARCHITECTURE.md` §4 (`per-second = 2 s` → `3 s`) and `.claude/rules/project.md` Unified per-window limit model (`per-second = 2 s` → `3 s`).
- [ ] **Modify** the `admin` commit-scope row in `.claude/rules/project.md` — it currently reads "`internal/admin`: per-tunnel counters + `/api/v1/admin/tunnels`"; after this plan `internal/admin` no longer holds the counters (they live in `tunnel:{name}` under `router`) and the endpoint is split — update to e.g. "`internal/admin`: tunnels list + batch-stats composer (over router + limit)".

**Tests (US5):**

| Test | Verifies |
|---|---|
| `TestRegistry_ScanTunnels_OneStepCursor` (miniredis) | returns a batch + next cursor; cursor 0 completes; strips the `tunnel:` prefix |
| `TestRegistry_TunnelMeta_OmitsNonRoutable` | a byte-only orphan (no `node`) is excluded; live tunnels return node + bytes |
| `TestLimiter_TunnelWindows_ComputedKeys` (fixed clock) | seeds `conc:{name}` as a HASH (`HSet … count …`) + the string windows; asserts a NON-zero `Conc` (read via HMGET) plus `sec-1` bandwidth + day/week; empty names → empty |
| `TestLimiter_BwWindowTTL_LastSecondReadable` | with 3s TTL the `sec-1` bucket is still present when read during `sec` |
| `TestHandler_AdminTunnels_ListPaginates` (httptest) | `?cursor=` returns names + next cursor |
| `TestHandler_AdminTunnels_StatsBatch` (httptest) | POST `{names}` returns merged per-name stats; oversized body → 413; non-POST → 405 |

---

## US6 — Ground-up verification — [ ]

**Why:** confirm the whole change is coherent, Lua-free, and green from the ground up.

### Task 6.1 — Lua/tx eradication proof — [ ]
- [ ] **Verify** repo-wide: `grep -rn "NewScript\|\.Eval\|TxPipeline\|\.Watch(" --include=*.go internal/` returns ONLY non-Redis matches (the attestation file-watcher `attSigners.Watch`, comments) — ZERO `redis` Lua/tx. Record the exact residual matches in `## Deviations` if any are intentional non-Redis hits.
- [ ] **Verify** repo-wide (supplementary to `make test-unit`): `grep -rn '"route:\|route:{\|tcnt\|iss_inflight' --include=*.go internal/` returns ZERO matches. NOTE: match the KEY forms only — `"route:` (quoted literal, e.g. `"route:abc"`) and `route:{` (the `route:{name}` template) — NOT the bare substring `route:`, which legitimately appears in English prose (e.g. "…the re-bound route: the active stream…"). All renamed to `tunnel:{name}` or removed.
- [ ] **Verify** no stale Lua-atomicity claims remain in comments: `grep -rin "Lua script\|single Lua\|single-Lua\|same Lua" --include=*.go internal/` returns ZERO matches (case-insensitive `-i` catches `Single Lua`; the `single-Lua` alternative catches the hyphenated form). NOTE: target the stale phrasings ONLY — the affirmative "no Lua, no TxPipeline" comments (e.g. `limiter.go`) are correct and MUST remain; do NOT grep the bare word `Lua`.
- [ ] **Verify** every removed script has an equivalent behavioral test in its package (US1–US5 tables).

### Task 6.2 — Invariant + docs coherence — [ ]
- [ ] **Re-read** `.claude/rules/project.md`, `docs/ARCHITECTURE.md`, `docs/PROJECT.md` — confirm they describe the `tunnel:{name}` merged key, the lock-based route ownership, the issuance lock, and the admin endpoints, with NO stale `route:{name}`/`tcnt:{name}`/Lua references.
- [ ] Confirm the Engineering posture is cited by the US1/US3 rationale and no residual "via Lua" mandate remains.

### Task 6.3 — Quality gates (the ONLY place they run) — [ ]
- [ ] `make lint` (×3 build tags) + `make vet` + `make govulncheck` — ZERO warnings/errors.
- [ ] `make build` — clean.
- [ ] `make test-unit` — all pass (`-race`).
- [ ] `make test-integration` — real `server.Run` + testcontainers; all pass.
- [ ] `make test-e2e` — two in-process replicas; all pass (adb-gated attestation test may skip without a device).
- [ ] `make compose-config` + `make test-scripts` if touched.
- [ ] No Mermaid chart is added/modified by this plan; if any doc edit touches a Mermaid block, run `make mermaid-check` and record it here.

### Task 6.4 — End-to-end double-check — [ ]
- [ ] Walk every user story's acceptance criteria against the final code; confirm each is met; tick all boxes.
- [ ] Confirm no file outside this plan's scope was altered; confirm no AI attribution anywhere.

---

## Deviations
<!-- Record here every reconciliation between this plan and the live code (task/action reference + what changed + why). -->
