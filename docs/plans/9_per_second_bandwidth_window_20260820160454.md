<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 9 — Per-second byte + packet bandwidth windows (replace the token-bucket batch-credit pacer)

Replace the per-tunnel/per-direction **token-bucket batch-credit** bandwidth pacer with two **per-second
fixed-window counters** — a byte window and a packet (read) window — each a pipelined `INCRBY`/`INCR` +
`EXPIRE … NX` (NO Lua). Charge every read directly; on either cap being exceeded, wait out the rest of the
current second. This removes the "draw a 1 MB batch to move 4 KB" over-charge that crippled the
short-connection / small-payload workload, and adds a loose tiny-packet-flood backstop.

## Context & key decisions (the decision record — not derivable from code)

- **Why the token bucket is wrong here.** The current pacer (`internal/limit` `ClaimBandwidth` +
  `internal/edge` `pace`/`bwBatch`) draws a **1 MB batch** of credit into per-stream local state on the
  first chunk. A fresh connection that moves only ~4 KB draws a full batch and discards the unspent
  remainder at close (no return path). At a rate ≤ 1 MB/s the batch is the whole one-second budget, so a
  single tiny fresh-connection request can drain the entire per-tunnel allowance to move 4 KB — pathological
  for the actual workload (short/no-keep-alive connections, ~4–5 KB payloads).
- **New model — per-second fixed windows, charge-per-read, no Lua.** Keys `bw:{name}:{dir}:{unix_second}`
  (bytes) and `pkt:{name}:{dir}:{unix_second}` (reads). Each read does ONE plain **pipelined** round-trip
  (`Pipeline`, NOT `TxPipeline`): `INCRBY bw… nr` + `INCR pkt…` + `EXPIRE bw… 2s NX` + `EXPIRE pkt… 2s NX`.
  If the returned byte count exceeds the byte cap OR the returned read count exceeds the packet cap, the
  caller sleeps until the next 1-second boundary (that wait IS the pacing); then it forwards the chunk.
  `EXPIRE … NX` sets the TTL only when the window has none (verified: go-redis v9.22.0 `ExpireNX`,
  `generic_commands.go`). TTL is **2 s** (not 1 s) so a write late in a window never expires the counter
  mid-window. A Valkey error **fails open** (forward unpaced) — unchanged contract.
- **Why a plain pipeline (not `TxPipeline`/Lua) is correct here — the right rigor is use-case-dependent.**
  These are per-second transient counters, and `ChargeBandwidth` runs on EVERY read (≈30 reads/sec on one
  `bw:…:{second}` key at 1 mbit + 4 KB). The `INCR`/`EXPIRE NX` commands cannot fail singularly, and
  `EXPIRE NX` makes the TTL **self-healing within the second**: if any read's `EXPIRE` is ever skipped (the
  non-atomic INCR-ran-EXPIRE-didn't window that atomicity would close), the very NEXT read in that second
  re-sets the TTL (the key still has none, so NX fires). The only residual is the LAST read of a second-key
  being orphaned by a connection death in the exact INCR→EXPIRE gap with no later same-second read — leaving
  one stale un-TTL'd counter (a few bytes) for one tunnel-second that is never reused (no effect on limiting;
  the next second is a new key). That is negligible and bounded, so strict atomicity is unwarranted for this
  use case — a durable/financial counter would justify `TxPipeline`/Lua; a self-healing transient rate window
  does not. This is a DELIBERATE, justified choice, not a deferred defect.
- **Read cap 16 KiB.** The paced-copy read slice is `wire.ChunkSize`, redefined **32768 → 16384**. This
  bounds each per-read charge (and the overshoot) and keeps small payloads to ~1 read = 1 Valkey round-trip.
  `wire.ChunkSize` is documented as "the paced-copy slice size only" (internal, NOT wire-visible — the data
  splice is opaque/unframed), so changing it does not touch the phone-client contract; but every reference
  (config floor, metrics estimate, docs, the `ChunkSize` assertion test) moves in lockstep.
- **Overshoot bound (accepted).** Within a 1-second window, concurrent reads can push a window past its cap
  before any observes it, so the per-second overshoot is bounded by `byteCap + N_concurrent × 16 KiB` and
  `pktCap + N_concurrent` — with `--limit-concurrent` this is a provable ceiling. This is the deliberate
  trade for a Lua-free, no-local-credit, charge-exactly design.
- **Packet cap is a loose operator knob — default 100, grounded in the target workload.** New
  `--limit-packets` (int, default **100**), per tunnel per direction, reads/sec — a backstop against
  tiny-packet op-amplification (1-byte reads that never trip the byte cap). The byte rate is the primary
  limit. Concrete sizing for the target deployment (per-direction `--limit-bandwidth` = the default
  `1mbit` = 125,000 B/s; ~4 KB request payloads, one read each): legit **reads/sec = 125,000 ÷ 4,096 ≈ 30**,
  and the byte window itself caps it there (read 31 × 4 KB > 125 KB), so a legit tunnel never approaches
  100 regardless of `--limit-concurrent` (all streams share the one per-direction byte window). 100 is thus
  ~3.3× headroom over the worst-case (smallest-message) legit rate, while a 1-byte flood — which would
  otherwise reach ~125,000 reads/sec before the byte cap trips — is capped at 100. It is disabled when 0
  (the Limiter default) so only the server and packet-cap tests set it; operators raise it for
  higher-bandwidth / smaller-message workloads (consistent with "operators raise the `--limit-*` values,
  never the code"): the floor to clear is `bandwidth ÷ smallest-message-bytes`.
- **Scope preserved.** The day/week traffic quota (`ClaimTraffic`, its Lua script, the `conc:{name}` TTL
  refresh piggyback) and the concurrency counter are **UNCHANGED**. The `--limit-bandwidth` flag keeps its
  meaning (bytes/sec, DECIMAL bits) and stays the byte-window cap. Fail-open behavior is preserved. The
  bandwidth floor stays `= wire.ChunkSize` (now 16384): a rate below one read slice would make a single read
  exceed the whole second's budget, throttling every read.
- **Safe to change heavily.** Nothing is deployed (no prod/staging/test), so this is a clean cutover with no
  migration.

Ground-truth sources this plan mirrors: `internal/limit/limiter.go`, `internal/edge/bridge.go` +
`internal/edge/edge.go`, `internal/wire/frame_v2.go`, `internal/config/config.go`,
`internal/metrics/metrics.go`, `internal/server/server.go`, and the bandwidth-model docs
(`docs/ARCHITECTURE.md` §4, `docs/PROJECT.md`, `docs/PROTOCOL.md`, `.claude/rules/project.md`).

---

## User Story 1 — [ ] Read-slice constant (16 KiB) + config surface

Move the paced-copy read slice to 16 KiB and add the packet-cap config surface (flag + floor).

**Acceptance criteria:**
- [ ] `wire.ChunkSize == 16384`; every `ChunkSize`-derived value/assertion/comment updated in lockstep.
- [ ] `--limit-packets` (int, default 100) exists with a `TUNNELD_*` env twin and a positive-int `Validate()`.
- [ ] The `--limit-bandwidth` floor is `16384` B/s (= `wire.ChunkSize`), with the help/error/comment updated.

### Task 1.1 — [ ] `wire.ChunkSize` → 16 KiB (`internal/wire/frame_v2.go`)

**Actions:**
- [ ] Change the constant and its comment:

  ```go
  // ChunkSize is the paced-copy read/slice size — the max body bytes read and charged per bandwidth
  // window step. It is internal (the opaque data splice is unframed; HTTP/2 provides framing), NOT part
  // of the phone-client wire contract. See docs/PROTOCOL.md.
  const ChunkSize = 16 * 1024
  ```
- [ ] `internal/wire/frame_v2_test.go`: `TestChunkSizeConstant` — assert `ChunkSize == 16384` (update the
  literal and the message).
- [ ] `internal/metrics/metrics_test.go:139`: the exported per-conn estimate is `2*ChunkSize`, so the
  asserted line becomes `tunneld_per_conn_mem_bytes 32768` (was `65536`).

**Definition of Done:**
- [ ] `ChunkSize == 16384`; the two ChunkSize-derived test assertions match.

### Task 1.2 — [ ] `--limit-packets` flag + bandwidth floor (`internal/config/config.go`)

**Actions:**
- [ ] Add the flag field (place it beside `LimitBandwidth`):

  ```go
  LimitPackets int `name:"limit-packets" default:"100" help:"Max reads (packets) per second per tunnel per direction — a loose backstop against tiny-packet floods; the byte rate is the primary limit."`
  ```
- [ ] Add it to the positive-int validation list (beside `{"--limit-concurrent", c.LimitConcurrent}`):
  `{"--limit-packets", c.LimitPackets}`.
- [ ] Lower the bandwidth floor to one read slice and fix its note (the token-bucket rationale is gone):

  ```go
  // bandwidthFloorBytesPerSec is the minimum accepted --limit-bandwidth in bytes/sec. It MUST equal
  // wire.ChunkSize (16*1024): each read charges up to one slice against the per-second byte window, so a
  // rate below one slice would make a single read exceed the whole second's budget and throttle every
  // read (the tunnel could never forward more than one slice per second). The literal is duplicated here
  // with this note rather than importing wire (avoids an import cycle).
  const bandwidthFloorBytesPerSec int64 = 16 * 1024
  ```
- [ ] Update the `--limit-bandwidth` flag help (`minimum 32768 B/s (~263kbit … 256kbit=32000 B/s is REJECTED)`
  → `minimum 16384 B/s (~131kbit … 128kbit=16000 B/s is REJECTED)`) and the `Validate()` error string
  (`= wire.ChunkSize; … 256kbit=32000 B/s fails` → `= wire.ChunkSize; … 128kbit=16000 B/s fails`).

**Definition of Done:**
- [ ] `--limit-packets` is a validated positive-int flag; the floor is 16384 with consistent help/error/comment.

### Task 1.3 — [ ] Config tests (`internal/config/config_test.go`)

**Actions:**
- [ ] Set `LimitPackets: 100` in the valid-config helper so `Validate()` passes.
- [ ] `TestValidateRequiresBandwidthFloor`: move the below/above-floor cases to straddle 16384 B/s (fail:
  `128kbit` = 16000 B/s; pass: `256kbit` = 32000 B/s and `1mbit`).

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestValidateRequiresBandwidthFloor` | `128kbit` (16000 B/s) rejected; `256kbit`/`1mbit` accepted | straddles the new 16384 floor |
| `TestValidateRejectsNonPositivePackets` | `--limit-packets ≤ 0` rejected | mirror the existing `--limit-concurrent` positive-int case |

**Definition of Done:**
- [ ] The floor test straddles 16384; a non-positive `--limit-packets` is rejected; the valid config passes.

---

## User Story 2 — [ ] Per-second byte + packet window limiter (`internal/limit`)

Replace the token bucket with a pipelined, Lua-free per-second window charge; keep the day/week quota.

**Acceptance criteria:**
- [ ] `ClaimBandwidth` + `claimBandwidthScript` are GONE.
- [ ] `ChargeBandwidth(ctx, name, dir, nr)` records `nr` bytes + one read into `bw:{name}:{dir}:{sec}` /
  `pkt:{name}:{dir}:{sec}` in ONE plain pipelined round-trip (`Pipeline`: `INCRBY`/`INCR` + `EXPIRE 2s NX`
  ×2, no Lua; `EXPIRE NX` self-heals a skipped TTL on the next same-second read — see the use-case rationale
  in Context) and returns
  `(over bool, retryAfter time.Duration, err error)`: `over` iff bytes > byteCap OR (pktCap>0 AND reads >
  pktCap); `retryAfter` = time to the next 1-second boundary; a Valkey error → `over=false` (fail-open).
- [ ] The packet cap is set via `WithPacketCap(n)` (functional option, go.md); default 0 = disabled.
- [ ] `ClaimTraffic` / `TrafficExhausted` and the `conc:{name}` TTL piggyback are UNCHANGED.

### Task 2.1 — [ ] `ChargeBandwidth` + `WithPacketCap` (`internal/limit/limiter.go`)

**Actions:**
- [ ] Add a `pktCap int64` field to `Limiter` (default 0), and the option:

  ```go
  // WithPacketCap sets the per-tunnel/per-direction reads-per-second cap (0 = disabled, the default).
  func WithPacketCap(n int64) Option { return func(l *Limiter) { l.pktCap = n } }
  ```
  Update the `Limiter` struct doc (`limiter.go:12-15`): it no longer carries a token bucket — it holds the
  per-second byte cap `bwRate`, the packet cap `pktCap`, and the day/week caps; and reconcile its
  "Every key's TTL is set in the SAME Lua script as its mutation (or SET EX …)" sentence for the new
  non-Lua windows (e.g. "…each key gets a TTL alongside its mutation — the same Lua script, `SET EX` for
  the cooldown windows, or a pipelined `EXPIRE NX` immediately after the INCR for the `bw:`/`pkt:` per-second
  windows"), matching the ARCHITECTURE §5 / project.md reconciliations.
- [ ] Update the `internal/limit/acme_cooldown.go:2` package doc comment: `… the global stream counter, the
  batch-credit bandwidth bucket, and the per-CA ACME cooldown/backoff.` → replace `batch-credit bandwidth
  bucket` with `per-second bandwidth + packet windows` (else the Task 5.2 `batch-credit` grep would flag it).
- [ ] Delete `claimBandwidthScript` and `ClaimBandwidth` entirely.
- [ ] Add the window TTL const + `ChargeBandwidth`:

  ```go
  // bwWindowTTL outlives a 1-second window (set once via EXPIRE NX on the window's first write) so a write
  // late in the window never expires the counter mid-window; the next second uses a fresh key.
  const bwWindowTTL = 2 * time.Second

  func bwWindowKeys(name, dir string, sec int64) (byteKey, pktKey string) {
  	s := strconv.FormatInt(sec, 10)
  	return "bw:" + name + ":" + dir + ":" + s, "pkt:" + name + ":" + dir + ":" + s
  }

  // ChargeBandwidth records nr bytes and one read against the current 1-second byte + packet windows for
  // (name, dir) in a single pipelined round-trip (INCRBY + INCR + EXPIRE…NX ×2 — no Lua), and reports
  // whether either per-second cap is now exceeded plus the time remaining in the current second (the caller
  // waits that out before the next read). A plain Pipeline (not TxPipeline) is deliberate: these are
  // per-second transient counters and EXPIRE NX self-heals a skipped TTL on the next same-second read, so
  // strict atomicity is unwarranted here (see the Context rationale). The packet cap is skipped when
  // pktCap == 0. A Valkey error returns over=false (fail-open: pacing never hard-depends on the control plane).
  func (l *Limiter) ChargeBandwidth(ctx context.Context, name, dir string, nr int64) (over bool, retryAfter time.Duration, err error) {
  	now := l.now()
  	sec := now.Unix()
  	byteKey, pktKey := bwWindowKeys(name, dir, sec)
  	pipe := l.rdb.Pipeline() // one round-trip; EXPIRE NX sets the TTL, self-healing on the next same-second read
  	bCmd := pipe.IncrBy(ctx, byteKey, nr)
  	pCmd := pipe.Incr(ctx, pktKey)
  	pipe.ExpireNX(ctx, byteKey, bwWindowTTL)
  	pipe.ExpireNX(ctx, pktKey, bwWindowTTL)
  	if _, err := pipe.Exec(ctx); err != nil {
  		return false, 0, err
  	}
  	over = bCmd.Val() > l.bwRate || (l.pktCap > 0 && pCmd.Val() > l.pktCap)
  	if over {
  		retryAfter = time.Unix(sec+1, 0).Sub(now)
  		if retryAfter < 0 {
  			retryAfter = 0
  		}
  	}
  	return over, retryAfter, nil
  }
  ```
  - Keep `strconv` imported (already used by `TrafficExhausted`). Leave `claimTrafficScript`,
    `ClaimTraffic`, `trafficKeys`, `TrafficExhausted` untouched.

**Definition of Done:**
- [ ] The token bucket is gone; `ChargeBandwidth` + `WithPacketCap` exist; the day/week quota is untouched;
  `internal/limit` compiles.

### Task 2.2 — [ ] Limiter tests (`internal/limit/limiter_test.go`)

**Actions:**
- [ ] Remove `TestClaimBandwidthPartialGrantAndRefill` and `TestClaimBandwidth_ClockStepBackNoInflation`
  (token-bucket-specific). Keep all day/week/conc/issuance/CA-cooldown tests unchanged.
- [ ] Update `internal/limit/window_test.go` `TestEveryKeyHasTTLAfterFirstOp` (line ~82): the SACRED
  no-permanent-state invariant test calls the deleted `l.ClaimBandwidth(ctx, "tunnel-x", "in", 1024)` —
  change it to `l.ChargeBandwidth(ctx, "tunnel-x", "in", 1024)`. This now creates BOTH the `bw:` and `pkt:`
  window keys (the `INCRBY`/`INCR` + `EXPIRE NX` run unconditionally), so the test must assert BOTH carry a
  TTL — strengthening the invariant coverage for the new key families.
- [ ] Add the per-second-window tests below (use `miniredis` + `SetClock` for the window second and, where
  needed, `WithPacketCap`).

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestChargeBandwidth_ByteWindowOver` | at the real `1mbit` byte cap, legit ~4 KB reads are byte-capped at ~30 reads/sec: `bwRate=125000`, 4096-byte reads → `over=false` through read 30, `over=true` (`retryAfter>0`) at read 31 (31×4096 > 125000) | fixed clock; `pktCap` large so the byte window is what trips |
| `TestChargeBandwidth_PacketWindowOver` | at the real default `--limit-packets`, a tiny-read flood trips at 100: `WithPacketCap(100)`, huge `bwRate`, 1-byte reads → `over=false` through read 100, `over=true` at read 101 (bytes far under `bwRate`, so the PACKET window is what trips) | fixed clock — proves the flood backstop at the real default value |
| `TestChargeBandwidth_PacketCapDisabled` | `pktCap==0` → many tiny reads never trip on packets (only bytes) | default limiter |
| `TestChargeBandwidth_WindowResetsNextSecond` | advancing the clock one second resets both counts (new keys) | `SetClock` t → t+1s |
| `TestChargeBandwidth_ExpireNXSetsTTLOnce` | the window key's TTL is set on creation and NOT reset by a later same-second write | assert `mr.TTL(key)` after two writes with clock advanced <1s |
| `TestChargeBandwidth_ExpireNXHealsMissingTTL` | a window key left WITHOUT a TTL (simulated orphan) gets a TTL from the NEXT same-second `ChargeBandwidth` — proving the `EXPIRE NX` self-healing the plain-pipeline choice relies on | pre-create `bw:…:{sec}` via a bare `INCR` (no expiry) with the clock fixed; call `ChargeBandwidth`; assert `mr.TTL(key)` is now set |
| `TestChargeBandwidth_FailOpenOnValkeyError` | a closed Valkey → `over=false, err!=nil` | `mr.Close()` before the call |

**Definition of Done:**
- [ ] The bandwidth tests exercise both windows, the reset, the NX-once TTL, and fail-open; the quota tests
  still pass.

---

## User Story 3 — [ ] Edge pacer: charge-per-read + wait-to-next-second (`internal/edge`)

Replace the batch-credit `pace` with a per-read `ChargeBandwidth` + a ctx-aware wait.

**Acceptance criteria:**
- [ ] `bwBatch` and `pace` are GONE; `pacedCopy` reads ≤ `wire.ChunkSize` (16 KiB), charges each read via
  `ChargeBandwidth`, waits `retryAfter` (ctx-aware) when over, then forwards; `ClaimTraffic` + fail-open +
  `rec.Bytes` are unchanged.
- [ ] The `StreamLimiter` interface exposes `ChargeBandwidth` (not `ClaimBandwidth`).

### Task 3.1 — [ ] Rewrite the bandwidth step in `pacedCopy` (`internal/edge/bridge.go`)

**Actions:**
- [ ] Delete the `bwBatch` const and the whole `pace` method.
- [ ] In `pacedCopy`, replace the `credit`/`e.pace(...)` bandwidth step (buffer stays `wire.ChunkSize`, now
  16 KiB) so each read is charged and the wait IS the pacing:

  ```go
  func (e *Edge) pacedCopy(ctx context.Context, name, dir string, dst io.Writer, src io.Reader, as *activeStream, counter *int64) int64 {
  	buf := make([]byte, wire.ChunkSize)
  	for {
  		nr, er := src.Read(buf)
  		if nr > 0 {
  			// Bandwidth pacing: charge this read against the per-second byte + packet windows; if either
  			// cap is now exceeded, wait out the rest of the second (that wait IS the pacing) before
  			// forwarding. A Valkey error fails open (forward unpaced) — never kill a live stream on a blip.
  			if over, wait, berr := e.lim.ChargeBandwidth(ctx, name, dir, int64(nr)); berr == nil && over {
  				select {
  				case <-ctx.Done(): // teardown — abandon the wait, don't hold the copy hostage
  				case <-time.After(wait):
  				}
  			}
  			dayOK, weekOK, terr := e.lim.ClaimTraffic(ctx, name, int64(nr))
  			if terr != nil {
  				dayOK, weekOK = true, true // control-plane blip: fail open (never kill as quota-exhausted)
  			}
  			if !dayOK || !weekOK {
  				win := "day"
  				if !weekOK {
  					win = "week"
  				}
  				e.rec.QuotaExhausted(name, win)
  				return quotaHit
  			}
  			if _, ew := dst.Write(buf[:nr]); ew != nil {
  				return copyWriteErr
  			}
  			atomic.AddInt64(counter, int64(nr))
  			e.rec.Bytes(name, dir, int64(nr))
  			as.lastAct.Store(e.now().UnixNano())
  			as.recent.Add(int64(nr))
  		}
  		if er != nil {
  			return copySrcEOF
  		}
  	}
  }
  ```
  - Update the `pacedCopy` doc comment (`consuming batch-drawn bandwidth credit` → `charging each read
    against the per-second bandwidth windows`). `time` stays imported (the wait). No other change to
    `splice`/the policy watcher/outcome codes.

**Definition of Done:**
- [ ] `bwBatch`/`pace` removed; `pacedCopy` charges per read and paces via the wait; quota + fail-open intact.

### Task 3.2 — [ ] `StreamLimiter` interface (`internal/edge/edge.go`)

**Actions:**
- [ ] Replace the bandwidth method on the consumer-site interface:

  ```go
  ChargeBandwidth(ctx context.Context, name, dir string, nr int64) (over bool, retryAfter time.Duration, err error)
  ```
  (keep `ClaimTraffic` and `TrafficExhausted`; the `var _ StreamLimiter = (*limit.Limiter)(nil)` assertion
  now checks the new method). `time` is already imported by `edge.go`.

**Definition of Done:**
- [ ] `StreamLimiter` exposes `ChargeBandwidth`; `*limit.Limiter` satisfies it.

### Task 3.3 — [ ] Edge tests (`internal/edge/*_test.go`)

**Actions:**
- [ ] `countingLimiter` (`fixes_test.go:542`) embeds `*limit.Limiter` and defines only `AcquireStream`/
  `ReleaseStream`, so it inherits the real `ChargeBandwidth` automatically (no `ClaimBandwidth` method exists
  to replace). Add a CONTROLLABLE `ChargeBandwidth` override on it — configurable `chargeOver bool`,
  `chargeWait time.Duration`, `chargeErr error` fields (default zero → `(false, 0, nil)`, i.e. never paces)
  — and use that override as the stub for the three new tests below.
- [ ] Remove `TestEdge_Pace_BatchCredit` and `TestEdge_Pace_EmptyBucketBlocks` (the `pace` method is gone).
- [ ] Update `TestEdge_PacedCopy_TrafficErrorFailsOpen`: with the real limiter and `mr.Close()`, BOTH
  `ChargeBandwidth` and `ClaimTraffic` error → the copy must still forward all bytes and fire no
  `QuotaExhausted` (it already asserts this; confirm it holds with the new charge call in front).
- [ ] The existing `NewLimiter(...)` calls in the edge tests need NO change (packet cap defaults to 0 via
  the option). Add the two new tests below.

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestEdge_PacedCopy_WaitsWhenOverCap` | when `ChargeBandwidth` reports `over` with a small `retryAfter`, `pacedCopy` waits ~that long before forwarding (then delivers all bytes) | `countingLimiter` override `chargeOver=true, chargeWait=40ms`; assert elapsed ≥ ~40ms and bytes delivered |
| `TestEdge_PacedCopy_CtxCancelAbandonsWait` | ctx cancellation during a pacing wait unblocks `pacedCopy` PROMPTLY (teardown/eviction must not wait out the full second) | `countingLimiter` override `chargeOver=true, chargeWait=5s`; cancel the ctx mid-wait; assert `pacedCopy` returns well under 5s |
| `TestEdge_PacedCopy_ChargeErrorFailsOpen` | a `ChargeBandwidth` error forwards the chunk unpaced (no wait, bytes flow) | `countingLimiter` override `chargeErr!=nil`; assert no wait, full copy |

**Definition of Done:**
- [ ] The fake + tests use `ChargeBandwidth`; the wait and fail-open paths are covered; the pace tests are gone.

---

## User Story 4 — [ ] Wire the packet cap into the server + test configs (`internal/server`, `e2e`)

**Acceptance criteria:**
- [ ] `server.Run` builds the limiter with `WithPacketCap(int64(cfg.LimitPackets))`.
- [ ] Every `config.ServeCmd` test literal sets `LimitPackets` so the data plane / `Validate()` are exercised
  with a real (non-throttling) packet cap.

### Task 4.1 — [ ] Server assembly (`internal/server/server.go`)

**Actions:**
- [ ] Pass the packet cap as an option (the positional `NewLimiter` signature is unchanged):

  ```go
  lim := limit.NewLimiter(rdb, bwRate, dayCap, weekCap, 3*cfg.LimitConnIdle,
  	limit.WithLogger(logger), limit.WithPacketCap(int64(cfg.LimitPackets)))
  ```

**Definition of Done:**
- [ ] The production limiter carries the configured packet cap.

### Task 4.2 — [ ] Set `LimitPackets` in every `ServeCmd` test literal

**Actions:**
- [ ] Add `LimitPackets: <value>` to each `config.ServeCmd` literal (a value well above what the test
  generates, so the packet cap never throttles legit test traffic):
  - `e2e/e2e_test.go` `runReplicaOnce` — `LimitPackets: 100000` (the device `/wait` throughput + high
    bandwidth/concurrency must not be packet-throttled). `cfg.Validate()` there requires it > 0.
  - `internal/server/server_test.go` `lifecycleConfig` — `LimitPackets: 100000`.
  - `internal/server/integration_test.go` — the assembled-server config(s) — `LimitPackets: 100000`.
  - `internal/server/acmewire_test.go`, `internal/server/schedulers_test.go` — any `ServeCmd` literal →
    `LimitPackets: 100000` (harmless where the field is unused; keeps them realistic).
  - (`internal/config/config_test.go` is handled in Task 1.3.)
- [ ] Reword the stale token-bucket comment in `e2e/tunnel_app_test.go` (line ~40): `… share the tunnel's
  per-direction bw bucket, sized above via replicaOpts.bandwidth …` → `… share the tunnel's per-direction
  per-second bandwidth window, sized above via replicaOpts.bandwidth …` (there is no longer a bandwidth
  "bucket").

**Definition of Done:**
- [ ] Every `ServeCmd` literal sets `LimitPackets`; no e2e/integration test is packet-throttled; the
  `e2e/tunnel_app_test.go` bandwidth comment uses the per-second-window terminology.

---

## User Story 5 — [ ] Documentation + ground-up verification

**Acceptance criteria:**
- [ ] `docs/ARCHITECTURE.md`, `docs/PROJECT.md`, `docs/PROTOCOL.md`, `README.md`, and `.claude/rules/project.md`
  describe the per-second byte + packet window model (no token bucket / batch credit), `ChunkSize == 16384`,
  and `--limit-packets`; no stale batch-credit/token-bucket/single-Lua residue remains on any live surface.
- [ ] Everything verified from the ground up; all quality gates green.

### Task 5.1 — [ ] Docs

**Actions:**
- [ ] `docs/ARCHITECTURE.md` §4 "Bandwidth model" — rewrite: per-tunnel/per-direction **per-second fixed
  windows** (`bw:{name}:{dir}:{sec}` bytes + `pkt:{name}:{dir}:{sec}` reads), one plain **pipelined**
  `INCRBY`/`INCR` + `EXPIRE 2s NX` per read (NO Lua; `EXPIRE NX` self-heals a skipped TTL on the next
  same-second read, so strict atomicity is unwarranted for these transient windows); over either cap → wait
  to the next second (the wait IS the pacing); Valkey error fails open; read slice `wire.ChunkSize` =
  **16384**; day/week quota unchanged; overshoot bound `byteCap + N_conn × 16 KiB` / `pktCap + N_conn`.
- [ ] `docs/ARCHITECTURE.md` — the two OTHER batch-credit mentions outside §4: line ~59 (the `internal/limit`
  package table row `… batch-credit bandwidth bucket …`) and line ~90 (the lifecycle text `paces bandwidth
  from the shared batch-credit bucket`) → reword to the per-second byte + packet windows.
- [ ] `docs/ARCHITECTURE.md` §5 heading (line ~114): `## 5. Valkey state (all transient — TTL atomic with the
  write, single Lua)` → reconcile the "single Lua" claim with the new non-Lua windows (e.g. `… every key
  TTL'd alongside its write — single Lua, or a pipelined EXPIRE NX for the bw:/pkt: windows`), matching the
  `.claude/rules/project.md` state-invariant reconciliation above so the two canonical docs stay consistent.
- [ ] `docs/PROJECT.md` — the caps table (`--limit-bandwidth` floor `≥ 32768` → `≥ 16384`; add a
  `--limit-packets` row); the non-goals line `No per-slice-exact bandwidth accounting (batch-credit draws).`
  → reword for the fixed-window model (e.g. `No cross-replica exact bandwidth accounting (per-second
  fixed windows; bounded overshoot).`).
- [ ] `README.md` — the "Caps" table (lines ~97-105) enumerates every `--limit-*` knob; add a
  `--limit-packets` row (default `100`, per tunnel per direction), consistent with the PROJECT.md caps table.
- [ ] `docs/PROJECT.md` §5 "State + retention" (lines ~118-120): the Valkey bullet lists the key families and
  states "Every key carries a TTL set **atomically with its write**. No permanent Valkey state." — the new
  `bw:`/`pkt:` windows TTL via a pipelined `EXPIRE NX` (not atomic with the `INCR`), so reconcile it the same
  way as the other three surfaces (§5 heading, `.claude/rules/project.md`, `limiter.go` struct doc): reword to
  "Every key gets a TTL alongside its write — set atomically in the same Lua script / `SET EX`, or via a
  pipelined `EXPIRE NX` right after the `INCR` for the self-healing transient `bw:`/`pkt:` per-second windows.
  No permanent Valkey state." Add the `bw:`/`pkt:` bandwidth windows to the key enumeration on line 118.
- [ ] `docs/PROTOCOL.md` — the two `wire.ChunkSize`/`ChunkSize == 32768` references (≈ lines 160, 184) →
  `16384`, keeping the "paced-copy slice size only, not wire framing" wording.
- [ ] `.claude/rules/project.md` — rewrite the **Bandwidth model** invariant (lines ~127-136: token bucket /
  1 MB batch / `bw:{name}:{dir}` → the per-second byte + packet windows, plain pipelined `INCRBY`/`INCR` +
  `EXPIRE 2s NX`, no Lua, fail-open, 16 KiB read slice, `--limit-packets`); update the two other
  `wire.ChunkSize = 32768` mentions (the E2E and Wire-protocol invariant blocks) → 16384; update the Rule Map
  scope row (line ~186: `… batch-credit bandwidth …` → `… per-second bandwidth+packet windows …`); add
  `--limit-packets` where the `--limit-*` surface is noted. Keep the `conc:{name}` TTL-refresh and day/week
  wording intact, AND preserve the still-valid safety invariant "The blocking [refill] wait MUST NEVER be
  held under a connection write mutex" (adapt "refill wait" → the per-second wait; it is still a blocking
  wait that must never be held under a connection write mutex).
- [ ] `.claude/rules/project.md` — the SACRED "Valkey (transient) + S3 (durable) state" invariant (lines
  ~108-110) says every key "carries a TTL set **atomically in the SAME Lua script** as its INCR/HINCRBY/SET."
  Reconcile it — WITHOUT weakening the no-permanent-state guarantee, and making clear the required rigor is
  use-case-dependent: reword to "…each key gets a TTL alongside its mutation — set atomically in the same Lua
  script (or `SET EX`), OR, for the transient per-second `bw:`/`pkt:` bandwidth windows, via a pipelined
  `EXPIRE NX` right after the `INCR`: `EXPIRE NX` self-heals a skipped TTL on the next same-second write, so
  a plain pipeline (not `TxPipeline`/Lua) is the correct, simpler tool for these self-healing transient
  counters — strict single-script atomicity is required only where an orphaned key would actually matter."

**Definition of Done:**
- [ ] All four docs reflect the fixed-window model, `ChunkSize == 16384`, and `--limit-packets`; no stale
  token-bucket / batch-credit / 32768 language remains for the bandwidth path.

### Task 5.2 — [ ] Final ground-up verification (double-check EVERYTHING)

**Actions:**
- [ ] Re-read this plan top to bottom; confirm every task/action + acceptance criterion is implemented.
- [ ] Confirm the token bucket is fully removed: `grep -rn 'ClaimBandwidth\|claimBandwidthScript\|bwBatch\|func (e \*Edge) pace' internal/` returns nothing.
- [ ] Confirm NO Lua in the bandwidth path: `ChargeBandwidth` uses a pipeline (no `redis.NewScript`); the
  only remaining `redis.NewScript` in `internal/limit` are the UNCHANGED quota/bind/self-heal scripts.
- [ ] Confirm `wire.ChunkSize == 16384` and every reference (config floor, metrics estimate + its test, the
  `ChunkSize` assertion test, the four docs) matches. Verify over the LIVE surfaces ONLY — NEVER edit the
  sacred `docs/plans/` artifacts (agent.md §2):
  - `grep -rn '32 \* 1024' internal/ .claude/ docs/PROJECT.md docs/ARCHITECTURE.md docs/PROTOCOL.md README.md`
    returns nothing (the const forms are all now `16 * 1024`).
  - `grep -rn '32768' internal/ .claude/ docs/PROJECT.md docs/ARCHITECTURE.md docs/PROTOCOL.md README.md`
    returns ONLY the deliberately-retained `tunneld_per_conn_mem_bytes 32768` in
    `internal/metrics/metrics_test.go` (= `2 × ChunkSize` = `2 × 16384`); no stale ChunkSize/floor `32768`.
  - `grep -rniE 'batch-credit|token bucket|bw bucket|ClaimBandwidth|bwBatch|refill' internal/ e2e/ client/
    .claude/ docs/PROJECT.md docs/ARCHITECTURE.md docs/PROTOCOL.md README.md` returns nothing. (These are
    the token-bucket-specific terms; the generic word `bucket` is intentionally NOT grepped — it legitimately
    names S3 buckets and the rate-limit `window.go` window.)
- [ ] Confirm the atomic-TTL invariant is RECONCILED (not left contradictory) on ALL FOUR live surfaces —
  `.claude/rules/project.md` state-invariant, `docs/ARCHITECTURE.md` §5 heading, `docs/PROJECT.md` §5, and
  `internal/limit/limiter.go` struct doc: `grep -rniE 'atomically with its write|TTL atomic with the write|
  atomically in the SAME Lua' .claude/ docs/PROJECT.md docs/ARCHITECTURE.md` returns no UNQUALIFIED claim
  (each must now name the pipelined `EXPIRE NX` path for the `bw:`/`pkt:` windows); `grep -rniE 'TxPipeline'
  internal/ .claude/ docs/` returns nothing.
- [ ] Confirm `--limit-packets` is wired end-to-end (flag → `Validate` → `WithPacketCap` → `ChargeBandwidth`)
  and per-direction; the byte rate stays the primary limit; fail-open preserved.
- [ ] Run the FULL quality gates (`make build vet lint govulncheck test-unit test-integration test-e2e
  test-scripts compose-config` + `make tidy`), capturing logs per the tee rule. `test-e2e` MUST pass,
  including the throughput-sensitive `TestE2E_ReferenceTunnelApp` `/wait` load (with a device) and
  `TestE2E_Quota` (quota still cuts via the unchanged day/week counter).
- [ ] Confirm hygiene: no AI attribution, no plan/finding IDs in code or commit messages, placeholders only,
  and NO out-of-scope files changed.

**Definition of Done:**
- [ ] All gates pass on the final code; the token bucket is gone; the fixed-window pacer + packet cap work
  end-to-end; the ground-up re-read finds zero gaps.

---

## Deviations

_(recorded during implementation per agent.md §2)_
