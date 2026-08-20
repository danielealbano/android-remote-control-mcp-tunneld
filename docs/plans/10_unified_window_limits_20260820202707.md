<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 10 — Unified per-window limits + live-tunnel counter reset on (re)bind

Two changes, both agreed in the design discussion:

1. **Unify day/week traffic onto the per-second window mechanism.** Fold the Lua `ClaimTraffic` into the
   plain-pipeline charge (the same one Plan 9 built for bandwidth): one `INCRBY`/`INCR` + `EXPIRE … NX`
   round-trip covering ALL four counters — byte/sec, packet/sec, traffic/day, traffic/week — with ONE
   enforcement rule: over a cap → **wait** if that window resets within `maxPacingWait` (**5 s**), else
   **kill** the connection. Traffic becomes **per-direction** (aligned with bandwidth) and uses
   **clock-aligned timestamped keys**. **NO Lua**, **NO `TxPipeline`/MULTI-EXEC** — plain `Pipeline` only.
2. **Reset live-tunnel-scoped counters on phone (re)bind.** When the phone (re)establishes its control
   connection, `DEL conc:{name}` — a fresh phone connection means all prior streams are dead, so the
   concurrent-stream count is implicitly zero. The current TTL-only healing (3 × `--limit-conn-idle` ≈ 6 min,
   and it under-heals a busy tunnel because new traffic keeps refreshing the leaked count) is not enough.

## Context & key decisions (the decision record — not derivable from code)

- **The live-vs-identity reset invariant (the load-bearing principle).** Caps split in two, and they behave
  oppositely on tunnel death:
  - **Live-tunnel-scoped** — counts of *currently-open* things (`conc:{name}` concurrent streams). If the
    tunnel dies, these are implicitly zero → **reset on (re)bind**.
  - **Identity-scoped cumulative quotas** — total volume/issuance per tunnel *name* (`traf:` day/week,
    issuance/`--issue-per-week`). These **MUST persist** across reconnects, or a tunnel resets its quota just
    by reconnecting. The reset MUST hit `conc:{name}` and MUST NOT touch the `traf:` counters.
- **One charge, one enforcement rule.** `Charge(ctx, name, dir, nr)` charges every per-window counter in a
  single plain-pipeline round-trip and returns an action: `Proceed` (under all caps → forward now), `Wait`
  (over a cap whose window resets within `maxPacingWait` → wait that long, then forward), or `Kill` (over a
  cap whose window resets beyond `maxPacingWait` → end the stream, with the window label for the metric).
  Bandwidth is the always-`Wait` case (a per-second window resets in ≤ 1 s ≤ 5 s); day/week are almost always
  `Kill` (reset hours/days away) except in the last ≤ 5 s of a window. `Kill` takes precedence over `Wait`
  (an exhausted far window can't be waited out). A Valkey error → `Proceed` (fail-open, unchanged contract).
- **Plain pipeline, no Lua, no TxPipeline.** Same rationale as Plan 9: `INCR`/`EXPIRE NX` can't fail
  singularly and `EXPIRE NX` self-heals a skipped TTL on the next same-window write. The orphan risk is
  *lower* than bandwidth here (far fewer key creations: ~1 day-key + ~1 week-key per tunnel per window vs
  thousands of per-second keys). Cross-counter atomicity is not needed — a torn pipeline skews the ledger by
  a few bytes at worst.
- **Per-direction traffic + clock-aligned timestamped keys.** Keys: `bw:{name}:{dir}:{unix_second}`,
  `pkt:{name}:{dir}:{unix_second}` (unchanged from Plan 9), and NEW `traf:{name}:{dir}:day:{unix_day}` /
  `traf:{name}:{dir}:week:{unix_week}` where `unix_day = unix_second / 86400` and `unix_week = unix_day / 7`.
  Clock-aligned so the window reset is computed from the clock (no `PTTL` read) and old windows roll off.
  Day/week windows are UTC-midnight-aligned days and epoch-aligned 7-day blocks. Each key's TTL is its
  window duration plus a small fixed **1 h** margin (day = **25 h**, week = **7 d + 1 h**) — enough that a
  write anywhere in a window (worst case: the first write at the window start) never expires the counter
  mid-window, without needlessly lingering (the key is dead weight after its window; the next window is a
  new key). NOT a 2× multiplier — a 14-day TTL on a 7-day counter would just waste memory. **Semantics
  change:** `--limit-traffic-day/week` become **per-direction** (default `1gb` = 1 GB up AND 1 GB down);
  nothing is deployed, so it is a free cutover.
- **`conc:` reset placement.** In `phoneconn.Manager.register`, after a successful `BindRoute` (we own the
  route) and BEFORE the conn is published to `m.conns` — inside the existing per-name `bindLock`. At that
  point the route resolves to this node but the local conn is not yet serviceable, so no legitimate stream
  can have acquired a slot for THIS connection; the only increments present are leaked ones from the dead
  prior owner. A reset error is logged and ignored (the `conc:` TTL remains the secondary backstop).
- **`conc:` TTL keeps working.** The TTL (`3 × --limit-conn-idle`, set by `AcquireStream`) stays as the
  crash backstop for the tunnel-truly-gone case; its per-traffic refresh moves from the deleted `ClaimTraffic`
  Lua into the `Charge` pipeline (a `PEXPIRE conc:{name}` — a no-op on a missing key, so a torn-down counter
  is never resurrected).
- **`maxPacingWait = 5 s`** (constant, not a flag). The admission-time quota gate (`TrafficExhausted`,
  read-only) is KEPT so an already-exhausted tunnel does not start a doomed stream.

Ground-truth sources this plan mirrors: `internal/limit/limiter.go` + `concurrency.go` + `window.go`,
`internal/edge/bridge.go` + `edge.go`, `internal/phoneconn/manager.go`, `internal/server/server.go`,
`internal/config/config.go`, and the model docs (`docs/ARCHITECTURE.md` §4/§5, `docs/PROJECT.md`,
`.claude/rules/project.md`).

---

## User Story 1 — [x] Unified per-window charge + `conc:` reset in the limiter (`internal/limit`)

Replace `ChargeBandwidth` (Plan 9) and `ClaimTraffic` (+ its Lua) with a single `Charge` covering all four
per-window counters; make traffic per-direction + clock-aligned; add `ResetStreams`.

**Acceptance criteria:**
- [x] `ClaimTraffic`, `claimTrafficScript`, `trafficKeys`, `ChargeBandwidth`, and `bwWindowKeys` are GONE.
- [x] `Charge(ctx, name, dir, nr)` does ONE plain pipelined round-trip — `INCRBY bw` + `INCR pkt` +
  `INCRBY traf-day` + `INCRBY traf-week` + `EXPIRE 2s NX`×2 + `EXPIRE 25h/(7d+1h) NX`×2 + `PEXPIRE conc` (no Lua,
  no `TxPipeline`) — and returns `(action ChargeAction, wait time.Duration, window string, err error)` per the
  rule in Context. A Valkey error → `(ChargeProceed, 0, "", err)` (fail-open).
- [x] `TrafficExhausted(ctx, name)` reflects the per-direction timestamped keys (day/week over in EITHER
  direction ⇒ over).
- [x] `ResetStreams(ctx, name)` deletes `conc:{name}`.
- [x] `AcquireStream`/`ReleaseStream` and the `conc:{name}` TTL are otherwise UNCHANGED; the day/week caps
  (`dayCap`/`weekCap`) persist across reconnects (never reset by `ResetStreams`).

### Task 1.1 — [x] `ChargeAction` + `Charge` + consts + keys (`internal/limit/limiter.go`)

**Actions:**
- [x] Replace `bwWindowTTL`/`bwWindowKeys`/`ChargeBandwidth` and delete `claimBandwidthScript` is already
  gone (Plan 9); now delete `claimTrafficScript`, `trafficKeys`, and `ClaimTraffic`. Add the unified action
  type, the window constants, the key helper, and `Charge`:

  ```go
  // ChargeAction is the caller's instruction after charging a read against every per-window counter.
  type ChargeAction int

  const (
  	ChargeProceed ChargeAction = iota // under all caps (or a fail-open Valkey error) → forward now
  	ChargeWait                        // over a cap whose window resets within maxPacingWait → wait, then forward
  	ChargeKill                        // over a cap whose window resets beyond maxPacingWait → end the stream
  )

  const (
  	bwWindowTTL   = 2 * time.Second    // per-second byte/packet windows (2× the 1s window)
  	trafDayTTL    = 25 * time.Hour            // 24h window + 1h margin so a write never expires the counter mid-window
  	trafWeekTTL   = 7*24*time.Hour + time.Hour // 7d window + 1h margin (a small fixed margin, NOT 2× — the key is dead weight after its window)
  	maxPacingWait = 5 * time.Second    // over a cap resetting within this → wait; else kill
  )

  // chargeKeys builds the four per-window keys for (name, dir) at unix second `sec`. Day/week are
  // clock-aligned: unix_day = sec/86400 (UTC-midnight days), unix_week = unix_day/7 (epoch-aligned 7-day
  // blocks) — so the window reset is computed from the clock, no PTTL read, and old windows roll off.
  func chargeKeys(name, dir string, sec int64) (bwKey, pktKey, dayKey, weekKey string) {
  	s := strconv.FormatInt(sec, 10)
  	d := strconv.FormatInt(sec/86400, 10)
  	w := strconv.FormatInt(sec/86400/7, 10)
  	base := name + ":" + dir
  	return "bw:" + base + ":" + s, "pkt:" + base + ":" + s,
  		"traf:" + base + ":day:" + d, "traf:" + base + ":week:" + w
  }

  // Charge records nr bytes + one read against the per-second byte/packet windows AND the per-day/week
  // traffic windows for (name, dir) in a single plain pipelined round-trip (INCRBY/INCR + EXPIRE…NX — no
  // Lua, no TxPipeline; EXPIRE NX self-heals a skipped TTL on the next same-window write), refreshes the
  // conc:{name} TTL, and returns the enforcement action. Kill takes precedence over Wait (an exhausted far
  // window can't be waited out); the returned window ("day"/"week") labels a Kill for the metric. The
  // packet cap is skipped when pktCap==0. A Valkey error returns ChargeProceed (fail-open).
  func (l *Limiter) Charge(ctx context.Context, name, dir string, nr int64) (ChargeAction, time.Duration, string, error) {
  	now := l.now()
  	sec := now.Unix()
  	bwKey, pktKey, dayKey, weekKey := chargeKeys(name, dir, sec)
  	pipe := l.rdb.Pipeline() // plain pipeline, one round-trip; EXPIRE NX self-heals TTLs on the next same-window write
  	bCmd := pipe.IncrBy(ctx, bwKey, nr)
  	pCmd := pipe.Incr(ctx, pktKey)
  	dCmd := pipe.IncrBy(ctx, dayKey, nr)
  	wCmd := pipe.IncrBy(ctx, weekKey, nr)
  	pipe.ExpireNX(ctx, bwKey, bwWindowTTL)
  	pipe.ExpireNX(ctx, pktKey, bwWindowTTL)
  	pipe.ExpireNX(ctx, dayKey, trafDayTTL)
  	pipe.ExpireNX(ctx, weekKey, trafWeekTTL)
  	pipe.PExpire(ctx, "conc:"+name, l.streamTTL) // refresh the live-stream counter TTL (no-op on a missing key)
  	if _, err := pipe.Exec(ctx); err != nil {
  		return ChargeProceed, 0, "", err // fail-open
  	}

  	secReset := time.Unix(sec+1, 0).Sub(now)
  	dayReset := time.Unix((sec/86400+1)*86400, 0).Sub(now)
  	weekReset := time.Unix((sec/86400/7+1)*7*86400, 0).Sub(now)

  	overSec := bCmd.Val() > l.bwRate || (l.pktCap > 0 && pCmd.Val() > l.pktCap)
  	dayOver := dCmd.Val() > l.dayCap
  	weekOver := wCmd.Val() > l.weekCap

  	// Kill precedence: a volume window over its cap that resets beyond maxPacingWait cannot be waited out.
  	if weekOver && weekReset > maxPacingWait {
  		return ChargeKill, 0, "week", nil
  	}
  	if dayOver && dayReset > maxPacingWait {
  		return ChargeKill, 0, "day", nil
  	}
  	// Otherwise wait for the furthest over-window that resets within maxPacingWait.
  	wait := time.Duration(0)
  	if overSec && secReset > wait {
  		wait = secReset
  	}
  	if dayOver && dayReset > wait {
  		wait = dayReset
  	}
  	if weekOver && weekReset > wait {
  		wait = weekReset
  	}
  	if wait > 0 {
  		return ChargeWait, wait, "", nil
  	}
  	return ChargeProceed, 0, "", nil
  }
  ```
  - `strconv` and `time` are already imported. Leave `AcquireStream`/`ReleaseStream`/`acquireScript`/
    `releaseScript` (concurrency.go) and the rate-window/issuance/ACME code untouched.
- [x] Fix the now-stale limiter doc comments that the change invalidates:
  - The `Limiter` struct doc (`limiter.go:12-17`) attributes the pipelined `EXPIRE NX` TTL path to "the
    **bw:/pkt: per-second bandwidth windows** … (self-healing on the next same-second write; see
    **ChargeBandwidth**)." Broaden it: `traf:` day/week now use the SAME pipelined `EXPIRE NX` (the Lua is
    deleted), so reword to "…for the **bw:/pkt: per-second and traf: day/week windows** (self-healing on the
    next same-window write; see **Charge**)." No live-surface comment may imply traffic still uses Lua.
  - The `NewLimiter` doc (`limiter.go:38-40`) says "dayCap/weekCap are the **combined-direction** traffic
    caps in bytes" → "**per-direction** traffic caps in bytes".

**Definition of Done:**
- [x] `Charge` compiles; the old bandwidth + traffic entry points are gone; the struct/`NewLimiter` docs read
  `Charge` / per-direction; `internal/limit` builds.

### Task 1.2 — [x] `TrafficExhausted` (per-direction) + `ResetStreams` (`internal/limit/limiter.go`)

**Actions:**
- [x] Rewrite `TrafficExhausted` for the per-direction timestamped keys (admission gate — no mutation): it is
  over when EITHER direction's current day or week counter is at/over its cap.

  ```go
  // TrafficExhausted reports whether the tunnel's current day/week window is at/over its cap in EITHER
  // direction — the admission-time gate (no mutation): a new stream is refused when no further byte could
  // be accepted. Clock-aligned to the same windows Charge writes.
  func (l *Limiter) TrafficExhausted(ctx context.Context, name string) (dayOver, weekOver bool, err error) {
  	sec := l.now().Unix()
  	d := strconv.FormatInt(sec/86400, 10)
  	w := strconv.FormatInt(sec/86400/7, 10)
  	keys := []string{
  		"traf:" + name + ":in:day:" + d, "traf:" + name + ":out:day:" + d,
  		"traf:" + name + ":in:week:" + w, "traf:" + name + ":out:week:" + w,
  	}
  	vals, err := l.rdb.MGet(ctx, keys...).Result()
  	if err != nil {
  		return false, false, err
  	}
  	dayOver = atoiCap(vals[0]) >= l.dayCap || atoiCap(vals[1]) >= l.dayCap
  	weekOver = atoiCap(vals[2]) >= l.weekCap || atoiCap(vals[3]) >= l.weekCap
  	return dayOver, weekOver, nil
  }
  ```
  Reuse the existing string→int64 parse from the current `TrafficExhausted` (extract it to a small
  `atoiCap(any) int64` helper if it is currently an inline closure, so the four per-direction lookups in
  `TrafficExhausted` share one parse helper — `Charge` reads counts via `cmd.Val()` and needs no parsing).
- [x] Add `ResetStreams` (the live-tunnel reset — DELETES the concurrency counter ONLY):

  ```go
  // ResetStreams clears the live concurrent-stream counter for name (conc:{name}) — called when the phone
  // (re)binds, because a fresh phone connection means all prior streams are dead. It NEVER touches the
  // identity-scoped traf: day/week quotas (those must persist across reconnects).
  func (l *Limiter) ResetStreams(ctx context.Context, name string) error {
  	return l.rdb.Del(ctx, "conc:"+name).Err()
  }
  ```

**Definition of Done:**
- [x] `TrafficExhausted` reads the per-direction timestamped keys; `ResetStreams` deletes only `conc:{name}`.

### Task 1.3 — [x] Limiter tests (`internal/limit/limiter_test.go`, `window_test.go`)

**Actions:**
- [x] Replace the Plan-9 `TestChargeBandwidth_*` tests and any `ClaimTraffic`/`TrafficExhausted` tests with
  the unified `Charge` tests below (use `miniredis` + a settable clock; reuse `newWindowLimiter`, extending
  it with day/week caps as needed).
- [x] Update `window_test.go` `TestEveryKeyHasTTLAfterFirstOp`: the `Charge` call now creates `bw:`, `pkt:`,
  `traf:…:day`, `traf:…:week` (all EXPIRE-NX'd) — assert every one carries a TTL (the SACRED invariant now
  covers the traffic windows too). Replace its `ClaimTraffic` call with a single `Charge`.

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestCharge_ByteWindowWaits` | over `bwRate` in one second → `ChargeWait`, `wait>0` (≤1s); under → `ChargeProceed` | 1mbit; 4 KB reads → 31st trips; pktCap disabled |
| `TestCharge_PacketWindowWaits` | over `pktCap` (100) → `ChargeWait`; under → `ChargeProceed` | huge bwRate; 1-byte reads → 101st trips |
| `TestCharge_DayCapKillsWhenResetFar` | day over with reset ≫ 5s → `ChargeKill`, `window=="day"` | small dayCap; fixed clock mid-day; per-direction |
| `TestCharge_WeekCapKillsAndPrecedesDay` | week over (reset far) → `ChargeKill`, `window=="week"` even if day also over | small weekCap |
| `TestCharge_DayCapWaitsNearBoundary` | day over with reset ≤ 5s → `ChargeWait` (not kill) | fixed clock set to `dayEnd − 3s` |
| `TestCharge_PerDirectionIsolated` | charging `in` does not trip the `out` day counter | separate `in`/`out` keys |
| `TestCharge_ExpireNXHealsMissingTTL` | a `traf:` key left un-TTL'd (bare INCR) gets a TTL from the next `Charge` | white-box `l.rdb.Incr`; assert `mr.TTL` |
| `TestCharge_FailOpenOnValkeyError` | closed Valkey → `ChargeProceed`, `err!=nil` | `mr.Close()` |
| `TestTrafficExhausted_PerDirection` | day/week over in EITHER direction ⇒ over; read-only (no mutation) | seed one direction's key past cap |
| `TestResetStreams_DeletesConcOnly` | `ResetStreams` DELs `conc:{name}`; a seeded `traf:` day key SURVIVES | seed `conc:` + `traf:`; assert conc gone, traf intact |
| `TestCharge_RefreshesConcTTLOnlyIfExists` | the `Charge` pipeline's `PEXPIRE conc:{name}` refreshes an EXISTING conc TTL to `streamTTL` but is a NO-OP on a missing key (a torn-down counter is never resurrected) — replaces the deleted `TestClaimTraffic_RefreshesConcTTLOnlyIfExists` | pre-seed `conc:` via `AcquireStream` then `Charge` → TTL refreshed; separately `Charge` with no prior `conc:` → assert `conc:{name}` was NOT created |

**Definition of Done:**
- [x] `Charge`'s proceed/wait/kill (day + week + per-second), per-direction isolation, NX self-heal, fail-open,
  `TrafficExhausted` per-direction, and `ResetStreams`-deletes-only-conc are all covered; the TTL invariant
  test covers the traffic windows.

---

## User Story 2 — [x] Edge: unified `Charge` enforcement (`internal/edge`)

Replace the two per-read limiter calls (`ChargeBandwidth` + `ClaimTraffic`) with the single `Charge`; keep
the admission gate.

**Acceptance criteria:**
- [x] `pacedCopy` calls `Charge` once per read and acts on the returned action: `ChargeProceed` → forward;
  `ChargeWait` → ctx-aware wait then forward; `ChargeKill` → `rec.QuotaExhausted(name, window)` + return
  `quotaHit`. Fail-open (a `Charge` error → `ChargeProceed` → forward unpaced). `rec.Bytes` + the
  activity/rolling-rate accounting are unchanged.
- [x] `StreamLimiter` exposes `Charge` + `TrafficExhausted` (no `ChargeBandwidth`, no `ClaimTraffic`).

### Task 2.1 — [x] Rewrite `pacedCopy` (`internal/edge/bridge.go`)

**Actions:**
- [x] Replace the `ChargeBandwidth`+wait and the `ClaimTraffic`+quota blocks with a single `Charge` switch:

  ```go
  		if nr > 0 {
  			// One charge covers the per-second bandwidth windows AND the day/week traffic quotas. Proceed →
  			// forward; Wait → pace out the rest of the (near) window then forward; Kill → the tunnel exceeded
  			// a day/week cap whose reset is too far to wait out. A Valkey error yields Proceed (fail-open —
  			// never kill a live stream on a control-plane blip).
  			if action, wait, win, cerr := e.lim.Charge(ctx, name, dir, int64(nr)); cerr == nil {
  				switch action {
  				case limit.ChargeWait:
  					select {
  					case <-ctx.Done(): // teardown — abandon the wait, don't hold the copy hostage
  					case <-time.After(wait):
  					}
  				case limit.ChargeKill:
  					e.rec.QuotaExhausted(name, win)
  					return quotaHit
  				}
  			}
  			if _, ew := dst.Write(buf[:nr]); ew != nil {
  				return copyWriteErr
  			}
  			atomic.AddInt64(counter, int64(nr))
  			e.rec.Bytes(name, dir, int64(nr))
  			as.lastAct.Store(e.now().UnixNano())
  			as.recent.Add(int64(nr))
  		}
  ```
  - Add the `internal/limit` import to `bridge.go` (for `limit.ChargeWait`/`ChargeKill`) if not present.
    Update the `pacedCopy` doc comment to describe the single unified charge. `time` stays imported.
- [x] Update the stale `handleTunnel` admission-gate comment (`bridge.go:127-129`): "in-flight streams are
  closed by the splice's **ClaimTraffic** accounting" → "…by the splice's **Charge** accounting".

**Definition of Done:**
- [x] `pacedCopy` uses one `Charge`; wait / kill / proceed / fail-open all wired; accounting unchanged.

### Task 2.2 — [x] `StreamLimiter` interface (`internal/edge/edge.go`)

**Actions:**
- [x] Replace the two methods with the unified one (keep `TrafficExhausted`, `AcquireStream`,
  `ReleaseStream`, `Allow`):

  ```go
  Charge(ctx context.Context, name, dir string, nr int64) (action limit.ChargeAction, wait time.Duration, window string, err error)
  ```
  Remove `ChargeBandwidth` and `ClaimTraffic` from the interface. Import `internal/limit` in `edge.go` for
  `limit.ChargeAction` (the package is already imported for the `var _ StreamLimiter = (*limit.Limiter)(nil)`
  assertion). `time` is already imported.

**Definition of Done:**
- [x] `StreamLimiter` exposes `Charge`; `*limit.Limiter` satisfies it.

### Task 2.3 — [x] Edge tests (`internal/edge/*_test.go`)

**Actions:**
- [x] Update the `countingLimiter` fake: replace its `ChargeBandwidth` override with a `Charge` override
  driven by configurable `chargeAction limit.ChargeAction`, `chargeWait time.Duration`, `chargeWindow string`,
  `chargeErr error` (default zero → `(ChargeProceed, 0, "", nil)`); drop the now-unused `chargeOver`. Update
  `chargeStubEdge` accordingly.
- [x] Rework the three Plan-9 pacedCopy tests to the action model, and add a kill test:
  - `TestEdge_PacedCopy_WaitsWhenOverCap` → stub `ChargeWait, 40ms`.
  - `TestEdge_PacedCopy_CtxCancelAbandonsWait` → stub `ChargeWait, 5s`; cancel mid-wait.
  - `TestEdge_PacedCopy_ChargeErrorFailsOpen` → stub `chargeErr!=nil` (bytes flow, no wait).
  - `TestEdge_PacedCopy_KillsOnQuota` (NEW) → stub `ChargeKill, window:"day"`; assert `pacedCopy` returns
    `quotaHit` and fired `QuotaExhausted(name,"day")`.
- [x] Any edge test that still calls `ClaimTraffic` directly (e.g. `TestEdge_HandleTunnel_QuotaAdmissionRefusal`
  seeds the quota via `ClaimTraffic`) must seed the per-direction `traf:` key another way — call `Charge`, or
  set the key via the test's redis client — so admission still sees the tunnel exhausted.
- [x] Reconcile the two existing real-limiter pacedCopy tests whose stale comments still say `ClaimTraffic`
  (both keep working under the unified `Charge`, complementing the new stub tests): `TestEdge_PacedCopy_QuotaExhaustion`
  (`bridge_test.go:86`, comment line ~89 "so ClaimTraffic refuses immediately" → "so Charge kills on the day
  cap immediately") and `TestEdge_PacedCopy_TrafficErrorFailsOpen` (`fixes_test.go:121`, comment "a Valkey
  error on ClaimTraffic" → "a Valkey error on Charge"). Confirm both still assert correctly against `Charge`
  (tiny day cap → `ChargeKill`; `mr.Close()` → fail-open `ChargeProceed`).

**Test (compressed):** the four pacedCopy tests above (`Proceed`/`Wait`/`CtxCancel`/`Kill`/`FailOpen`).

**Definition of Done:**
- [x] The fake + tests use `Charge`; wait / ctx-cancel / kill / fail-open covered; no `ChargeBandwidth`/
  `ClaimTraffic` reference remains in the edge tests.

---

## User Story 3 — [x] Reset `conc:{name}` on phone (re)bind (`internal/phoneconn`, `internal/server`)

**Acceptance criteria:**
- [x] On a successful `BindRoute` in `Manager.register`, `conc:{name}` is reset (`DEL`) BEFORE the conn is
  published to `m.conns` (inside the existing `bindLock`); a reset error is logged and ignored.
- [x] `ResetStreams` is injected via a narrow consumer-site interface; `server.Run` wires the limiter.

### Task 3.1 — [x] `StreamResetter` seam + reset in `register` (`internal/phoneconn/manager.go`)

**Actions:**
- [x] Add the consumer-site interface + Config field:

  ```go
  // StreamResetter clears a tunnel's live-scoped counters (the concurrent-stream count) when the phone
  // (re)binds — a fresh phone connection means all prior streams are dead. Satisfied by *limit.Limiter.
  // It MUST NOT touch identity-scoped quotas (day/week traffic), which persist across reconnects.
  type StreamResetter interface {
  	ResetStreams(ctx context.Context, name string) error
  }
  ```
  Add `Streams StreamResetter` to `Config`, store it on `Manager` (`streams StreamResetter`), and wire it in
  `NewManager` (`streams: cfg.Streams`).
- [x] In `register`, after the `BindRoute` loop succeeds and BEFORE the `m.conns` publish (still under
  `bindLock`), reset the live counters:

  ```go
  		// route is ours now (BindRoute won) but not yet serviceable (conn not published) — so no legitimate
  		// stream can have acquired a slot for THIS connection. Reset the live concurrent-stream counter: a
  		// fresh phone connection means all prior (crashed-node) streams are dead → count is implicitly zero.
  		// Identity quotas (day/week traffic) are deliberately untouched. A reset error is non-fatal (the
  		// conc:{name} TTL is the backstop).
  		if m.streams != nil {
  			if err := m.streams.ResetStreams(ctx, c.name); err != nil {
  				m.logger.Warn("conc reset on bind failed (TTL is the backstop)", "tunnel", c.name, "err", err)
  			}
  		}
  ```
  Place this AFTER the `for attempt … BindRoute …` loop breaks and BEFORE `m.mu.Lock(); … m.conns[c.name] = c`.

**Definition of Done:**
- [x] `register` resets `conc:{name}` on a won bind, before publishing the conn; the seam is nil-safe.

### Task 3.2 — [x] Wire the limiter into phoneconn (`internal/server/server.go`)

**Actions:**
- [x] Pass the limiter as the resetter where the phone manager is constructed:

  ```go
  	phoneMgr := phoneconn.NewManager(phoneconn.Config{
  		Router: reg, Logs: asyncLogs, Recorder: rec, Logger: logger,
  		NodeID: nodeID, NodeHost: nodeHost, NodeStart: nodeStart,
  		RouteTTL: cfg.RouteTTL, Streams: lim,
  	})
  ```
  (`lim` is already constructed above the phone-manager site.)

**Definition of Done:**
- [x] `server.Run` injects the limiter; the production phone manager resets `conc:` on bind.

### Task 3.3 — [x] phoneconn tests (`internal/phoneconn/*_test.go`)

**Actions:**
- [x] Add a `StreamResetter` stub (records the names it was asked to reset) and a test that a successful
  `register`/bind calls `ResetStreams(name)` exactly once; assert the reset happens (ordering vs the map
  insert is covered by construction — the call precedes the publish). Existing `register` tests that build a
  `Config` without `Streams` keep working (the field is nil-safe).

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestManager_ResetsConcOnBind` | a successful bind calls `StreamResetter.ResetStreams(name)` once | stub resetter; fake router that binds OK |
| `TestManager_BindNilResetterSafe` | a `Config` with `Streams==nil` binds without panicking | omit `Streams` |
| `TestManager_BindResetErrorNonFatal` | a `ResetStreams` that RETURNS an error still lets `register`/bind succeed and publish the conn (the `conc:` TTL is the backstop) | stub resetter returning an error; assert `register` returns no error and the conn is registered |

**Definition of Done:**
- [x] Bind resets the live counter via the seam; a nil resetter is safe.

---

## User Story 4 — [x] Config help + documentation

**Acceptance criteria:**
- [x] `--limit-traffic-day/week` help states **per direction**.
- [x] `docs/ARCHITECTURE.md`, `docs/PROJECT.md`, `README.md`, `.claude/rules/project.md` describe the unified
  per-window model (bandwidth + traffic), the per-direction traffic semantics, the 5 s wait-else-kill rule,
  and the **live-vs-identity reset invariant** (with `conc:` reset on bind).

### Task 4.1 — [x] Config help (`internal/config/config.go`)

**Actions:**
- [x] Update the two flag help strings: `Per-tunnel bytes per 24h window …, both directions combined
  (BINARY).` → `Per-tunnel bytes per 24h window (UTC-aligned), per direction (BINARY).` (and the week line
  analogously). No `Validate()` change — the `week ≥ day` check still holds per-direction.

**Definition of Done:**
- [x] The traffic flag help says per-direction, UTC-aligned.

### Task 4.2 — [x] Docs

**Actions:**
- [x] `docs/ARCHITECTURE.md` §4 "Bandwidth model" → rename/rewrite to the **unified per-window model**: one
  `Charge` per read (plain pipeline, `INCRBY`/`INCR` + `EXPIRE NX`, no Lua) covering per-second byte/packet
  windows AND per-direction day/week traffic windows; over a cap → wait if the window resets within 5 s, else
  kill; day/week are clock-aligned per-direction; fail-open; overshoot bound unchanged. Remove the now-stale
  separate "day/week via TTL'd Lua INCR" wording.
- [x] `docs/ARCHITECTURE.md` §5 "Valkey state" (lines ~114-124): the state enumeration and its heading name
  the `bw:`/`pkt:` windows as written via a pipelined `EXPIRE NX`; add the new per-direction
  `traf:{name}:{dir}:day/week:{n}` keys to that family (same pipelined `EXPIRE NX`, no longer the deleted
  `claimTrafficScript` Lua) so §5 stays consistent with PROJECT.md §5.
- [x] `docs/PROJECT.md`: the caps table (traffic rows → "per direction"); §5 "State + retention" (lines
  ~118-123) — add the `traf:{name}:{dir}:day/week:{n}` keys to the enumeration AND broaden the pipelined
  `EXPIRE NX` attribution clause: "…for the self-healing transient `bw:`/`pkt:` per-second windows" →
  "…for the self-healing transient `bw:`/`pkt:` per-second AND `traf:` day/week windows" (the `traf:` keys
  now use the same pipelined `EXPIRE NX`, not the deleted Lua) — matching the ARCHITECTURE §5 edit; add a
  short **live-vs-identity reset** note (conc reset on bind; day/week persist). Non-goals unchanged.
- [x] `README.md`: the "Caps" table traffic rows → per-direction, and fix the now-inaccurate **week** label:
  line 102 `| Traffic / tunnel / rolling 7d | …` → the week window is now an **epoch-aligned fixed 7-day
  window, per direction** (NOT rolling); reword to e.g. `| Traffic / tunnel / 7d window (per direction) |`
  and the day row to `… / 24h window (UTC-aligned, per direction)` — consistent with the Task 4.1 config help.
- [x] `.claude/rules/project.md`:
  - Rewrite the **Bandwidth model** invariant to the unified `Charge` (per-second + per-direction day/week,
    plain pipeline, no Lua, wait-else-kill-5s). Keep the `conc:{name}` TTL wording (now refreshed via the
    `Charge` pipeline's `PEXPIRE`, not the removed Lua). Preserve the "blocking wait MUST NEVER be held under
    a connection write mutex" safety line.
  - Broaden the SACRED **Valkey (transient) + S3 state** invariant (lines ~108-116): its pipelined
    `EXPIRE NX` attribution names "the transient per-second `bw:`/`pkt:` bandwidth windows" — the `traf:`
    day/week windows now use the SAME pipelined `EXPIRE NX` (the Lua is deleted), so reword to "…the
    transient per-second `bw:`/`pkt:` **AND `traf:` day/week** windows", and add `traf:{name}:{dir}:day/week`
    to the enumerated key family — matching the PROJECT.md §5 / ARCHITECTURE §5 edits (no live-surface
    invariant may imply traffic still uses Lua).
  - ADD an explicit **live-vs-identity reset invariant**: live-tunnel-scoped counters (`conc:{name}`) reset
    on tunnel (re)bind; identity-scoped cumulative quotas (`traf:` day/week, issuance/`--issue-per-week`)
    MUST persist across reconnects.
  - Update the **Source-IP + ingress** / other invariants only where they reference the old day/week Lua or
    "combined-direction" traffic (reword to the per-direction unified `Charge`).

**Definition of Done:**
- [x] All four docs reflect the unified model + per-direction traffic + the live-vs-identity reset invariant;
  no stale "day/week Lua" / "both directions combined" language remains on any live surface.

---

## User Story 5 — [x] Ground-up verification

### Task 5.1 — [x] Final ground-up verification (double-check EVERYTHING)

**Actions:**
- [x] Re-read this plan top to bottom; confirm every task/action + acceptance criterion is implemented.
- [x] Confirm the removed entry points are gone: `grep -rn 'ClaimTraffic\|claimTrafficScript\|ChargeBandwidth\|bwWindowKeys\|trafficKeys' internal/` returns nothing.
- [x] Confirm NO Lua and NO TxPipeline in the charge path: `Charge` uses `l.rdb.Pipeline()` only;
  `grep -rn '\.TxPipeline(' internal/` returns nothing (grep the CALL, not the bare token — the `Charge`
  doc comment legitimately says "no TxPipeline"); the only `redis.NewScript` in `internal/limit` are the
  UNCHANGED rate-window / concurrency / issuance / ACME scripts (bind/self-heal live in `internal/router`).
- [x] Confirm the reset invariant holds in code: `ResetStreams` deletes ONLY `conc:{name}`; `traf:` day/week
  keys are never deleted on bind; the reset call in `register` precedes the `m.conns` publish.
- [x] Confirm traffic is per-direction + clock-aligned end to end (`Charge` writes `traf:{name}:{dir}:day/week:{n}`;
  `TrafficExhausted` reads the same 4 keys); the admission gate still refuses an exhausted tunnel.
- [x] Run the FULL quality gates (`make build vet lint govulncheck test-unit test-integration test-e2e
  test-scripts compose-config` + `make tidy`), capturing logs per the tee rule. `test-e2e` MUST pass,
  including `TestE2E_Quota` — note the per-direction cap (the echo direction trips it) and that, in the rare
  case the test crosses a UTC-day boundary, the kill may be delayed by ≤ `maxPacingWait` (the transfer is
  still cut in the new day, whose reset is far), so the assertion still holds within its `waitBool` windows.
- [x] Confirm hygiene: no AI attribution, no plan/finding IDs in code or commit messages, placeholders only,
  and NO out-of-scope files changed.

**Definition of Done:**
- [x] All gates pass on the final code; the unified charge + per-direction traffic + `conc:` reset-on-bind
  work end to end; the ground-up re-read finds zero gaps.

---

## Deviations

_(recorded during implementation per agent.md §2)_

None. The planned code blocks reconciled cleanly against the current codebase; all four quality-gate
tiers (unit, integration, e2e, scripts) plus lint ×3 / vet / build / govulncheck / tidy pass on the
implemented code with no changes to the planned contracts.
