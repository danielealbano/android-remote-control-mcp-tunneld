<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 20 — Cross-node stream slot eviction

When a tunnel's global stream cap (`conc:{name}`) is full, the entry node today evicts only one of ITS OWN
streams; when every slot is held on other nodes it refuses the connection (`stream-cap`) even though those
streams are idle. Let the entry node, when it has nothing to evict, have the node holding the tunnel's most
idle evictable stream evict it over the mesh, then retry.

## Context & key decisions (the decision record — not derivable from code)

- **Evidence (2026-11-01, production, read-only):** every one of the 395 timestamped `stream-cap` cap-hit
  lines of 2026-10-28..11-01 was logged on a node holding ZERO live streams of that tunnel (connection logs
  replayed per node); in 361 of them the other nodes held exactly the cap (4). The clients (identified by their
  operator's published egress ranges) open one TLS connection per tool call and leave it idle. Reported in the
  Android Remote Control MCP app's issue #209 (fast `Connection failed` answers).
- **Victim choice (user, 2026-11-01):** the entry node evicts its own least-active evictable stream FIRST,
  exactly as today. ONLY when it has none, it asks every other live node IN PARALLEL for its least-active
  evictable stream and has the node whose stream is MOST IDLE evict it ("most idle cluster-wide"), then
  retries the acquire once. Evictability and the per-node ranking are unchanged: idle ≥
  `--limit-conn-evict-idle` OR rolling 60 s bytes < `--limit-conn-protect-rate`; the longest-idle one goes.
- **Pending slots stay non-evictable (user, 2026-11-01):** a slot taken for a connection still waiting for
  its dial-back is a request in progress (not tracked as an `activeStream`); it keeps counting toward the cap
  and is never offered or evicted.
- **Two new mesh ops** on `POST /api/v1/mesh/control`, `slot-candidate` and `free-slot` (replica↔replica only,
  NOT part of the phone contract, so `client/` is unaffected). `free-slot` answers only after the victim's Valkey
  slot is released (`evictLeastActive` already releases it synchronously).
- **Fallback (implementation decision):** when the most idle node answers `free-slot` with an explicit
  `applied:false` (its stream became active or ended meanwhile), the next most idle offer is tried. A `free-slot`
  call that FAILS (error, timeout, lost answer) ends the attempt and is reported as "may have freed a slot":
  `free-slot` is not idempotent — the remote evicts before answering and ignores the caller's cancellation — so
  asking another node could evict a second stream for one admission. `handleTunnel`'s single retry-acquire then
  decides: when no slot was freed it refuses with `stream-cap`. When every `free-slot` answers `applied:false`
  there is no retry and the connection is refused at once.
- **A victim already being evicted is never picked again:** the selection skips streams whose `evicted` flag
  is set and the eviction claims the victim with `CompareAndSwap`, so `applied:true` means a stream not already
  being evicted was evicted and its slot release was attempted (a victim admitted fail-open holds no slot, and a
  failed `ReleaseStream` leaves its slot taken; the single retry-acquire decides). Without it, concurrent refusals
  re-pick a victim that stays tracked until its splice unwinds and free nothing. This also changes the LOCAL path
  when two admissions on one node race: today the second one usually re-picks the same victim and is refused; with
  this plan it evicts the next least-active stream and is admitted.
- **Context:** `mesh.SlotController.FreeSlot` takes a `context.Context` because the op ends in Valkey I/O, like
  the other I/O-performing mesh `Controller` methods; `SlotCandidate` does no I/O and takes none. `Edge.FreeSlot` /
  `evictLeastActive` keep none: their only I/O is the victim's EXISTING slot-release closure (`releaseSlot` in
  `handleTunnel`, unchanged by this plan), which deliberately runs on `context.Background()` so the slot is freed
  whatever happens to the caller — a cancelled release would leave the slot taken, because the victim's own deferred
  release then no-ops (`sync.Once`). That single `ZREM` is bounded by the Valkey client's socket timeouts: tunneld
  sets none, so go-redis v9.23.0's defaults apply (`ReadTimeout` 5 s, `WriteTimeout` = `ReadTimeout`, `options.go`).
  The local eviction path already calls the same closure the same way.
- **Bounds:** the parallel `slot-candidate` round (including the node listing) runs under one 1 s deadline;
  each `free-slot` call under its own 1 s deadline (the mesh is the private WireGuard network, a call takes
  milliseconds); at most one `slot-candidate` and one `free-slot` per other live node, and only the last
  `free-slot` can go unanswered. Refusals are driven by public traffic, so a node runs at most
  `slotFreeConcurrency` = 32 remote-slot attempts at once (the same bound as `evictBroadcastConcurrency`); an attempt
  that finds them all busy skips the mesh and is refused with `stream-cap` exactly as today (non-blocking).
- **Logging:** a failed node listing or mesh call on this path is logged at Debug with `tunnel` + `peer` (the
  other node's id; the server logger already carries this node's own id as `node`) — it
  runs on every refused admission of a saturated tunnel (public-traffic driven), like the bridge's other
  data-plane control errors (`open far side failed`, `stream-cap acquire failed`). No new metric: the victim is
  already counted as `PublicConnClose("evicted")` and the refusal as `stream-cap`.
- **No Valkey, wire-frame, config or metric change.** No Mermaid chart is added or modified.
- **No new code comments** (user rule): no comment line is added to any code. The `serveControl` doc comment's
  "→ {applied}" becomes partly wrong (`slot-candidate` also answers `idle_ms`) and is removed; every other
  touched comment stays correct and is kept.
- **Decision-record precedence:** `.claude/rules/project.md` makes the Plan 3 record canonical in a dispute, and
  Plan 3 records the LOCAL-only eviction; the stream-cap eviction joins the carve-outs that `docs/ARCHITECTURE.md`
  and `docs/PROTOCOL.md` are canonical for (Action 3.3.3).
- Out of scope: release and rollout (the user decides). The production limits were already changed on
  2026-11-01 (`--limit-concurrent` 10, `--limit-conn-min-rate` 1kb, `--limit-conn-min-grace` 20s,
  `--limit-conn-idle` 32s) — an operator change, not part of this plan.
- Branch `fix/plan-20-cross-node-stream-slot-eviction`; one commit per task, in order; every task leaves the
  code base compiling.

---

## User Story 1: Let any node evict a tunnel's least-active stream on request

- [x] **US1** — Expose the per-node victim choice and serve it over the mesh.

Why: the entry node needs to learn, and act on, the most idle evictable stream another node holds.

### Acceptance Criteria

- [x] `Edge.SlotCandidate(tunnel)` reports the idle time of the stream `Edge.FreeSlot(tunnel)` would evict, and
      `false` when the tunnel has no evictable stream on the node (protected, other tunnels' and already-evicted
      streams never count).
- [x] `Edge.FreeSlot(tunnel)` evicts exactly that stream (`close_reason=evicted`, slot released once) and returns
      `false` when there is none; two concurrent calls never both report the same victim.
- [x] Mesh `slot-candidate` answers `{"applied":true,"idle_ms":<n>}` (`idle_ms` absent when the candidate is idle
      less than 1 ms) / `{"applied":false}`; mesh `free-slot` answers `{"applied":<evicted>}`; both require `tunnel`
      (`400` otherwise) and need no `conn_id`.

### [x] Task 1.1: Edge victim choice

- [x] **Action 1.1.1** — `internal/edge/bridge.go` (modify): split the victim selection out of
      `evictLeastActive`, skip already-evicted streams, claim the victim with `CompareAndSwap`, and add the two
      exported methods (the existing doc comment of `evictLeastActive` and the inline `release()` comment stay).

```go
// evictLeastActive closes the least-active EVICTABLE local stream of a tunnel (idle ≥ EvictIdle OR
// rolling rate < ProtectRate; never a protected stream). Returns true if one was evicted.
func (e *Edge) evictLeastActive(tunnel string) bool {
	for {
		victim, _ := e.leastActive(tunnel)
		if victim == nil {
			return false
		}
		if !victim.evicted.CompareAndSwap(false, true) {
			continue
		}
		victim.cancel()
		if victim.release != nil {
			victim.release() // free the Valkey slot NOW; the victim's own deferred release becomes a no-op
		}
		return true
	}
}

func (e *Edge) leastActive(tunnel string) (*activeStream, time.Duration) {
	now := e.now().UnixNano()
	e.smu.Lock()
	defer e.smu.Unlock()
	var victim *activeStream
	var victimIdle int64 = -1
	for s := range e.streams {
		if s.tunnel != tunnel || s.evicted.Load() {
			continue
		}
		idle := now - s.lastAct.Load()
		rate := s.recent.Load()
		evictable := idle >= int64(e.cfg.EvictIdle) || rate < e.cfg.ProtectRate
		if !evictable {
			continue
		}
		if idle > victimIdle {
			victim = s
			victimIdle = idle
		}
	}
	return victim, time.Duration(victimIdle)
}

func (e *Edge) SlotCandidate(tunnel string) (time.Duration, bool) {
	victim, idle := e.leastActive(tunnel)
	if victim == nil {
		return 0, false
	}
	return idle, true
}

func (e *Edge) FreeSlot(tunnel string) bool {
	return e.evictLeastActive(tunnel)
}
```

Tests (`internal/edge/policy_test.go`; the existing `evictLeastActive` tests keep passing unchanged):

| Test | Verifies |
|---|---|
| `TestEdge_SlotCandidate_MostIdleEvictable` | Table, fixed `e.now`, `EvictIdle` 1 min (above every idle time used) and `ProtectRate` 1000: two low-rate streams (idle 1 s, 3 s, `recent` 0) + a protected stream idle 5 s with `recent` 5000 + another tunnel's stream idle 30 s → `(3s, true)`; only the protected stream → `(0, false)`; no stream → `(0, false)`; the 3 s stream already marked `evicted` → `(1s, true)`. |
| `TestEdge_FreeSlot_EvictsMostIdle` | `FreeSlot` cancels the stream `SlotCandidate` reported, sets its `evicted` flag, calls its `release` exactly once, leaves the others running; returns `false` when nothing is evictable. |
| `TestEdge_EvictLeastActive_SkipsAlreadyEvicted` | With the most idle stream already marked `evicted`, the call evicts the next one; with every candidate marked, it returns `false` and cancels nothing. |
| `TestEdge_FreeSlot_ConcurrentCallsPickDistinctVictims` | Two idle streams, two concurrent `FreeSlot` calls (`-race`): both return `true` and each stream is cancelled exactly once; a third call returns `false`. |

#### Definition of Done

- [x] The selection logic exists once (`leastActive`), used by `evictLeastActive` and `SlotCandidate`.
- [x] Every test of the table above is written.

### [x] Task 1.2: Mesh `slot-candidate` / `free-slot` ops

- [x] **Action 1.2.1** — `internal/mesh/listener.go` (modify; add the `time` import):

```diff
 type Controller interface {
 	TunnelController
 	ConnController
+	SlotController
 }
@@
 type ConnController interface {
 	Open(ctx context.Context, tunnel, connID string, open wire.OpenPayload) (bool, error)
 	Evict(ctx context.Context, tunnel, connID, reason string) (bool, error)
 }
+
+type SlotController interface {
+	SlotCandidate(tunnel string) (time.Duration, bool)
+	FreeSlot(ctx context.Context, tunnel string) bool
+}
@@
 type ControlResponse struct {
-	Applied bool `json:"applied"` // renew: a nudge was enqueued; terminate: a live phone conn was closed
+	Applied bool  `json:"applied"` // renew: a nudge was enqueued; terminate: a live phone conn was closed
+	IdleMS  int64 `json:"idle_ms,omitempty"`
 }
@@
 // serveControl handles the mesh control RPC (mesh-role mTLS already enforced by ServeHTTP): a JSON
-// {op, tunnel} → {applied} request/response. Unknown op / missing tunnel → 400; op failure → 502.
+// {op, tunnel} request/response. Unknown op / missing tunnel → 400; op failure → 502.
 func (h *Handler) serveControl(w http.ResponseWriter, r *http.Request) {
@@
-	if req.Op != "renew" && req.Op != "terminate" && req.Op != "open" && req.Op != "evict" {
+	if req.Op != "renew" && req.Op != "terminate" && req.Op != "open" && req.Op != "evict" &&
+		req.Op != "slot-candidate" && req.Op != "free-slot" {
 		http.Error(w, "unknown op", http.StatusBadRequest)
 		return
 	}
@@
-	var applied bool
+	var resp ControlResponse
 	var err error
 	switch req.Op {
 	case "renew":
-		applied, err = h.control.Renew(r.Context(), req.Tunnel)
+		resp.Applied, err = h.control.Renew(r.Context(), req.Tunnel)
 	case "terminate":
-		applied, err = h.control.Terminate(r.Context(), req.Tunnel)
+		resp.Applied, err = h.control.Terminate(r.Context(), req.Tunnel)
 	case "open":
-		applied, err = h.control.Open(r.Context(), req.Tunnel, req.ConnID, *req.Open)
+		resp.Applied, err = h.control.Open(r.Context(), req.Tunnel, req.ConnID, *req.Open)
 	case "evict":
-		applied, err = h.control.Evict(r.Context(), req.Tunnel, req.ConnID, req.Reason)
+		resp.Applied, err = h.control.Evict(r.Context(), req.Tunnel, req.ConnID, req.Reason)
+	case "slot-candidate":
+		var idle time.Duration
+		idle, resp.Applied = h.control.SlotCandidate(req.Tunnel)
+		resp.IdleMS = idle.Milliseconds()
+	case "free-slot":
+		resp.Applied = h.control.FreeSlot(r.Context(), req.Tunnel)
 	}
@@
 	w.Header().Set("Content-Type", "application/json")
-	if err := json.NewEncoder(w).Encode(ControlResponse{Applied: applied}); err != nil {
+	if err := json.NewEncoder(w).Encode(resp); err != nil {
```

- [x] **Action 1.2.2** — `internal/server/serve.go` (modify): `adminController` serves the two ops from the edge.

```diff
 type adminController struct {
-	mgr          phoneControl
-	nonce        func(ctx context.Context) (string, error) // mints the single-use renewal challenge nonce
-	evictStreams func(name string)                         // edge.EvictTunnelStreams on this node
-	evictConn    func(name, connID, reason string) bool
+	mgr           phoneControl
+	nonce         func(ctx context.Context) (string, error) // mints the single-use renewal challenge nonce
+	evictStreams  func(name string)                         // edge.EvictTunnelStreams on this node
+	evictConn     func(name, connID, reason string) bool
+	slotCandidate func(tunnel string) (time.Duration, bool)
+	freeSlot      func(tunnel string) bool
 }
```

```go
func (c *adminController) SlotCandidate(tunnel string) (time.Duration, bool) {
	return c.slotCandidate(tunnel)
}

func (c *adminController) FreeSlot(_ context.Context, tunnel string) bool {
	return c.freeSlot(tunnel)
}
```

(placed right after `func (c *adminController) Evict`; the field block above is the gofmt realignment of the
existing fields plus the two new ones.)

- [x] **Action 1.2.3** — `internal/server/server.go` (modify):

```diff
-	adminCtl := &adminController{mgr: phoneMgr, nonce: challengeFunc(enrollSvc), evictStreams: ed.EvictTunnelStreams, evictConn: ed.EvictConnStreams}
+	adminCtl := &adminController{mgr: phoneMgr, nonce: challengeFunc(enrollSvc), evictStreams: ed.EvictTunnelStreams, evictConn: ed.EvictConnStreams,
+		slotCandidate: ed.SlotCandidate, freeSlot: ed.FreeSlot}
```

- [x] **Action 1.2.4** — `internal/mesh/mesh_test.go` (modify, shared test fake): `fakeController` gains three
      fields and two methods.

```go
	idle      time.Duration
	candidate bool
	freed     bool
```

```go
func (f *fakeController) SlotCandidate(tunnel string) (time.Duration, bool) {
	f.called = true
	f.tunnel = tunnel
	return f.idle, f.candidate
}

func (f *fakeController) FreeSlot(_ context.Context, tunnel string) bool {
	f.called = true
	f.tunnel = tunnel
	return f.freed
}
```

Tests:

| Test | Verifies |
|---|---|
| `TestControlSlotCandidateDispatches` (`internal/mesh/mesh_test.go`) | Table: candidate idle 2500 ms → `200`, `applied:true`, `idle_ms` 2500, controller got the tunnel; candidate idle 500 µs → `applied:true` and the raw JSON has no `idle_ms` key; no candidate → `applied:false` and no `idle_ms` key. |
| `TestControlFreeSlotDispatches` (same file) | `freed` true/false → `200` with the same `applied`; controller got the tunnel. |
| `TestControlSlotOpsRequireTunnel` (same file) | Table over both ops with an empty tunnel → `400`, controller not called; both ops without `conn_id` are accepted. |
| `TestAdminController_SlotOps` (`internal/server/admin_controller_test.go`) | `SlotCandidate` / `FreeSlot` return exactly what the injected edge funcs return, with the tunnel passed through. |

#### Definition of Done

- [x] `adminController` has a method for every method of `mesh.Controller`.
- [x] Every test of the table above is written.

---

## User Story 2: Free a stream slot on another node when the entry node has none

- [ ] **US2** — On a full cap with nothing to evict locally, evict the cluster's most idle evictable stream
      over the mesh and retry.

Why: the issue #209 failure mode — every slot idle on other nodes, the new connection refused.

### Acceptance Criteria

- [ ] With every slot of a tunnel held on other nodes and no evictable stream on the entry node, a new public
      connection is admitted after the most idle evictable stream among the other nodes is evicted
      (`close_reason=evicted` on that node).
- [ ] The local eviction still runs first; the mesh is used only when it found nothing; an admission under the
      cap or a fail-open acquire error never touches the mesh.
- [ ] The `slot-candidate` query reaches every other live node in parallel.
- [ ] When no other node has an evictable stream the connection is refused with `stream-cap` exactly as today; a
      `free-slot` that fails never leads to a second eviction; every mesh call is bounded (the query round 1 s,
      each `free-slot` 1 s); a node runs at most 32 remote-slot attempts at once and refuses beyond that without
      touching the mesh.
- [ ] Pending (dial-back waiting) slots are never evicted.

### [x] Task 2.1: Server-side remote slot freeing

- [x] **Action 2.1.1** — `internal/server/serve.go` (modify; add the `cmp` and `slices` imports), after
      `func (a *openAdapter) Open`:

```go
const (
	slotQueryTimeout    = time.Second
	slotFreeTimeout     = time.Second
	slotFreeConcurrency = 32
)

type remoteSlots struct {
	nodeID       string
	nodes        liveNodeLister
	mesh         meshControl
	logger       *slog.Logger
	queryTimeout time.Duration
	freeTimeout  time.Duration
	inflight     chan struct{}
}

type slotOffer struct {
	node, addr string
	idle       time.Duration
}

func (r *remoteSlots) FreeRemoteSlot(ctx context.Context, tunnel string) bool {
	select {
	case r.inflight <- struct{}{}:
	default:
		r.logger.Debug("remote slot freeing skipped: too many attempts in flight", "tunnel", tunnel)
		return false
	}
	defer func() { <-r.inflight }()
	for _, o := range r.offers(ctx, tunnel) {
		fctx, cancel := context.WithTimeout(ctx, r.freeTimeout)
		res, err := r.mesh.Control(fctx, o.addr, mesh.ControlRequest{Op: "free-slot", Tunnel: tunnel})
		cancel()
		if err != nil {
			r.logger.Debug("free-slot failed on a node", "tunnel", tunnel, "peer", o.node, "err", err)
			return true
		}
		if res.Applied {
			return true
		}
	}
	return false
}

func (r *remoteSlots) offers(ctx context.Context, tunnel string) []slotOffer {
	ctx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	defer cancel()
	nodes, err := r.nodes.LiveNodes(ctx)
	if err != nil {
		r.logger.Debug("slot-candidate: node listing failed", "tunnel", tunnel, "err", err)
		return nil
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var out []slotOffer
	for id, info := range nodes {
		if id == r.nodeID {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := r.mesh.Control(ctx, info.Advertise, mesh.ControlRequest{Op: "slot-candidate", Tunnel: tunnel})
			if err != nil {
				r.logger.Debug("slot-candidate failed on a node", "tunnel", tunnel, "peer", id, "err", err)
				return
			}
			if !res.Applied {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			out = append(out, slotOffer{node: id, addr: info.Advertise, idle: time.Duration(res.IdleMS) * time.Millisecond})
		}()
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b slotOffer) int { return cmp.Compare(b.idle, a.idle) })
	return out
}
```

- [x] **Action 2.1.2** — `internal/server/serve_test.go` (modify, shared test fake): `fakeMeshControl` gains
      per-(op, peer) results that take precedence over `applied` / `errs`, each optionally blocking until its
      channel closes or the call's context ends.

```go
type fakeMeshResult struct {
	resp  mesh.ControlResponse
	err   error
	block chan struct{}
}
```

```diff
 type fakeMeshControl struct {
 	mu       sync.Mutex
 	calls    []meshCall
 	applied  map[string]bool
 	errs     map[string]error
+	byOp     map[string]fakeMeshResult
 	block    chan struct{}
@@ func (f *fakeMeshControl) Control(ctx context.Context, peer string, req mesh.ControlRequest) (mesh.ControlResponse, error) {
 	f.calls = append(f.calls, meshCall{peer: peer, req: req})
 	applied, err := f.applied[peer], f.errs[peer]
+	res, byOp := f.byOp[req.Op+"@"+peer]
 	f.mu.Unlock()
 	if f.block != nil {
 		select {
 		case <-f.block:
 		case <-ctx.Done():
 			return mesh.ControlResponse{}, ctx.Err()
 		}
 	}
+	if byOp {
+		if res.block != nil {
+			select {
+			case <-res.block:
+			case <-ctx.Done():
+				return mesh.ControlResponse{}, ctx.Err()
+			}
+		}
+		return res.resp, res.err
+	}
 	if err != nil {
```

Tests (`internal/server/serve_test.go`; `fakeLiveNodes` with self + nodes B, C, D; timeouts and an `inflight`
channel (capacity 32 unless noted) set on the struct):

| Test | Verifies |
|---|---|
| `TestRemoteSlots_FreesOnMostIdleNode` | B offers 5 s, C offers 30 s, D none → exactly one `free-slot`, sent to C; returns `true`; self never contacted; every `slot-candidate` names the tunnel. |
| `TestRemoteSlots_FallsBackOnlyOnExplicitRefusal` | Table: C's `free-slot` answers `applied:false` → B is asked next and its `applied:true` → `true`; both answer `applied:false` → `false`; C's `free-slot` errors → `true` with NO `free-slot` sent to B. |
| `TestRemoteSlots_NoOfferSendsNoFree` | Every node answers `applied:false` → no `free-slot` call, `false`. |
| `TestRemoteSlots_FailedQuerySkipsNode` | B's `slot-candidate` errors, C offers → `free-slot` to C, `true`. |
| `TestRemoteSlots_NodeListingFailure` | `LiveNodes` errors → `false`, no mesh call. |
| `TestRemoteSlots_OnlySelfSendsNothing` | `LiveNodes` holds only self (a single replica) → `false`, no mesh call. |
| `TestRemoteSlots_SkipsWhenAttemptsSaturated` | `inflight` of capacity 1, pre-filled → `false` at once, no mesh call; after draining it, the same call reaches the nodes again. |
| `TestRemoteSlots_QueriesNodesInParallel` | Global `block`; wait until `inflight` reaches 3 (B, C, D) before closing it, as `TestBroadcastControl` does, and fail if it never does; then `maxSeen` = 3. |
| `TestRemoteSlots_QueryBoundedByTimeout` | Global `block` never closed, `queryTimeout` 50 ms → returns `false` well within 1 s and every call has returned (`returned` = number of calls). |
| `TestRemoteSlots_FreeBoundedByTimeout` | Offers answer at once; C's `free-slot` blocks (per-op `block` never closed), `freeTimeout` 50 ms → returns `true` well within 1 s, exactly one `free-slot` sent, every call has returned. |

#### Definition of Done

- [x] Every goroutine of `offers` has returned before it returns (`wg.Wait`).
- [x] Every test of the table above is written.

### [x] Task 2.2: Edge asks for a remote slot

- [x] **Action 2.2.1** — `internal/edge/edge.go` (modify):

```diff
 type DialBackReadiness interface {
 	DialBackReady() bool
 }
+
+type RemoteSlots interface {
+	FreeRemoteSlot(ctx context.Context, tunnel string) bool
+}
@@ type Edge struct {
 	lim       StreamLimiter
+	slots     RemoteSlots
 	logs      PhoneEventSink
@@
 func New(cfg Config, ban func(netip.Addr) bool,
-	rec Recorder, r Router, dialBacks DialBackWaiter, opener Opener, ready DialBackReadiness, lim StreamLimiter,
+	rec Recorder, r Router, dialBacks DialBackWaiter, opener Opener, ready DialBackReadiness, lim StreamLimiter, slots RemoteSlots,
 	logs PhoneEventSink, chal ACMEChallenges, addr net.Addr) *Edge {
 	return &Edge{
 		cfg: cfg, ban: ban, rec: rec, router: r, dialBacks: dialBacks, opener: opener, ready: ready,
-		lim: lim, logs: logs, chal: chal,
+		lim: lim, slots: slots, logs: logs, chal: chal,
```

- [x] **Action 2.2.2** — `internal/edge/bridge.go` (modify, `handleTunnel`):

```diff
-	} else if !acq && e.evictLeastActive(name) {
+	} else if !acq && (e.evictLeastActive(name) || e.slots.FreeRemoteSlot(ctx, name)) {
```

- [x] **Action 2.2.3** — `internal/server/server.go` (modify): build `remoteSlots` before the edge and pass it to
      `edge.New`.

```diff
 	opener := &openAdapter{nodeID: nodeID, phones: phoneMgr, nodes: reg, mesh: meshClient,
 		open: wire.OpenPayload{Addr: cfg.DialBackAdvertise, UseHTTPS: cfg.DialBackHTTPS, UseMTLS: cfg.DialBackMTLS}}
+	slots := &remoteSlots{nodeID: nodeID, nodes: reg, mesh: meshClient, logger: logger,
+		queryTimeout: slotQueryTimeout, freeTimeout: slotFreeTimeout, inflight: make(chan struct{}, slotFreeConcurrency)}
 	ed := edge.New(edge.Config{
@@
 	}, banIP, rec,
-		reg, dialBacks, opener, dialBackReadiness{https: cfg.DialBackHTTPS, host: cfg.ControlHost, certs: reserved}, lim,
+		reg, dialBacks, opener, dialBackReadiness{https: cfg.DialBackHTTPS, host: cfg.ControlHost, certs: reserved}, lim, slots,
 		&edgeLogSink{st: connLogs, logger: logger, nodeHost: nodeHost, nodeStart: nodeStart}, chal, edgeAddr)
```

- [x] **Action 2.2.4** — `internal/edge/harness_test.go` (modify, shared test fake): a `fakeRemoteSlots`, a
      `slots` field on `testEdge`, and `newTestEdge` passes it to `New` right after `lim`.

```go
type fakeRemoteSlots struct {
	calls atomic.Int32
	free  func(ctx context.Context, tunnel string) bool
}

func (f *fakeRemoteSlots) FreeRemoteSlot(ctx context.Context, tunnel string) bool {
	f.calls.Add(1)
	return f.free != nil && f.free(ctx, tunnel)
}
```

```diff
 	chal   *fakeACMEChallenges
+	slots  *fakeRemoteSlots
 }
@@ func newTestEdge(t *testing.T, cfg Config, banIP func(netip.Addr) bool) *testEdge {
 	chal := &fakeACMEChallenges{}
+	slots := &fakeRemoteSlots{}
@@
-	e := New(cfg, banIP, rec, rtr, dial, opener, ready, lim, sink, chal, addr)
-	return &testEdge{e: e, rec: rec, sink: sink, rtr: rtr, dial: dial, opener: opener, ready: ready, chal: chal}
+	e := New(cfg, banIP, rec, rtr, dial, opener, ready, lim, slots, sink, chal, addr)
+	return &testEdge{e: e, rec: rec, sink: sink, rtr: rtr, dial: dial, opener: opener, ready: ready, chal: chal, slots: slots}
```

Tests (`internal/edge/bridge_test.go`; setup unless noted: `cfg.Concurrent = 2`, both slots taken with probe
members via `te.e.lim.AcquireStream` = "held on another node", `te.rtr.ok = true`):

| Test | Verifies |
|---|---|
| `TestEdge_HandleTunnel_StreamCapFreesRemoteSlot` | `te.slots.free` releases one probe member and returns `true` → the connection proceeds to the dial-back (`waitPhone(t, te, 0)`), no `stream-cap` rejection, `FreeRemoteSlot` called once with the tunnel name. |
| `TestEdge_HandleTunnel_StreamCapNothingToFree` | Table: `te.slots.free` returns `false`; `te.slots.free` returns `true` without releasing a probe (a failed `free-slot`, or the freed slot taken by another admission) → in both, one `stream-cap` rejection after the single retry, no `OPEN` requested (`te.opener.calls` empty), client closed, `FreeRemoteSlot` called once. |
| `TestEdge_HandleTunnel_RemoteSlotOnlyWhenLocalHasNone` | Table: a tracked local idle stream whose `release` frees a probe → local eviction admits, `FreeRemoteSlot` NOT called; a free slot (cap not reached) → NOT called; `AcquireStream` errors (the existing `countingLimiter{acquireErr}` set as `te.e.lim`) → fail-open admission, NOT called. |
| `TestEdge_PendingSlotNeverEvicted` | `cfg.Concurrent = 1`, `cfg.DialBackTimeout = time.Minute`, `te.dial.never = true`, no probes: a first `handleTunnel` runs in a goroutine on a cancellable context, takes the slot and waits for its dial-back (its `OPEN` is recorded); then `SlotCandidate` → `(0, false)`, `FreeSlot` → `false`, and a second `handleTunnel` gets `stream-cap` after one `FreeRemoteSlot` call (`free` returns `false`) while the first one is still waiting (its done channel still open); finally the context is cancelled and the first goroutine's done channel is awaited. |

#### Definition of Done

- [x] `edge.New` has no other caller than `server.Run` and the harness (both updated).
- [x] Every test of the table above is written.

### [ ] Task 2.3: End-to-end regression

- [ ] **Action 2.3.1** — `e2e/e2e_test.go` (modify, test code): move the `isEvicted` closure of `TestE2E_Eviction`
      into a file-level helper `evictedByEdge(t *testing.T, c *tls.Conn) bool` whose first statement is
      `t.Helper()`; the closure's body moves unchanged with its trailing comments; the block comment above the
      closure stays in `TestE2E_Eviction`, which keeps its assertions through `evictedByEdge`.
- [ ] **Action 2.3.2** — `e2e/e2e_test.go` (modify, test code): add `TestE2E_CrossNodeEviction` (below).

| Test | Verifies |
|---|---|
| `TestE2E_CrossNodeEviction` | Replicas A and B with `concurrent: 2`; the phone's control connection on A (`echoPhone(t, inf, edgeA, edgeA)`); a first roundtrip through B; then wait (`waitBool`) until `POST /api/v1/admin/tunnels/stats` `{"names":[<name>]}` on `inf.internal[edgeB]` reports `conc` 0; two TLS connections through A fill the cap; right before dialling the third, `echoOn` succeeds on both; the third connection through B round-trips (`waitBool` 15 s, closing a failed attempt) and exactly one of the two A connections is closed by the edge (`evictedByEdge`). |

#### Definition of Done

- [ ] `TestE2E_Eviction` and `TestE2E_CrossNodeEviction` both use `evictedByEdge`.

---

## User Story 3: Document cluster-wide stream eviction

- [ ] **US3** — Keep the canonical docs and `project.md` accurate.

Why: the mesh ops are part of the documented replica contract and the cap's behavior changed.

### Acceptance Criteria

- [ ] `docs/PROTOCOL.md` §5 documents both ops and when they are sent; `docs/ARCHITECTURE.md` describes the stream
      cap's eviction (local first, then the most idle stream on another node, pending slots never) and lists the
      ops in the package map; `docs/PROJECT.md` and `.claude/rules/project.md` stay accurate. No plan number is
      added to any of them.

### [ ] Task 3.1: `docs/PROTOCOL.md` §5

- [ ] **Action 3.1.1** — `docs/PROTOCOL.md` §5 (modify):

```diff
-`POST /api/v1/mesh/control`: a JSON request → response `{applied}` (mesh-role mTLS). The ops:
+`POST /api/v1/mesh/control`: a JSON request → response `{applied}` (`slot-candidate` adds `idle_ms`) (mesh-role
+mTLS). The ops:
@@
   to every node; each ends the splices opened through that connection, keeping `ban-evict` /
   `admin-terminate` when that is the reason, else `phone-close`.
+- `slot-candidate`: `{"op":"slot-candidate","tunnel":"<name>"}` → `{"applied":<this node holds an evictable
+  stream of the tunnel>,"idle_ms":<idle time in whole ms of the stream free-slot would evict>}`; `idle_ms` is
+  omitted when it is 0 — always with `applied:false`, and for a candidate idle less than 1 ms (read as 0).
+- `free-slot`: `{"op":"free-slot","tunnel":"<name>"}` → `{"applied":<a stream was evicted>}` — evict this node's
+  least-active evictable stream of the tunnel (`close_reason=evicted`) and free its stream slot before answering.
+
+A node that finds a tunnel's stream cap full and has no evictable stream of its own sends `slot-candidate` to
+every other live node, then `free-slot` to the node whose stream is the most idle (to the next one only when it
+answers `applied:false`; a failed call ends the attempt), and retries its admission once when a `free-slot`
+answered `applied:true` or failed (`ARCHITECTURE.md` §2).
```

#### Definition of Done

- [ ] The `400` rules line still matches the handler (unknown op, missing tunnel; neither new op needs `conn_id`).

### [ ] Task 3.2: `docs/ARCHITECTURE.md`

- [ ] **Action 3.2.1** — `docs/ARCHITECTURE.md` §1 package map (modify):

```diff
-| `internal/mesh` | replica↔replica mTLS HTTP/2 control RPCs (renew, terminate, open, evict), per-pair pools |
+| `internal/mesh` | replica↔replica mTLS HTTP/2 control RPCs (renew, terminate, open, evict, slot-candidate, free-slot), per-pair pools |
```

- [ ] **Action 3.2.2** — `docs/ARCHITECTURE.md` §2, new paragraph right after the one ending "tunneld never sees
      plaintext." (modify):

```markdown
**Stream cap.** A tunnel holds at most `--limit-concurrent` public connections at once across all nodes
(`conc:{name}`, §5; a Valkey error admits without a slot, fail-open). The entry node takes the slot before it asks
for the dial-back, so a connection still waiting for its dial-back counts and is never evicted. When the cap is
full the entry node evicts one stream and retries once. A stream is evictable when it has been idle (no byte
either way) for at least `--limit-conn-evict-idle` or moved fewer than `--limit-conn-protect-rate` bytes over the
last 60 s; the most idle one goes. The entry node evicts its own first; when it has none, it asks every other live
node for its most idle evictable stream (mesh `slot-candidate`, 1 s) and has the node whose stream is the most idle
evict it (mesh `free-slot`, 1 s; the next node only when that one answers that it has none left, while a failed
call ends the attempt, since the node may have evicted already); a node runs at most 32 such attempts at once and
refuses beyond that without asking. The victim ends with `close_reason=evicted`; when no slot was freed the new
connection is closed (`stream-cap`).
```

#### Definition of Done

- [ ] No Mermaid block of `ARCHITECTURE.md` changed.

### [ ] Task 3.3: `docs/PROJECT.md` and `.claude/rules/project.md`

- [ ] **Action 3.3.1** — `docs/PROJECT.md` §4 caps table (modify):

```diff
-| Concurrent data streams / tunnel | `--limit-concurrent` | `4` |
+| Concurrent data streams / tunnel, all nodes together (a full cap evicts the entry node's least-active evictable stream, else the most idle one on another node — [`ARCHITECTURE.md`](ARCHITECTURE.md) §2) | `--limit-concurrent` | `4` |
```

- [ ] **Action 3.3.2** — `.claude/rules/project.md` "Wire protocol" (modify):

```diff
-  `wire.ChunkSize` = 16384 is the pacing slice). The mesh carries control RPCs only (`renew`, `terminate`,
-  `open`, `evict` — replica↔replica, not part of the phone contract). ANY wire change MUST update
+  `wire.ChunkSize` = 16384 is the pacing slice). The mesh carries control RPCs only (`renew`, `terminate`,
+  `open`, `evict`, `slot-candidate`, `free-slot` — replica↔replica, not part of the phone contract). ANY wire change MUST update
```

- [ ] **Action 3.3.3** — `.claude/rules/project.md` "MANDATORY: Read These First" item 4 (modify):

```diff
-   Route ownership and the ban model are described by `docs/ARCHITECTURE.md` and `docs/PROTOCOL.md`, which
-   are canonical for them.
+   Route ownership, the ban model and the stream-cap eviction are described by `docs/ARCHITECTURE.md` and
+   `docs/PROTOCOL.md`, which are canonical for them.
```

#### Definition of Done

- [ ] The `.claude/` changes are committed on the branch.

---

## User Story 4: Ground-up double check

- [ ] **US4** — Verify EVERYTHING implemented by this plan from the ground up.

Why: catch any drift between this plan and what was built before the pull request.

### Acceptance Criteria

- [ ] Every checkbox of US1–US3 is ticked against the files on disk (re-read each touched file).

### [ ] Task 4.1: Re-read and verify every change

- [ ] **Action 4.1.1** — Re-read `internal/edge/bridge.go`, `internal/edge/edge.go`, `internal/mesh/listener.go`,
      `internal/server/serve.go`, `internal/server/server.go`, every touched test file (every test named in the
      plan's tables exists), `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md`, `docs/PROJECT.md` and
      `.claude/rules/project.md` against their actions; `git diff --name-only main...HEAD` together with
      `git status --porcelain` lists exactly those files plus this plan and nothing else.
- [ ] **Action 4.1.2** — `git diff main...HEAD -- '*.go' | grep -nE '^\+.*//'`, then review every hit by hand: the
      only hits are existing comments re-added unchanged (the `victim.release()` trailing comment, the realigned
      `adminController` field comments, the realigned `ControlResponse.Applied` comment, the `serveControl` doc
      comment minus "→ {applied}"), the trailing comments moved unchanged into `evictedByEdge`, and `//` inside
      strings or URLs; every existing comment of the touched code is still present and correct.
- [ ] **Action 4.1.3** — Before `make test-e2e`, run `adb devices`, state which device-gated tests will run (they run
      only with exactly one device in state `device`) and what they install on it.

#### Definition of Done

- [ ] Quality gates, each captured with `tee` to `/tmp/<descriptive>.log`, all exit 0: `make lint`, `make build`,
      `make vet`, `make govulncheck`, `make tidy` (then `git diff --exit-code go.mod go.sum`), `make test-scripts`,
      `make third-party-licenses`, `make test-unit`, `make test-integration`, `make test-e2e`, `make test-staging`
      (skips without `TUNNELD_STAGING_SSH_KEY`).
