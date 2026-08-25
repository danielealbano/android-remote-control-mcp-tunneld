<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 12 — Per-tunnel admin actions: reissue (moved) + terminate

## Scope

Restructure the internal admin surface around per-tunnel action URLs and add a `terminate` action:

- **Move** the existing force-renew from `POST /api/v1/admin/renew?tunnel=<name>` to
  `POST /api/v1/admin/tunnels/{name}/reissue`. The old endpoint is **removed** (hard-cut, no alias — the
  platform is not deployed, so no backward-compat is carried).
- **Add** `POST /api/v1/admin/tunnels/{name}/terminate`: owner-routed; on the owner node it closes the
  live phone control connection **and** evicts that node's in-flight public splices, both attributed
  `close_reason=admin-terminate`. It is ephemeral by design — the phone reconnects immediately (a
  force-reconnect / kick, not a keep-down).
- **Generalize** the mesh `/api/v1/mesh/control` envelope for a second op (`renew` | `terminate`) and its
  `Controller` interface.

Both actions reuse the existing owner-routing pattern (local controller when this node owns the route,
else the mesh control RPC to the owner). "reissue" is the operator-facing verb for the existing renewal
mechanism: the internal mesh op and controller method stay `renew`/`Renew` (they drive the frozen
`RENEW_NUDGE` protocol frame — see `docs/PROTOCOL.md`); only the URL and the operator JSON field are named
for the action.

No Mermaid charts are added or modified, so the §9 Mermaid-validation step does not apply.

## User Stories

- [x] **US1 — Terminate primitives (close-reason + phone close + edge splice evict)**
- [x] **US2 — Owner-routed reissue + terminate (mesh envelope, admin controller, admin endpoints)**
- [x] **US3 — Documentation + ground-up verification**

---

## US1 — Terminate primitives

Add the low-level pieces `terminate` needs, independent of any wiring: the `admin-terminate` close reason,
a per-name phone-connection close, and an edge method that evicts a tunnel's in-flight public splices with
that reason.

Acceptance criteria:
- [x] `store.CloseAdminTerminate == "admin-terminate"` exists.
- [x] `Manager.Close(name, reason)` closes the named live phone control connection with that reason and
      reports whether one existed.
- [x] `Edge.EvictTunnelStreams(name)` cancels every active public splice of that tunnel; each records
      `close_reason=admin-terminate`.
- [x] Splice close-reason attribution precedence is `banned > terminated > evicted > server-shutdown`.

### Task 1.1 — Add the `admin-terminate` close reason

- [x] **Action** — modify `internal/store/event.go`: add the constant to the close-reason enum block.

```go
CloseServerShutdown = "server-shutdown"
CloseAdminTerminate = "admin-terminate"
CloseCertExpired    = "cert-expired"
```

Definition of Done:
- [x] The constant sits inside the existing `const (...)` close-reason block.

### Task 1.2 — Per-name phone-connection close

- [x] **Action** — modify `internal/phoneconn/manager.go`: add `Close` on `*Manager` (mirrors the
  `SendRenewNudge` lookup/liveness guard; `conn.close` is idempotent).

```go
// Close closes the named tunnel's live phone control connection with the given close reason (recorded on
// the phone end event) and reports whether a live connection existed. Used by the admin terminate action.
func (m *Manager) Close(name, reason string) bool {
	c, ok := m.lookup(name)
	if !ok || c.isClosed() {
		return false
	}
	c.close(reason)
	return true
}
```

Definition of Done:
- [x] Returns `false` (no side effect) when no live connection exists; `true` after closing one.

Tests (`internal/phoneconn/manager_test.go` or the existing phoneconn test file):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestManager_Close_ClosesLiveConn` | `Close` closes a registered conn with the given reason and returns true; `closeReason()` reflects it | register a conn via the package's existing test harness/fake |
| `TestManager_Close_AbsentReturnsFalse` | `Close("nobody", …)` returns false, no panic | empty manager |

### Task 1.3 — Edge splice eviction by tunnel name

- [x] **Action** — modify `internal/edge/bridge.go`: add a `terminated` marker to `activeStream`, and amend
  the existing `banned` field comment's precedence enumeration (`… over evicted/shutdown`) to include the new
  `terminated` state.

```go
evicted    atomic.Bool // set BEFORE cancel() on saturation eviction, so the splice can tell an eviction cancel from a server-drain (parent ctx) cancel
banned     atomic.Bool // set BEFORE cancel() on a ban reload, so the splice attributes ban-evict over terminated/evicted/shutdown
terminated atomic.Bool // set BEFORE cancel() on an admin terminate, so the splice attributes admin-terminate over evicted/shutdown
```

- [x] **Action** — modify `internal/edge/bridge.go`: add `EvictTunnelStreams` (peer of
  `EvictBannedStreams`, keyed on the tunnel name only).

```go
// EvictTunnelStreams cancels every ACTIVE public splice for the named tunnel (admin terminate) on THIS
// node, attributing admin-terminate. Streams ingested on other nodes are not tracked here — they are torn
// down when the owner's phone connection drops.
func (e *Edge) EvictTunnelStreams(name string) {
	e.smu.Lock()
	var victims []*activeStream
	for s := range e.streams {
		if s.tunnel == name {
			victims = append(victims, s)
		}
	}
	e.smu.Unlock()
	for _, s := range victims {
		s.terminated.Store(true)
		s.cancel()
	}
}
```

- [x] **Action** — modify `internal/edge/bridge.go`: extend the splice watcher's `ctx.Done()`
  attribution (currently `banned → evicted → shutdown`) to include `terminated`, keeping `banned` first, AND
  update the preceding comment so its ctx-cancel-trigger enumeration lists the new admin-terminate case.

```go
			case <-ctx.Done():
				// The stream ctx cancels on a ban reload (EvictBannedStreams marks banned first), on an
				// admin terminate (EvictTunnelStreams marks terminated first), on saturation eviction
				// (evictLeastActive marks evicted first), OR on server drain (the parent ctx) — attribute
				// each accurately, banned taking precedence.
				if as.banned.Load() {
					setReason(store.CloseBanEvict)
				} else if as.terminated.Load() {
					setReason(store.CloseAdminTerminate)
				} else if as.evicted.Load() {
					setReason(store.CloseEvicted)
				} else {
					setReason(store.CloseServerShutdown)
				}
```

Definition of Done:
- [x] A matching in-flight splice is cancelled and records `admin-terminate`; a non-matching splice is
      untouched.
- [x] `banned` still wins over `terminated` when both are set.

Tests (`internal/edge/fixes_test.go`, modeled on `TestEvictBannedStreams_KillsMatching`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestEvictTunnelStreams_KillsMatching` | `EvictTunnelStreams("t1")` cancels the t1 splice with `close_reason=admin-terminate`, marks `terminated`, leaves a t2 splice running | reuse the harness that stands up two tracked `activeStream`s and reads the splice reason |
| `TestSpliceReason_BannedBeatsTerminated` | with both `banned` and `terminated` set before a ctx cancel, the reason is `ban-evict` | drive the watcher attribution path (as in the existing evicted/shutdown reason test) |
| `TestSpliceReason_TerminatedBeatsEvicted` | with both `terminated` and `evicted` set before a ctx cancel, the reason is `admin-terminate` (pins the `terminated > evicted` boundary) | same watcher attribution path |

---

## US2 — Owner-routed reissue + terminate

Generalize the mesh control envelope for a second op, give the admin controller a `Terminate`, and replace
the single renew endpoint with the two per-tunnel action URLs. Implemented as three sequential tasks so no
reference dangles at any point (the `Nudged`→`Applied` rename and the handler rewrite land together).

Acceptance criteria:
- [x] `mesh.Controller` exposes `Renew` and `Terminate`; `mesh.ControlRequest.Op` accepts `"renew"` |
      `"terminate"`; `mesh.ControlResponse` reports a single `applied` boolean.
- [x] `POST /api/v1/admin/tunnels/{name}/reissue` behaves exactly as the old `/api/v1/admin/renew` (owner
      routing, 405/400/404 paths, JSON `{tunnel, owner, reissued}`), addressed by path segment. The
      operator-facing result field is action-named (`reissued`), symmetric with terminate's `terminated`;
      the internal mesh op and controller method stay `renew`/`Renew`.
- [x] `POST /api/v1/admin/tunnels/{name}/terminate` routes to the owner, closes the phone control conn +
      evicts that node's in-flight public splices, and returns `{tunnel, owner, terminated}`.
- [x] `POST /api/v1/admin/renew` no longer exists; NO Go file (unit or e2e) references it.

### Task 2.1 — Generalize the mesh control envelope + Controller

- [x] **Action** — modify `internal/mesh/listener.go`: extend the `Controller` interface, generalize the
  request/response, and add the `terminate` dispatch (shared missing-tunnel + JSON-write path).

```go
// Controller executes a mesh control op on THIS (owner) node. Implemented in internal/server (mesh MUST
// NOT import phoneconn/enroll). Renew enqueues a RENEW_NUDGE; Terminate closes the tunnel's live phone
// connection and evicts this node's in-flight public splices. Each returns whether it applied.
type Controller interface {
	Renew(ctx context.Context, tunnel string) (bool, error)
	Terminate(ctx context.Context, tunnel string) (bool, error)
}

// ControlRequest / ControlResponse are the /api/v1/mesh/control JSON envelope (replica↔replica only).
type ControlRequest struct {
	Op     string `json:"op"`     // "renew" | "terminate"
	Tunnel string `json:"tunnel"` // the tunnel name to act on
}

type ControlResponse struct {
	Applied bool `json:"applied"` // renew: a nudge was enqueued; terminate: a live phone conn was closed
}
```

```go
// serveControl handles the mesh control RPC (mesh-role mTLS already enforced by ServeHTTP): a JSON
// {op, tunnel} → {applied} request/response. op is "renew" (enqueue a RENEW_NUDGE to the named tunnel's
// live phone connection) or "terminate" (close that phone connection and evict this node's in-flight
// public splices). Unknown op / missing tunnel → 400; op failure → 502.
func (h *Handler) serveControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ControlRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad control request", http.StatusBadRequest)
		return
	}
	if req.Op != "renew" && req.Op != "terminate" {
		http.Error(w, "unknown op", http.StatusBadRequest)
		return
	}
	if req.Tunnel == "" {
		http.Error(w, "missing tunnel", http.StatusBadRequest)
		return
	}
	var applied bool
	var err error
	switch req.Op {
	case "renew":
		applied, err = h.control.Renew(r.Context(), req.Tunnel)
	case "terminate":
		applied, err = h.control.Terminate(r.Context(), req.Tunnel)
	}
	if err != nil {
		http.Error(w, req.Op+" failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ControlResponse{Applied: applied})
}
```

Definition of Done:
- [x] `client.go` needs no change (it decodes into `ControlResponse` without field references).
- [x] Unknown op and missing tunnel both → 400; op failure → 502; non-POST → 405.

Tests (`internal/mesh/mesh_test.go` — reconcile existing, add terminate):

| Test | Verifies | Setup notes |
|---|---|---|
| `fakeController` (reconcile) | gains a `Terminate` method + a `terminated`/reuse flag, mirroring `Renew` | add alongside the existing `Renew` stub |
| `TestControlRenewDispatches` (reconcile) | still passes with the response field now `applied` | rename the decode check `resp.Nudged` → `resp.Applied` (this test only decodes the response) |
| `TestControlTerminateDispatches` | `{op:"terminate",tunnel:"t"}` calls `Terminate`, returns `{applied:true}` | mesh-role request via `meshRoleReq` |
| `TestControlClient_Errors` (reconcile) | the client `Control` decode test still passes with the renamed field | rename the encoded `ControlResponse{Nudged:true}` → `{Applied:true}`, the `resp.Nudged` → `resp.Applied` check, and the local `wantNudged` table field → `wantApplied` |

### Task 2.2 — Admin controller with Terminate + edge wiring

- [x] **Action** — modify `internal/server/serve.go`: rename `renewController` → `adminController`, add the
  `evictStreams` dependency and the `Terminate` method (add the `internal/store` import if absent).

```go
// phoneControl is the consumer-side surface the admin controller needs from the phone manager (satisfied by
// *phoneconn.Manager) — an interface so adminController's Renew/Terminate logic is unit-testable in isolation.
type phoneControl interface {
	SendRenewNudge(name, nonceHex, ariWindow string) bool
	Close(name, reason string) bool
}

// adminController is this node's mesh.Controller: Renew enqueues a RENEW_NUDGE to the tunnel's LOCAL phone
// connection; Terminate evicts this node's in-flight public splices then closes that phone connection. Used
// both by the local admin path and by the mesh /api/v1/mesh/control handler on the owner node.
type adminController struct {
	mgr          phoneControl
	nonce        func(ctx context.Context) (string, error) // mints the single-use renewal challenge nonce
	evictStreams func(name string)                          // edge.EvictTunnelStreams on this node
}

func (c *adminController) Renew(ctx context.Context, tunnel string) (bool, error) {
	nonceHex, err := c.nonce(ctx)
	if err != nil {
		return false, err
	}
	return c.mgr.SendRenewNudge(tunnel, nonceHex, ""), nil
}

// Terminate kicks the tunnel on THIS (owner) node: it first evicts this node's in-flight public splices
// (attributed admin-terminate), then closes the live phone control connection. The phone reconnects
// afterwards — terminate is a force-reconnect, not a keep-down. Returns whether a live phone conn existed.
func (c *adminController) Terminate(_ context.Context, tunnel string) (bool, error) {
	c.evictStreams(tunnel)
	return c.mgr.Close(tunnel, store.CloseAdminTerminate), nil
}
```

- [x] **Action** — modify `internal/server/server.go`: reorder construction so the edge `ed` is built
  before the controller and the mesh handler, then build the controller with `ed.EvictTunnelStreams`. (The
  edge already depends only on `meshClient`, which is built earlier; nothing between them depends on the
  controller or mesh handler, so moving `edge.New(...)` ahead of them is safe.)

```go
	meshClient := mesh.NewClient(meshCert.clientTLS(caObj), cfg.MeshPoolSize, mesh.WithRecorder(rec))

	// Public edge (constructed from the resolved static address — the raw listener is bound LAST, below).
	edgeAddr, err := net.ResolveTCPAddr("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", cfg.Listen, err)
	}
	ed := edge.New(edge.Config{
		// … unchanged Config …
	}, banIP, banTunnel, rec,
		reg, phoneMgr, meshClient, lim, &edgeLogSink{st: asyncLogs, logger: logger, nodeHost: nodeHost, nodeStart: nodeStart}, edgeAddr)

	adminCtl := &adminController{mgr: phoneMgr, nonce: challengeFunc(enrollSvc), evictStreams: ed.EvictTunnelStreams}
	meshHandler := mesh.NewHandler(phoneMgr.OwnsConn,
		&bridgeAdapter{mgr: phoneMgr, dialBackTimeout: cfg.LimitDialBackTimeout}, adminCtl)
```

Definition of Done:
- [x] `adminController` satisfies the two-method `mesh.Controller`; `*phoneconn.Manager` satisfies
      `phoneControl`.
- [x] Construction order compiles with the edge built before the controller/mesh handler; the "bind
      listeners LAST" ordering below is unchanged.

Tests (`internal/server/admin_controller_test.go`; a `fakePhoneControl` records `SendRenewNudge`/`Close`
calls, and `evictStreams` is a spy recording the name + a shared call-order counter):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestAdminController_Renew` | `Renew` calls `SendRenewNudge(name, <nonce>, "")` and returns its bool; a nonce-mint error propagates and returns false | nonce closure returns a fixed hex; a second case returns an error |
| `TestAdminController_Terminate_EvictThenClose` | `Terminate` calls `evictStreams(name)` BEFORE `Close(name, "admin-terminate")`, and returns `Close`'s bool | assert the spy's recorded order (evict index < close index) and the reason string |

### Task 2.3 — Admin action endpoints (reissue + terminate); remove renew

- [x] **Action** — modify `internal/server/server.go`: replace `adminRenewHandler` with a shared
  `adminActionHandler` (path-addressed, owner-routed).

```go
// adminActionHandler routes a per-tunnel admin action ({name} from the path) to the tunnel's owner node:
// the local controller method when this node owns the route, else the mesh control RPC. op is the mesh op
// ("renew" | "terminate"); respField is the operator-facing JSON boolean key ("reissued" | "terminated").
// Internal listener only (never published). 404 when no route is bound.
func adminActionHandler(nodeID string, reg *router.Registry, mc *mesh.Client, log *slog.Logger,
	op, respField string, local func(ctx context.Context, name string) (bool, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.PathValue("name")
		if name == "" {
			http.Error(w, "missing tunnel", http.StatusBadRequest)
			return
		}
		owner, _, _, ok, err := reg.LookupRoute(r.Context(), name)
		if err != nil {
			log.Warn("admin "+op+": route lookup failed", "tunnel", name, "err", err)
			http.Error(w, "route lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "no route bound for tunnel", http.StatusNotFound)
			return
		}
		var applied bool
		if owner == nodeID {
			applied, err = local(r.Context(), name)
		} else {
			addr, addrOK, lerr := reg.LookupNode(r.Context(), owner)
			if lerr != nil || !addrOK {
				log.Warn("admin "+op+": owner node unresolved", "tunnel", name, "owner", owner, "err", lerr)
				http.Error(w, "owner node unavailable", http.StatusBadGateway)
				return
			}
			var res mesh.ControlResponse
			res, err = mc.Control(r.Context(), addr, mesh.ControlRequest{Op: op, Tunnel: name})
			applied = res.Applied
		}
		if err != nil {
			log.Warn("admin "+op+": failed", "tunnel", name, "owner", owner, "err", err)
			http.Error(w, op+" failed", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tunnel": name, "owner": owner, respField: applied})
	}
}
```

- [x] **Action** — modify `internal/server/server.go`: register the two action patterns and remove the old
  renew registration (Go 1.26 `ServeMux` wildcard patterns; the handler checks the method itself, matching
  the existing style, so no reliance on `ServeMux` 405 semantics). Also rewrite the stale preceding block
  comment (currently "Internal server (… force-renew …). The mux mounts /api/v1/admin/renew and delegates
  everything else …") so it names the per-tunnel reissue + terminate actions and no longer says
  `/api/v1/admin/renew` (otherwise the comment is false and the Task 3.2 `--include='*.go'` grep matches it).

```go
	// Internal server (metrics + healthz + admin actions; never proxied). The mux mounts the per-tunnel
	// admin actions /api/v1/admin/tunnels/{name}/reissue and .../terminate and delegates everything else to
	// the existing metrics handler (unchanged).
	internalMux := http.NewServeMux()
	internalMux.Handle("/api/v1/admin/tunnels/{name}/reissue",
		adminActionHandler(nodeID, reg, meshClient, logger, "renew", "reissued", adminCtl.Renew))
	internalMux.Handle("/api/v1/admin/tunnels/{name}/terminate",
		adminActionHandler(nodeID, reg, meshClient, logger, "terminate", "terminated", adminCtl.Terminate))
	internalMux.Handle("/", metrics.Handler(m.Registry(), rdb, adminTunnels, reg, logger))
```

- [x] **Action** — modify `e2e/e2e_test.go` and `e2e/tunnel_app_test.go`: migrate the admin e2e caller off
  the removed endpoint (otherwise `make test-e2e` in Task 3.2 breaks — the POST would fall through to the
  `/` catch-all). Rename the `postAdminRenew` helper to `postAdminReissue`; POST
  `http://<internalAddr>/api/v1/admin/tunnels/<name>/reissue` (name in the path via `url.PathEscape`, no
  query) and decode `{reissued}`. Update both call sites in `TestE2E_CrossNodeRenewNudge` (the real-tunnel
  200/`reissued:true` assertion and the unknown-tunnel 404) and the local-nudge phase in
  `tunnel_app_test.go`, including their comments and failure messages, to the new endpoint. (The RENEW_NUDGE
  mechanism is unchanged, so the `TestE2E_CrossNodeRenewNudge` function name stays.)

- [x] **Action** — add to `e2e/e2e_test.go` a `postAdminTerminate` helper (peer of `postAdminReissue`,
  POSTing `/api/v1/admin/tunnels/<name>/terminate` and decoding `{terminated}`) and a cross-node terminate
  roundtrip test `TestE2E_CrossNodeTerminate` (see the E2E test table below), giving terminate the same
  integrated cross-node coverage the reissue/renew path has via `TestE2E_CrossNodeRenewNudge`.

Definition of Done:
- [x] `adminRenewHandler` and the `/api/v1/admin/renew` registration are gone.
- [x] The `{name}/reissue` and `{name}/terminate` patterns do not collide with the `tunnels/list` /
      `tunnels/stats` paths served under `/` (distinct path shapes).
- [x] `grep -rn "admin/renew\|postAdminRenew" --include='*.go' .` returns nothing.
- [x] The cross-node terminate path (entry node → mesh RPC → owner closes the phone conn + unbinds the
      route) is exercised end-to-end by `TestE2E_CrossNodeTerminate`.

Tests (`internal/server/admin_renew_test.go` → rename to `admin_actions_test.go`; the `{name}` path value is
injected with `req.SetPathValue("name", …)`; `mc` is `nil` — remote dispatch is covered by the mesh tests):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestAdminAction_NonPost` | GET → 405 | any action handler |
| `TestAdminAction_MissingName` | empty path value → 400 | no `SetPathValue` |
| `TestAdminReissue_NoRoute` | unbound name → 404, local closure not called | local closure records invocation |
| `TestAdminReissue_Local` | bound-to-self → 200, `{tunnel, owner, reissued:true}` | `BindRoute` to this node; local closure returns true |
| `TestAdminTerminate_Local` | bound-to-self → 200, `{tunnel, owner, terminated:true}`; closure called with the name | local closure returns true |

E2E test (`e2e/e2e_test.go`, `//go:build e2e`; mirrors `TestE2E_CrossNodeRenewNudge`):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestE2E_CrossNodeTerminate` | POST terminate to the NON-owner replica → `200 {terminated:true}`; the owner drops the phone control connection and unbinds the route (`LookupRoute` transitions to `ok=false` on the shared Valkey) | enroll via replica A with the control connection owned by replica B (as in `TestE2E_CrossNodeRenewNudge`, via `echoPhone` — whose Go client does NOT auto-reconnect, so terminate leaves the route unbound: the correct, deterministic observable is the unbind, NOT a reconnect); build a `router.Registry` over the shared Valkey (a redis client from `redis.ParseURL(inf.redisURL)`), wait for the route bound on B, POST terminate to A, then `waitBool` until `LookupRoute` reports `ok=false` |

---

## US3 — Documentation + ground-up verification

Acceptance criteria:
- [x] `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md`, `docs/PROJECT.md`, `README.md` describe the two action
      endpoints and the generalized mesh control op; no doc mentions `/api/v1/admin/renew`.
- [x] `admin-terminate` appears in the connection-log close-reason enumeration.
- [x] All quality gates pass on the final code.

### Task 3.1 — Update the canonical docs

- [x] **Action** — modify `docs/PROTOCOL.md` §5 (mesh control paragraph): ops `renew` | `terminate`,
  response `{applied}`; `renew` forces a `RENEW_NUDGE`; `terminate` closes the owner's live phone control
  connection and evicts that node's in-flight public splices (`close_reason=admin-terminate`), after which
  the phone reconnects. These are the mechanisms behind `POST /api/v1/admin/tunnels/{name}/reissue` and
  `.../terminate`. Unknown op / missing tunnel → 400, non-POST → 405, op failure → 502.
- [x] **Action** — modify `docs/ARCHITECTURE.md`: (a) §8 — replace the `/api/v1/admin/renew` line with the
  two `/api/v1/admin/tunnels/{name}/reissue` + `/terminate` endpoints (owner-routed over the mesh control
  RPC); (b) §8 — add `admin-terminate` to the close-reason list on the connection-log line (~190); (c) §9 —
  amend the splice close-reason attribution sentence (~222-223, currently "…record `close_reason=server-shutdown`
  (`evicted` is reserved for saturation eviction, `ban-evict` for a ban reload)") to also name
  `admin-terminate` for an admin terminate, so the canonical splice-attribution set stays complete.
- [x] **Action** — modify `docs/PROJECT.md`: replace the `/api/v1/admin/renew` clause in the admin-surface
  sentence with the reissue + terminate endpoints.
- [x] **Action** — modify `README.md`: replace the `/api/v1/admin/renew` clause with the reissue +
  terminate endpoints.

Definition of Done:
- [x] `grep -n "admin/renew" README.md docs/PROJECT.md docs/ARCHITECTURE.md docs/PROTOCOL.md` returns
      nothing. (Scope to the canonical docs ONLY — NEVER `docs/plans/`: the sacred plan artifacts, incl. this
      plan and plan 8, legitimately contain `admin/renew` and MUST NOT be edited.)
- [x] Each doc states terminate is ephemeral (the phone reconnects) and attributed `admin-terminate`.

### Task 3.2 — Ground-up double-check + quality gates

- [x] **Action** — re-read this plan from the top and verify EVERY action landed: the close reason, the
  phone `Close`, the edge `EvictTunnelStreams` + attribution precedence, the mesh envelope/Controller, the
  `adminController` + construction reorder, the two endpoints, the removal of `/api/v1/admin/renew`
  (including the e2e caller migration), and the four doc updates. Confirm no stray reference remains via
  greps scoped to source + canonical docs (NEVER `docs/plans/`, whose sacred artifacts legitimately contain
  these tokens): `grep -rn 'adminRenewHandler\|renewController\|ControlResponse.Nudged\|postAdminRenew\|admin/renew' --include='*.go' .` returns nothing, and
  `grep -n 'admin/renew' README.md docs/PROJECT.md docs/ARCHITECTURE.md docs/PROTOCOL.md` returns nothing.
- [x] **Action** — run the full quality gates via the project commands and fix anything they surface:
  `make lint`, `make vet`, `make govulncheck`, `make test-unit`, `make test-integration`, `make test-e2e`,
  `make compose-config`, `make tidy` (drift check).

Definition of Done:
- [x] Every checkbox above is `[x]`; all gates green on the final code.

---

## Deviations

- **US2 Task 2.3 (e2e helper).** The plan specified renaming `postAdminRenew` → `postAdminReissue` and adding
  a peer `postAdminTerminate`. Both public helpers exist exactly as specified, but they are implemented as
  thin wrappers over one shared `postAdminAction(t, internalAddr, action, name, respField)` helper (which
  POSTs `.../tunnels/<name>/<action>` and decodes the result boolean under `respField` via a generic map) —
  to avoid duplicating the HTTP round-trip. No behavioral difference from the plan.
