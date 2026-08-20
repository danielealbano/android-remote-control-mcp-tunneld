<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 8 — Cross-node force-renew: `/admin/renew` + mesh `/mesh/control`

Add an operator endpoint that forces tunneld to emit a real `RENEW_NUDGE` to a phone, **from any
replica**, by routing the request to the node that actually holds the phone's `/control` connection. This
introduces a control-plane RPC on the replica mesh (`/mesh/control`) alongside the existing data splice
(renamed `/mesh` → `/mesh/data`), and exercises the phone-side nudge path (Kotlin reference client
on-device; Go reference client cross-node in CI).

## Context & key decisions (the decision record — not derivable from code)

- **Why:** nudging is NODE-LOCAL — `phoneconn.Manager.SendRenewNudge`/`ConnectedNames` only see phones
  bound to THIS node. The renewal watcher (`internal/server/schedulers.go`) nudges on a hardcoded 1h scan
  only when `ShouldRenew` is due, so there is no way to force a nudge on demand, and no cross-node way to
  nudge a phone whose owner replica is a different node.
- **Mesh gains a control plane.** The mesh was DATA-only (`POST /mesh` splice). We split it: `POST /mesh/data`
  (the existing opaque splice) and `POST /mesh/control` (a small JSON request/response for control ops,
  starting with `renew`). Both stay behind the existing mesh-role mTLS. The mesh MUST NOT import
  `phoneconn`/`enroll`, so the control operation is a `mesh.Controller` interface implemented in
  `internal/server` (mirrors the existing `OwnerCheck`/`Bridge` seams).
- **Direct rename** `/mesh` → `/mesh/data` (NO dual-serve/transition): nothing is deployed anywhere
  (no production/staging/test), so a coordinated cutover is free. The mesh is replica↔replica only — NOT
  the frozen phone-client wire contract — so this is not a phone-facing change.
- **`POST /admin/renew?tunnel=<name>`** on the INTERNAL listener (never published; same trust boundary as
  `/metrics` and `/admin/tunnels`). Route-aware: `router.LookupRoute(name)` → if the owner is THIS node,
  nudge locally; else `router.LookupNode(owner)` → mesh advertise addr → `meshClient.Control(...)` to the
  owner. `404` when no route is bound. The **owner node** mints the renewal nonce (the same
  `challengeFunc(enrollSvc)` the watcher uses), so the phone's follow-up `/issue` validates through the
  normal attestation path. Forced renewals count against the existing per-tunnel `IssuePerWeek` cap; no
  new auth (mesh mTLS + internal-only listener). No new configuration.
- **Testing split (agreed with the user):**
  - **Cross-node** (`/mesh/control` + the full owner-routing) is tested in the e2e tier with TWO in-process
    replicas sharing Valkey and the **Go** reference client (`client/`) as the phone: enroll via A, bind
    control on B (B owns), `POST /admin/renew` on **A**'s internal listener → A meshes to B → B nudges →
    the Go client renews. No device.
  - **Client-side on-device** is tested by folding a **local** `/admin/renew` nudge phase into the existing
    `TestE2E_ReferenceTunnelApp` (single replica, owner == that node): the Kotlin app decodes the
    `RENEW_NUDGE` frame → `Enroll.issue` → hot-swaps the cert.
- **Build note:** US1 changes `mesh.NewHandler`'s signature; the server.go call is updated at the start of
  US2 (first task). The full build/lint/test gates run once at the end of the plan (per
  `development_pipeline.md`), so the intermediate state is expected.

The ground-truth sources this plan mirrors: `internal/mesh/{client,listener}.go`,
`internal/server/{server,serve,schedulers}.go`, `internal/router/{route_e2e,nodes}.go`,
`internal/metrics/server.go`, `internal/phoneconn/manager.go`, `client/{control,renew,enroll}.go`,
`docs/PROTOCOL.md` §5, and the existing `e2e/e2e_test.go` two-replica pattern (`TestE2E_CrossNodeAndFastPath`).

---

## User Story 1 — [x] Mesh control channel (`/mesh/data` + `/mesh/control`)

Split the mesh into a data path and a control path; add a `renew` control op behind the existing
mesh-role mTLS, plus the mesh-client method to call it. Keep `mesh` free of `phoneconn`/`enroll` imports
via a `Controller` interface.

**Acceptance criteria:**
- [x] The mesh data splice is served at `POST /mesh/data` (renamed from `/mesh`); the client posts there.
- [x] `POST /mesh/control` accepts a JSON `{op, tunnel}`, dispatches `op:"renew"` to a `mesh.Controller`,
  and returns JSON `{nudged}`; unknown op → 400, non-POST → 405, missing tunnel → 400. Mesh-role mTLS is
  required (identity-role rejected), as for the data path.
- [x] `mesh.Client.Control(ctx, peer, ControlRequest)` posts to `/mesh/control` over the existing per-peer
  mTLS H2 pool and returns the decoded `ControlResponse`.
- [x] `docs/PROTOCOL.md` §5 documents `/mesh/data` + `/mesh/control`.

### Task 1.1 — [x] Split the listener path + add the control op (`internal/mesh/listener.go`)

**Actions:**
- [x] Add the control types + `Controller` seam and route by path. Modify `internal/mesh/listener.go`:

  ```go
  // Controller executes a mesh control op on THIS (owner) node. Implemented in internal/server (mesh MUST
  // NOT import phoneconn/enroll). Renew mints a fresh renewal nonce and enqueues a RENEW_NUDGE to the
  // named tunnel's live phone connection, returning whether it was enqueued.
  type Controller interface {
  	Renew(ctx context.Context, tunnel string) (bool, error)
  }

  // ControlRequest / ControlResponse are the /mesh/control JSON envelope (replica↔replica only).
  type ControlRequest struct {
  	Op     string `json:"op"`     // "renew"
  	Tunnel string `json:"tunnel"` // the tunnel name whose phone to nudge
  }

  type ControlResponse struct {
  	Nudged bool `json:"nudged"`
  }
  ```

  Add a `control Controller` field to `Handler` and thread it through `NewHandler`:

  ```go
  type Handler struct {
  	owns    OwnerCheck
  	bridge  Bridge
  	control Controller
  }

  // NewHandler builds the mesh handler.
  func NewHandler(owns OwnerCheck, bridge Bridge, control Controller) *Handler {
  	return &Handler{owns: owns, bridge: bridge, control: control}
  }
  ```

  Replace the `if r.URL.Path != "/mesh"` gate in `ServeHTTP` (after the mesh-role check) with a path switch,
  moving the existing data body into `serveData` and adding `serveControl`:

  ```go
  	// (mesh-role peer-cert check unchanged, above.)
  	switch r.URL.Path {
  	case "/mesh/data":
  		h.serveData(w, r)
  	case "/mesh/control":
  		h.serveControl(w, r)
  	default:
  		http.NotFound(w, r)
  	}
  }

  // serveData is the opaque bidirectional splice (the former POST /mesh body: method check, X-Tunnel/
  // X-Conn-Id/X-Stream-Id, owner connID check, bridge.OpenMesh + SpliceMesh) — moved from the old /mesh
  // handler. Its moved comments' `/mesh` references (this line, the `r.Method` note, and the `ownerStream`
  // doc that says "the /mesh request/response body") become `/mesh/data`, staying accurate with PROTOCOL §5.
  func (h *Handler) serveData(w http.ResponseWriter, r *http.Request) {
  	// ... unchanged data-splice body (comment path references updated to /mesh/data) ...
  }

  // serveControl handles the mesh control RPC (mesh-role mTLS already enforced by ServeHTTP).
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
  	switch req.Op {
  	case "renew":
  		if req.Tunnel == "" {
  			http.Error(w, "missing tunnel", http.StatusBadRequest)
  			return
  		}
  		nudged, err := h.control.Renew(r.Context(), req.Tunnel)
  		if err != nil {
  			http.Error(w, "renew failed", http.StatusBadGateway)
  			return
  		}
  		w.Header().Set("Content-Type", "application/json")
  		_ = json.NewEncoder(w).Encode(ControlResponse{Nudged: nudged})
  	default:
  		http.Error(w, "unknown op", http.StatusBadRequest)
  	}
  }
  ```
  - Add imports `encoding/json` (and confirm `io`, `net/http`, `context` are present). The mesh-role check
    at the top of `ServeHTTP` stays FIRST so it guards both paths.

**Definition of Done:**
- [x] `/mesh/data` serves the splice; `/mesh/control` dispatches `renew`; both reject non-mesh-role certs.

### Task 1.2 — [x] Mesh client: rename data POST + add `Control` (`internal/mesh/client.go`)

**Actions:**
- [x] In `OpenStream`, change the request URL `"https://"+peer+"/mesh"` → `"https://"+peer+"/mesh/data"`.
- [x] Add the control call (reuses the per-peer pool; `active` guards the pool against reaping for the
  request's duration):

  ```go
  // Control posts a mesh control RPC to peer over the per-peer mTLS H2 pool and returns the decoded
  // response. Short request/response (not a splice); the pool's active-count guards it against reaping.
  func (c *Client) Control(ctx context.Context, peer string, req ControlRequest) (ControlResponse, error) {
  	p := c.pool(peer) // active++
  	defer p.active.Add(-1)
  	hc := p.clients[int(p.next.Add(1))%len(p.clients)]

  	body, err := json.Marshal(req)
  	if err != nil {
  		return ControlResponse{}, err
  	}
  	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+peer+"/mesh/control", bytes.NewReader(body))
  	if err != nil {
  		return ControlResponse{}, err
  	}
  	httpReq.Header.Set("Content-Type", "application/json")
  	resp, err := hc.Do(httpReq)
  	if err != nil {
  		return ControlResponse{}, fmt.Errorf("mesh control %s: %w", peer, err)
  	}
  	defer func() { _ = resp.Body.Close() }()
  	if resp.StatusCode != http.StatusOK {
  		return ControlResponse{}, fmt.Errorf("mesh control %s: status %d", peer, resp.StatusCode)
  	}
  	var out ControlResponse
  	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
  		return ControlResponse{}, err
  	}
  	return out, nil
  }
  ```
  - Add imports `bytes`, `encoding/json` (confirm `io`, `net/http`, `fmt`, `context` present).

**Definition of Done:**
- [x] `OpenStream` posts `/mesh/data`; `Control` posts `/mesh/control` and decodes `{nudged}`.

### Task 1.3 — [x] Mesh tests + `docs/PROTOCOL.md` §5

**Actions:**
- [x] Update `internal/mesh/mesh_test.go` for the data-path rename and the `NewHandler` signature:
  - Every `NewHandler(owns, bridge)` call (incl. inside the `reqWithCert` helper) gains a fake controller
    argument; add a tiny `fakeController` (a func-backed `Renew`) to the shared test scaffolding.
  - Move EVERY request that must reach `serveData` from `/mesh` → `/mesh/data`: the `reqWithCert` `path`
    argument (it builds `https://node/<path>`) in `TestMeshRejectsMissingHeaders` (400), and the direct
    request URLs in `TestMesh_NonPostIs405` (GET, 405), `TestMeshNotOwner` (409),
    `TestMeshBridgesValidStream` (200), and `TestMeshHandler_DuplicateStreamAnswers422` (422/502/200). Also
    update `TestMesh_NonPostIs405`'s doc comment and its `t.Fatalf` message from `/mesh` → `/mesh/data` so
    they stay accurate.
  - Leave the two role-rejection tests (`TestMeshRejectsIdentityRoleCert`, `TestMeshRejectsNoCert`) on
    `"mesh"` — the 403 mesh-role check precedes the path switch, so they are path-agnostic. The `OpenStream`
    client tests use a path-agnostic test server, so only the data URL inside `OpenStream` (Task 1.2) changes.
- [x] Update `docs/PROTOCOL.md` §5 (lines ~166-171): the mesh stream is `POST /mesh/data`; add a paragraph
  that `POST /mesh/control` is a JSON `{op, tunnel}` → `{nudged}` control RPC (mesh-role mTLS), first op
  `renew`, replica↔replica only.

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestControlRenewDispatches` | `POST /mesh/control {op:"renew",tunnel:"t"}` calls the controller and returns `{nudged:true}` | mesh-role peer cert; fake controller returns `(true,nil)`; assert body |
| `TestControlUnknownOp` | unknown `op` → 400 | fake controller not called |
| `TestControlMissingTunnel` | `op:"renew"` with empty tunnel → 400 | — |
| `TestControlNonPostIs405` | a non-POST (GET) to `/mesh/control` with a mesh-role cert → 405 | maps the US1 non-POST acceptance criterion |
| `TestControlRejectsNonMeshRole` | `/mesh/control` with a non-mesh-role cert → 403 | reuses the data-path role assertion |
| `TestDataPathRenamed` | `POST /mesh/data` still splices; `POST /mesh` (old) → 404 | existing data body under the new path |
| `TestControlClient_Errors` | `Client.Control` decodes `{nudged}` on 200 and returns an error on a non-200 mesh response | httptest H2 server (mirror `TestMeshClient_Maps422ToDuplicateStream`) |

**Definition of Done:**
- [x] The mesh data-path rename and the control/data tests are in place; `docs/PROTOCOL.md` §5 reflects both paths.

---

## User Story 2 — [x] Force-renew admin endpoint (`POST /admin/renew`)

Wire a `mesh.Controller` implementation and a route-aware `/admin/renew` handler onto the internal
listener; restore the `mesh.NewHandler` call.

**Acceptance criteria:**
- [x] `POST /admin/renew?tunnel=<name>` on the internal listener returns `200 {tunnel, owner, nudged}` when
  the owner is reachable, `404` when no route is bound, `400` when `tunnel` is missing, `405` for non-POST.
- [x] When the owner is THIS node it nudges locally; when the owner is another node it forwards via
  `meshClient.Control` to that node, which nudges locally. The owner mints the renewal nonce
  (`challengeFunc(enrollSvc)`) either way.
- [x] `/metrics`, `/healthz`, `/admin/tunnels` still served (the internal mux composes the existing
  `metrics.Handler`).

### Task 2.1 — [x] `renewController` + restore the mesh handler wiring (`internal/server`)

**Actions:**
- [x] Add `renewController` (implements `mesh.Controller`) in `internal/server/serve.go`:

  ```go
  // renewController is this node's mesh.Controller: it mints a fresh renewal nonce (the same challenge the
  // renewal watcher uses) and enqueues a RENEW_NUDGE to the tunnel's LOCAL phone connection. Used both
  // directly by the /admin/renew local path and by the mesh /mesh/control handler on the owner node.
  type renewController struct {
  	mgr   *phoneconn.Manager
  	nonce func(ctx context.Context) (string, error)
  }

  func (rc *renewController) Renew(ctx context.Context, tunnel string) (bool, error) {
  	nonceHex, err := rc.nonce(ctx)
  	if err != nil {
  		return false, err
  	}
  	return rc.mgr.SendRenewNudge(tunnel, nonceHex, ""), nil
  }
  ```
- [x] In `internal/server/server.go`, construct it once and pass it to `mesh.NewHandler` (updating the
  existing call at the mesh-handler construction site):

  ```go
  	renewCtl := &renewController{mgr: phoneMgr, nonce: challengeFunc(enrollSvc)}
  	meshHandler := mesh.NewHandler(phoneMgr.OwnsConn,
  		&bridgeAdapter{mgr: phoneMgr, dialBackTimeout: cfg.LimitDialBackTimeout}, renewCtl)
  ```

**Definition of Done:**
- [x] `internal/server` compiles; the mesh handler carries a working controller.

### Task 2.2 — [x] Route-aware `/admin/renew` handler + internal mux (`internal/server/server.go`)

**Actions:**
- [x] Add the handler (route-aware; local via `renewCtl`, remote via `meshClient.Control`):

  ```go
  // adminRenewHandler forces a RENEW_NUDGE for ?tunnel=<name>, routing to the owner node. Internal-listener
  // only (never published). 404 when no route is bound; the owner mints the nonce and enqueues the nudge.
  // ctl is the mesh.Controller INTERFACE (renewController satisfies it) so the local-nudge path is unit
  // testable with a stub — consistent with the OwnerCheck/Bridge/Controller consumer-site seams.
  func adminRenewHandler(nodeID string, reg *router.Registry, ctl mesh.Controller, mc *mesh.Client, log *slog.Logger) http.HandlerFunc {
  	return func(w http.ResponseWriter, r *http.Request) {
  		if r.Method != http.MethodPost {
  			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
  			return
  		}
  		name := r.URL.Query().Get("tunnel")
  		if name == "" {
  			http.Error(w, "missing tunnel", http.StatusBadRequest)
  			return
  		}
  		owner, _, _, ok, err := reg.LookupRoute(r.Context(), name)
  		if err != nil {
  			log.Warn("admin renew: route lookup failed", "tunnel", name, "err", err)
  			http.Error(w, "route lookup failed", http.StatusInternalServerError)
  			return
  		}
  		if !ok {
  			http.Error(w, "no route bound for tunnel", http.StatusNotFound)
  			return
  		}
  		var nudged bool
  		if owner == nodeID {
  			nudged, err = ctl.Renew(r.Context(), name)
  		} else {
  			addr, addrOK, lerr := reg.LookupNode(r.Context(), owner)
  			if lerr != nil || !addrOK {
  				log.Warn("admin renew: owner node unresolved", "tunnel", name, "owner", owner, "err", lerr)
  				http.Error(w, "owner node unavailable", http.StatusBadGateway)
  				return
  			}
  			var res mesh.ControlResponse
  			res, err = mc.Control(r.Context(), addr, mesh.ControlRequest{Op: "renew", Tunnel: name})
  			nudged = res.Nudged
  		}
  		if err != nil {
  			log.Warn("admin renew: nudge failed", "tunnel", name, "owner", owner, "err", err)
  			http.Error(w, "renew failed", http.StatusBadGateway)
  			return
  		}
  		w.Header().Set("Content-Type", "application/json")
  		_ = json.NewEncoder(w).Encode(map[string]any{"tunnel": name, "owner": owner, "nudged": nudged})
  	}
  }
  ```
- [x] Compose the internal mux (replace the single `metrics.Handler` at the `internalSrv` construction so
  `/admin/renew` is mounted and everything else delegates to the existing handler):

  ```go
  	internalMux := http.NewServeMux()
  	internalMux.Handle("/admin/renew", adminRenewHandler(nodeID, reg, renewCtl, meshClient, logger))
  	internalMux.Handle("/", metrics.Handler(m.Registry(), rdb, adminStore, logger))
  	internalSrv := &http.Server{Addr: cfg.InternalListen, ReadHeaderTimeout: readHeaderTimeout,
  		Handler: internalMux}
  ```
  - `metrics.Handler`'s signature is UNCHANGED (no churn to its tests); `/admin/tunnels`, `/metrics`,
    `/healthz` still resolve via the `"/"` delegate.
  - Confirm `encoding/json`, `log/slog`, `net/http`, and the `router`/`mesh` packages are imported in
    `server.go` (router + mesh already are).

**Test (compressed) — handler-level, no containers:**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestAdminRenew_NonPost` | a non-POST (GET) request → 405 | maps the US2 non-POST acceptance criterion |
| `TestAdminRenew_MissingTunnel` | no `?tunnel` → 400 | httptest request to the handler |
| `TestAdminRenew_NoRoute` | `LookupRoute` ok=false → 404 | fake registry via miniredis (mirror existing router unit tests) |
| `TestAdminRenew_Local` | owner==nodeID → `ctl.Renew` called, `200 {tunnel,owner,nudged:true}` | inject a stub `mesh.Controller` returning `(true,nil)`; registry (owner==this node) via miniredis |

**Definition of Done:**
- [x] `/admin/renew` compiles and its local + error paths are unit-covered; internal mux composes cleanly.

---

## User Story 3 — [x] Cross-node e2e test (Go client)

Prove the full cross-node path: `/admin/renew` on a non-owner replica → mesh `/mesh/control` → owner
nudges → the Go reference client renews.

**Acceptance criteria:**
- [x] The e2e harness exposes each replica's internal-listener address, and `echoPhone` exposes the live
  `*client.Client` so a renewal can be observed via `client.Identity().PublicCertPEM`.
- [x] `TestE2E_CrossNodeRenewNudge`: two replicas share the infra; enroll via A, control on B (B owns);
  `POST /admin/renew?tunnel=<name>` to **A**'s internal listener; the Go client's public cert rotates.

### Task 3.1 — [x] Expose the internal addr + the live client (`e2e/e2e_test.go`)

**Actions:**
- [x] Reuse the EXISTING `inf.internal` map for the internal-listener address: `runReplicaOnce` already
  records `inf.internal[edgeAddr] = internalAddr` before returning, and `TestE2E_Quota` already reads
  `inf.internal[edge]`. The new tests read the internal addr the same way, so NO `startReplica`/
  `runReplicaOnce` signature change is needed (reconciled with existing code — see Deviations).
- [x] Change `echoPhone` to return the live client too: `func echoPhone(...) (*client.Client, *client.Identity)`
  (it already builds and runs `c`; return it alongside `ident`). All THREE existing callers in
  `e2e/e2e_test.go` — `TestE2E_CrossNodeAndFastPath`, `TestE2E_Quota`, `TestE2E_Eviction` — use only the
  identity, so update each to `_, ident := echoPhone(...)`. Only the new `TestE2E_CrossNodeRenewNudge` keeps
  the client (`c, ident := echoPhone(...)`) to observe the renewal.

**Definition of Done:**
- [x] The internal-listener address is exposed via the existing `inf.internal[edge]` map (no signature
  change); `echoPhone` returns `(*client.Client, *client.Identity)` with the three existing callers switched
  to `_, ident := echoPhone(...)`; the e2e package still builds under `-tags=e2e`.

### Task 3.2 — [x] The cross-node renew test (`e2e/e2e_test.go`)

**Actions:**
- [x] A small helper `postAdminRenew(t, internalAddr, name) (status int, nudged bool)` that `POST`s
  `http://<internal>/admin/renew?tunnel=<name>`, returns the HTTP status code, and decodes `{nudged}` only
  on a 200 (so callers assert both the 200/nudged path and the 404 no-route path).

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestE2E_CrossNodeRenewNudge` | `/admin/renew` on a NON-owner replica forces the owner to nudge; the Go client renews its public cert | two replicas edgeA+edgeB (`startE2EInfra`); `c, ident := echoPhone(edgeA, edgeB)` (edgeB owns); wait for the route to bind; capture `sha256(c.Identity().PublicCertPEM)`; `postAdminRenew(inf.internal[edgeA], ident.Name)` returns `(200, true)`; poll until `c.Identity().PublicCertPEM` hash changes (renewed via the nudge); assert `postAdminRenew(inf.internal[edgeA], "nosuchtunnel")` returns status `404` |

**Definition of Done:**
- [x] With two replicas, a renew posted to the non-owner replica rotates the Go client's cert; an unknown
  tunnel is 404.

---

## User Story 4 — [x] Device reference test: local nudge phase

Fold a server-nudge phase into the on-device reference test so the Kotlin app's `RENEW_NUDGE` decode →
`Enroll.issue` → cert hot-swap path is exercised on real hardware (single replica → local `/admin/renew`).

**Acceptance criteria:**
- [x] After the manual-`refresh` phase, `TestE2E_ReferenceTunnelApp` captures the current `/info`
  `tls_cert_sha256`, `POST`s `/admin/renew?tunnel=<name>` to the replica's internal listener (asserting
  `nudged==true`), and asserts the served cert digest changes (the app rotated purely from the nudge — no
  `refresh` broadcast), with the app nonce unchanged and the cert still validating.

### Task 4.1 — [x] Add the nudge phase (`e2e/tunnel_app_test.go`)

**Actions:**
- [x] Read the replica's internal-listener address from the existing `inf.internal[edge]` map (the
  `startReplica` signature is unchanged — see Task 3.1 / Deviations). Reuse the `postAdminRenew` helper from US3.
- [x] After the refresh assertions, add: capture `f2` (current `/info` digest); `postAdminRenew(inf.internal[edge], name)`
  (assert it returns `(200, true)`); `waitBool` until `/info` `tls_cert_sha256` != `f2`; assert the nonce is
  unchanged and re-run `assertPhoneCert`. Reuse the same FGS/ALPN harness helpers — no new app behavior.

**Test (compressed):** extends `TestE2E_ReferenceTunnelApp` (no new test function).

**Definition of Done:**
- [x] On a connected device the nudge phase rotates the cert via the RENEW_NUDGE path; skips without a device.

---

## User Story 5 — [x] Documentation + ground-up verification

**Acceptance criteria:**
- [x] `docs/ARCHITECTURE.md`, `docs/PROJECT.md`, and `README.md` mention `/admin/renew` where they
  enumerate the internal listener endpoints (`/metrics`, `/healthz`, `/admin/tunnels`); `docs/PROTOCOL.md` §5 reflects
  `/mesh/data` + `/mesh/control` (from US1). `.claude/rules/project.md` stays accurate (commit scopes).
- [x] Everything verified from the ground up.

### Task 5.1 — [x] Docs

**Actions:**
- [x] Add `/admin/renew` to the internal-listener endpoint lists in `docs/ARCHITECTURE.md`,
  `docs/PROJECT.md`, and `README.md` (force a renewal for a tunnel; routes to the owner over
  `/mesh/control`; internal-only). Do NOT duplicate the wire detail — cross-reference `docs/PROTOCOL.md` §5.

**Definition of Done:**
- [x] Docs are truthful about the endpoint and the mesh control path; no duplication.

### Task 5.2 — [x] Final ground-up verification (double-check EVERYTHING)

**Actions:**
- [x] Re-read this plan top to bottom; confirm every task/action + acceptance criterion is implemented.
- [x] Confirm the mesh split is complete: NO `"/mesh"` data path remains (client posts `/mesh/data`;
  listener serves `/mesh/data` + `/mesh/control`); `grep -rn '"/mesh"' internal/` returns nothing.
- [x] Confirm `mesh` still imports NO `phoneconn`/`enroll` (the `Controller` seam holds).
- [x] Confirm `/admin/renew` is internal-listener only and never wired to the public edge or mesh listener;
  the owner mints the nonce; forced renewals are subject to `IssuePerWeek`.
- [x] Run the FULL quality gates (`make build vet lint govulncheck test-unit test-integration test-e2e
  test-scripts compose-config` + `make tidy`), capturing logs per the tee rule. `test-e2e` MUST include
  `TestE2E_CrossNodeRenewNudge` PASSING (no device) AND `TestE2E_ReferenceTunnelApp` (with its new nudge
  phase) PASSING with a device connected.
- [x] Confirm hygiene: no AI attribution, no plan/finding IDs in code or commit messages, placeholders only,
  and NO out-of-scope files changed.

**Definition of Done:**
- [x] All gates pass on the final code; the cross-node test passes in CI; the device nudge phase passes with
  a device and skips without one; the ground-up re-read finds zero gaps.

---

## Deviations

_(recorded during implementation per agent.md §2)_

- **Task 3.1 / Task 4.1 — internal-listener address reuses the existing `inf.internal` map (NO
  `replicaAddrs` struct / NO `startReplica` signature change).** The plan proposed changing
  `runReplicaOnce`/`startReplica` to return a `replicaAddrs{edge, internal}` struct and updating all six
  `startReplica` callers to `.edge`. The current `e2e/e2e_test.go` already exposes each replica's internal
  address via the `inf.internal` map (`runReplicaOnce` records `inf.internal[edgeAddr] = internalAddr`
  before returning, at `e2e/e2e_test.go`), and `TestE2E_Quota` already reads it as `inf.internal[edge]`.
  The new cross-node test and the device nudge phase read the internal address the same way
  (`inf.internal[edgeA]` / `inf.internal[edge]`). Introducing `replicaAddrs` would DUPLICATE that existing
  mechanism and churn six callers for no behavioral gain, so `startReplica`/`runReplicaOnce` keep their
  `string` return. **Why:** reconcile with existing code and avoid a redundant parallel mechanism (the
  established idiom in this file is `inf.internal[edge]`). Only the intended `echoPhone` signature change
  (return the live `*client.Client`) was applied, with its three existing callers switched to
  `_, ident := echoPhone(...)`. All US3/US4 acceptance criteria are met and both e2e tests pass.
