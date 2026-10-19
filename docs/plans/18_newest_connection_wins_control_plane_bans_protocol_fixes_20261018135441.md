<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 18 — Newest connection wins, control-plane tunnel bans, issuance answers, app fixes, PROTOCOL.md corrections

## Decisions (user, 2026-10-17/18) — FIXED, reviewers MUST NOT change them

- **D1 Route ownership.** The route `tunnel:{name}` stores NO certificate fingerprint. Any identity certificate that
  passes the existing checks (chains to the internal CA, unexpired, not mesh-role, valid name, name not banned) binds,
  and the new control connection REPLACES the previous one whatever its generation: same node → the old one is closed
  at once; other node → the old one closes at its next heartbeat (`HeartbeatNotOwner`). No 409. The heartbeat's
  self-heal path stops comparing fingerprints.
- **D2 Bans.** `tunnel-fingerprint` bans are REMOVED (parser, engine, docs). The public edge NO LONGER checks tunnel
  bans and `EvictBannedStreams` is REMOVED. The edge keeps its peer-address (ip / cidr / country) check. Tunnel-name
  bans stay enforced at the control plane: on connect (`/api/v1/control`, `/api/v1/issue`, the mTLS dial-back) and on
  reload via `EvictBanned` (name only); the banned phone's splices then end on every node through the existing
  `evict` broadcast (`ban-evict`), the per-splice route check being the fallback. The window in which nodes disagree
  about a ban (each node polls its own ban files) is ACCEPTED. A leftover `tunnel-fingerprint` line is skipped with a
  warning (unknown kind); the nodes' ban files are checked before rollout.
- **D3** `/api/v1/control` over HTTP/1.x is refused with `505`. HTTP/1.1 stays for `/api/v1/data`; `/api/v1/issue`
  keeps working over HTTP/2 and HTTP/1.1.
- **D4** The weekly-cap refusal (`issuance_cap`) carries the real time left on the name's 7-day window, not a flat
  604800 s. The in-flight `issuance_cap` hint (300 s) is unchanged.
- **D5** `identity_sign_failed` becomes `503` with `retryable: true`.
- **D6** The server caps the whole `/api/v1/issue` handler at 390 s; PROTOCOL.md tells clients to allow at least
  400 s; both apps' `/issue` read timeout goes from 300 s to 400 s (the enroll POST keeps its 300 s). No time is
  reserved inside the 390 s for the bookkeeping after a successful ACME order (user, 2026-10-18).
- **D7 Apps (reference AND soak, same code).** `stop` cancels the control call at once (no late `OPEN` /
  `RENEW_NUDGE` is acted on; a late renewal cannot recreate a forgotten identity); the dial-back has ONE 10 s
  deadline for connect + TLS + upgrade together; the dial-back sessions/splices opened through a control connection
  close when it ends; a non-200 `/control` answer closes the request body too.
- **D8** Idle public connections (≈60 s via the min-rate rule): NO code change, documented only.
- **D9** Attestation roots: NO pinning; the root source is documented only.
- **D10** ClientHello single-record limit: no change, not documented.
- **D11** PROTOCOL.md: fix every listed error, fill every listed gap, and state the corrected facts where the claims
  overstated (US6).
- **D12** Wrong comments: remove the word "rolling" at `internal/limit/issuance.go` (both places), the `§1` reference
  at `internal/ca/ca.go:17`, and the `§6` reference at `internal/ban/dbip.go:77`.
- Not changed (user): nonce purpose binding, attestation package-name check, LE-only default, the soak app's
  `PhoneStore` keeping no previous-generation aliases.
- A splice on a non-owner node whose route check runs in the instant between the owner's unbind and its evict
  broadcast is logged `phone-close` instead of `ban-evict`: a label only, not relevant (user, 2026-10-18).
- The reference and soak apps are test apps: they support ONLY the specific command sequences our tests and soak runs
  use, not random manual use. Command orderings those never issue (e.g. `forget` while `enroll` is still issuing) are
  out of scope (user, 2026-10-18).
- No plan numbers are added to ARCHITECTURE.md, PROJECT.md, PROTOCOL.md, the README, `.claude/rules/` or any similar doc
  (SACRED user rule, 2026-10-18).
- No new code comments: code changes only remove the wrong part of an existing comment that a change makes wrong; no
  comment text is added anywhere (Go, Kotlin, tests).
- No production retro-compat (zero clients): a stale `fingerprint` field left in a live `tunnel:{name}` hash is
  ignored and expires with the key; no migration.

## [x] User Story 1 — Tunnel bans: name only, control plane only

Remove fingerprint bans and the edge's tunnel-ban checks (D2), so the control plane alone revokes a tunnel.

Acceptance criteria:
- [x] A `tunnel-fingerprint` line in a ban file is skipped with a warning; the rest of the file loads.
- [x] `ban.Engine.MatchTunnel` takes only a name.
- [x] `phoneconn` bans by name on `/api/v1/control`, `/api/v1/issue` and the mTLS dial-back; `EvictBanned` matches by name.
- [x] The edge has no tunnel-ban dependency, no `EvictBannedStreams`, and no `activeStream.fp`; its peer-address ban is unchanged.
- [x] A banned phone's splices still end on every node through the `evict` broadcast (`ban-evict`).

### [x] Task 1.1 — Ban package

[x] **Action 1.1.1** — modify `internal/ban/parse.go`:

```diff
-	case "ip", "cidr", "country", "tunnel-name", "tunnel-fingerprint":
+	case "ip", "cidr", "country", "tunnel-name":
@@
-// wanted country codes (expanded later against the DB-IP CSV), and name/fingerprint bans.
+// wanted country codes (expanded later against the DB-IP CSV), and name bans.
 type parsed struct {
-	prefixes     []prefixSource
-	countries    map[string]Source // country code → representative source
-	names        map[string]Source
-	fingerprints map[string]Source
+	prefixes  []prefixSource
+	countries map[string]Source // country code → representative source
+	names     map[string]Source
 }
@@ parseFile
 	p := parsed{
-		countries:    map[string]Source{},
-		names:        map[string]Source{},
-		fingerprints: map[string]Source{},
+		countries: map[string]Source{},
+		names:     map[string]Source{},
 	}
@@
-		case "tunnel-fingerprint":
-			src.Reason, src.Detail = ReasonTunnelFingerprint, value
-			p.fingerprints[value] = src
 		}
```

[x] **Action 1.1.2** — modify `internal/ban/engine.go`:

```diff
 type snapshot struct {
 	table *bart.Table[Source]
 	names map[string]Source
-	fps   map[string]Source
 }
@@
-	return &snapshot{table: &bart.Table[Source]{}, names: map[string]Source{}, fps: map[string]Source{}}
+	return &snapshot{table: &bart.Table[Source]{}, names: map[string]Source{}}
@@
-// MatchTunnel reports whether the tunnel name or certificate fingerprint is banned.
-func (e *Engine) MatchTunnel(name, fingerprint string) (Source, bool) {
+// MatchTunnel reports whether the tunnel name is banned.
+func (e *Engine) MatchTunnel(name string) (Source, bool) {
 	s := e.current.Load()
 	if src, ok := s.names[name]; ok {
 		return src, true
 	}
-	if src, ok := s.fps[fingerprint]; ok {
-		return src, true
-	}
 	return Source{}, false
 }
@@ build
 	names := map[string]Source{}
-	fps := map[string]Source{}
 	countries := map[string]Source{}
@@
 		maps.Copy(names, p.names)
-		maps.Copy(fps, p.fingerprints)
@@
-	return &snapshot{table: table, names: names, fps: fps}, nil
+	return &snapshot{table: table, names: names}, nil
```

[x] **Action 1.1.3** — modify `internal/ban/entry.go`: package comment `(IP/CIDR/country/tunnel-name/` + `// tunnel-fingerprint)` →
`(IP/CIDR/country/tunnel-name)`; delete `ReasonTunnelFingerprint Reason = "banned_tunnel_fingerprint"`.

[x] **Action 1.1.4** — modify `internal/ban/watch.go:16`: `// onReload (passed to Run) is how live name/fingerprint revocation reaches` →
`// onReload (passed to Run) is how live name revocation reaches`.

[x] **Action 1.1.5** — modify `internal/ban/dbip.go:77` (D12): `// previous snapshot rather than silently dropping every country ban (docs/ARCHITECTURE.md §6).` →
`// previous snapshot rather than silently dropping every country ban.`

Definition of Done:
- [x] `internal/ban` has no fingerprint ban kind, field, reason or comment.

### [x] Task 1.2 — Phone connections ban by name

[x] **Action 1.2.1** — modify `internal/phoneconn/listener.go`:

```diff
-// BanTunnel reports whether (name, fingerprint) is banned.
-type BanTunnel func(name, fingerprint string) bool
+// BanTunnel reports whether name is banned.
+type BanTunnel func(name string) bool
@@ ServeHTTP
-	if h.banTunnel != nil && h.banTunnel(id.name, id.fingerprint) {
+	if h.banTunnel != nil && h.banTunnel(id.name) {
```

[x] **Action 1.2.2** — modify `internal/phoneconn/dialback.go:107`: `h.banTunnel(id.name, id.fingerprint)` → `h.banTunnel(id.name)`.

[x] **Action 1.2.3** — modify `internal/phoneconn/manager.go`:

```diff
-// EvictBanned closes every live connection whose (name, fingerprint) matches the ban predicate,
+// EvictBanned closes every live connection whose name matches the ban predicate,
 // recording ban-evict. Wired to the ban-reload hook in server.Run.
-func (m *Manager) EvictBanned(match func(name, fingerprint string) bool) {
+func (m *Manager) EvictBanned(match func(name string) bool) {
@@
-		if match(c.name, c.fingerprint) {
+		if match(c.name) {
```

[x] **Action 1.2.4** — modify `internal/phoneconn/meta.go:4` (package comment): `tunnel-name/fingerprint ban enforcement` → `tunnel-name ban enforcement`.

Definition of Done:
- [x] Every tunnel-ban call in `internal/phoneconn` passes only the name.

### [x] Task 1.3 — Edge: no tunnel bans, no ban sweep

[x] **Action 1.3.1** — modify `internal/edge/edge.go`: delete the `banTun    func(name, fingerprint string) bool` field and
drop the parameter from `New`:

```diff
-func New(cfg Config, ban func(netip.Addr) bool, banTun func(string, string) bool,
+func New(cfg Config, ban func(netip.Addr) bool,
 	rec Recorder, r Router, dialBacks DialBackWaiter, opener Opener, ready DialBackReadiness, lim StreamLimiter,
 	logs PhoneEventSink, chal ACMEChallenges, addr net.Addr) *Edge {
 	return &Edge{
-		cfg: cfg, ban: ban, banTun: banTun, rec: rec, router: r, dialBacks: dialBacks, opener: opener, ready: ready,
+		cfg: cfg, ban: ban, rec: rec, router: r, dialBacks: dialBacks, opener: opener, ready: ready,
```

[x] **Action 1.3.2** — modify `internal/edge/bridge.go`:
- `activeStream`: delete the `fp         string       // the route fingerprint this stream targets (ban sweeps match on it)`
  field (`banned` stays: `EvictConnStreams` sets it for `ban-evict`).
- Delete `EvictBannedStreams` and its doc comment.
- `handleTunnel`:

```diff
-// handleTunnel resolves the route, enforces the ban + global stream cap (with one evict-and-retry),
+// handleTunnel resolves the route, enforces the global stream cap (with one evict-and-retry),
@@
-	nodeID, fp, connID, ok, err := e.router.LookupRoute(ctx, name)
+	nodeID, _, connID, ok, err := e.router.LookupRoute(ctx, name)
@@
-	if e.banTun != nil && e.banTun(name, fp) {
-		e.rec.Reject("ban", name, peerAddr(client))
-		closeLogged(e.cfg.Logger, "public client", client)
-		return
-	}
@@
-	// close) — and retry once when the fresh route differs (re-checking the ban on its fingerprint).
+	// close) — and retry once when the fresh route differs.
@@
-		n2, fp2, c2, ok2, lerr := e.router.LookupRoute(ctx, name)
+		n2, _, c2, ok2, lerr := e.router.LookupRoute(ctx, name)
@@
 		if lerr == nil && ok2 && (n2 != nodeID || c2 != connID) {
-			if e.banTun != nil && e.banTun(name, fp2) {
-				e.rec.Reject("ban", name, peerAddr(client))
-				closeLogged(e.cfg.Logger, "public client", client)
-				return
-			}
-			fp = fp2 // the splice now targets the re-bound route: the active stream must carry ITS fingerprint (ban sweeps match on it)
 			openedVia = c2
@@
-	as := &activeStream{tunnel: name, member: token, connID: openedVia, parent: ctx, fp: fp, started: e.now(), cancel: cancel}
+	as := &activeStream{tunnel: name, member: token, connID: openedVia, parent: ctx, started: e.now(), cancel: cancel}
@@
-	// A ban reload during the dial-back wait sweeps only TRACKED streams; re-check now that we are
-	// tracked so a tunnel banned in that window does not keep one live splice (docs/PROJECT.md §2 — a
-	// reload stops live traffic, not only new admissions). The deferred untrackStream/slot
-	// release run on this early return, and the client socket is closed like every sibling rejection.
-	if e.banTun != nil && e.banTun(name, fp) {
-		e.rec.Reject("ban", name, peerAddr(client))
-		closeLogged(e.cfg.Logger, "public client", client)
-		return
-	}
```
The two lookups take the 4-result form in Task 2.3.

Definition of Done:
- [x] `internal/edge` (non-test) has no `banTun`, no `EvictBannedStreams` and no `activeStream.fp`; `accept.go`'s peer-address ban is untouched.

### [x] Task 1.4 — Server wiring

[x] **Action 1.4.1** — modify `internal/server/server.go`:

```diff
-	banTunnel := func(name, fp string) bool { _, b := banEng.MatchTunnel(name, fp); return b }
+	banTunnel := func(name string) bool { _, b := banEng.MatchTunnel(name); return b }
@@ edge.New(...)
-	}, banIP, banTunnel, rec,
+	}, banIP, rec,
@@ ban watcher hook
-			phoneMgr.EvictBanned(func(name, fp string) bool { _, b := e.MatchTunnel(name, fp); return b })
-			ed.EvictBannedStreams(func(name, fp string) bool { _, b := e.MatchTunnel(name, fp); return b })
+			phoneMgr.EvictBanned(func(name string) bool { _, b := e.MatchTunnel(name); return b })
```

Definition of Done:
- [x] The reload hook calls only `phoneMgr.EvictBanned`; `banTunnel` still feeds `HandlerConfig.BanTunnel`.

### [x] Task 1.5 — Tests for US1

[x] **Action 1.5.1** — add/update/delete the tests below.

| Test | Verifies | Notes |
|---|---|---|
| `TestMatchTunnelName` (replaces `TestMatchTunnelNameAndFingerprint`, `internal/ban/engine_test.go`) | a `tunnel-name` ban matches that name; another name does not | |
| `TestFreshEnginePanicSafe` (update, `engine_test.go:42`) | 1-arg `MatchTunnel` on a fresh engine | |
| `TestParseHandlesAllEntryKinds` (update, `parse_test.go`) | ip / cidr / country / tunnel-name parse; `tunnel-fingerprint` now returns the unknown-kind error | |
| `TestLoad_TunnelFingerprintLineSkipped` (new, `internal/ban`) | a file with `tunnel-fingerprint sha256:aa` and `tunnel-name abc` loads: `skipping malformed ban line` is logged for the fingerprint line and `MatchTunnel("abc")` matches | temp file + `slog` text handler on a buffer |
| `TestServeHTTP_TunnelNameBanGates` (new, `internal/phoneconn/listener_test.go`) | for `/api/v1/control` and `/api/v1/issue`: a valid identity whose name `BanTunnel` reports → 403 `banned`, `Reject("ban", name, ip)` recorded, nothing registered, `OnIssue` not called | table test over the two paths; `tlsRequest` with `ProtoMajor = 2` |
| dial-back ban tests (update, `dialback_test.go:97` and the status table) | 1-arg `BanTunnel`; a banned name on an mTLS dial-back → 403 | |
| `TestEvictBanned` and the `ban-evict` row of `TestManager_Teardown_NotifiesClosedHook` (update, `manager_test.go:273`, `:629`) | `EvictBanned(func(name string) bool)` closes the named connection with `ban-evict` and notifies the closed hook | |
| `client/harness_test.go:172` (update) | 1-arg `BanTunnel` | |
| `internal/edge` (update) | `newTestEdge(t, cfg, banIP)` without the tunnel-ban parameter, all callers | |
| deleted (they test the removed edge tunnel-ban behaviour) | `TestEvictBannedStreams_KillsMatching` (`fixes_test.go:808`), `TestHandleTunnel_RetryPathBanRecordsBan` (`fixes_test.go:940`), `TestEdge_HandleTunnel_RouteBan_Close` (`accept_test.go:115`), `TestBridge_BanDuringDialbackEvictsStream` (`bridge_test.go:23`) | `TestSpliceReason_BannedBeatsTerminated` stays (it sets `banned` directly) |
| `TestE2E_TunnelNameBanEndsSplicesOnEveryNode` (new, `e2e/e2e_test.go`) | replica B runs with a ban file and owns the Go client's control connection; a live splice enters through replica A; appending `tunnel-name <name>` to B's ban file right after the splice is established ends the splice through A within 8 s of the splice's start, and the client's `Run` returns | ending before the splice's first route check (10 s after it starts, `bridge.go` `routeCheckInterval`) shows the evict broadcast ended it; `replicaOpts` gains `banFile` (→ `cfg.BanFile`) |
| existing coverage of US1 AC5 (unchanged, must keep passing) | `TestManager_Teardown_NotifiesClosedHook` (`ban-evict` reaches the closed hook), `TestSpliceEvictor_EvictsLocallyAndBroadcasts` (`serve_test.go:477`, local eviction + broadcast), `TestEdge_EvictConnStreams_OnlyThatConnection` (`bridge_test.go:283`) | |

Definition of Done:
- [x] Every row is done; the only deleted tests are the four listed.

## [x] User Story 2 — A new control connection replaces the old one

Drop the route fingerprint and the 409 (D1), so a phone that renewed its identity reconnects at once instead of being refused.

Acceptance criteria:
- [x] `BindRoute(ctx, name, nodeID, connID)` replaces any owner (last writer wins); `ErrConnIDCollision` stays.
- [x] `BindRouteIfAbsentOrOwner(ctx, name, nodeID, connID)` binds when absent, refreshes when the connID matches, answers `SelfHealNotOwner` otherwise.
- [x] `LookupRoute` returns `(nodeID, connID, ok, err)`; new binds write `node`, `connID` and the byte counters only.
- [x] `/api/v1/control` never answers 409; a second connection for a name with another valid identity cert supersedes the first (same node at once; other node at its next heartbeat).
- [x] `ca.Fingerprint` and the phone identity's certificate fingerprint are gone.

### [x] Task 2.1 — Router

[x] **Action 2.1.1** — modify `internal/router/route_e2e.go` (replace `BindRoute`, `BindRouteIfAbsentOrOwner`, `bindHSet`, `LookupRoute`):

```go
// BindRoute writes tunnel:{name} with node and per-connection connID (a connID equal to the currently-stored
// one → ErrConnIDCollision, the re-roll signal), serialized by the per-name lock. Otherwise last-writer-wins.
// Heartbeat/Unbind stay owner-conditional on connID.
func (r *Registry) BindRoute(ctx context.Context, name, nodeID, connID string) error {
	return r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "connID").Result()
		if err != nil {
			return err
		}
		if cid, _ := vals[0].(string); cid == connID {
			return ErrConnIDCollision
		}
		return bindHSet(ctx, r, name, nodeID, connID, true) // fresh owner → zero the byte fields
	})
}

// BindRouteIfAbsentOrOwner is the self-heal variant used by the phone heartbeat's "missing" path: it binds
// only if the key is absent or still owned by this connID, under the per-name lock.
func (r *Registry) BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, connID string) (SelfHealResult, error) {
	var res SelfHealResult
	err := r.withLock(ctx, name, func() error {
		vals, err := r.rdb.HMGet(ctx, key(name), "node", "connID").Result()
		if err != nil {
			return err
		}
		node, _ := vals[0].(string)
		cid, _ := vals[1].(string)
		if node == "" { // absent → fresh bind (zero the byte fields)
			res = SelfHealBound
			return bindHSet(ctx, r, name, nodeID, connID, true)
		}
		if cid != connID {
			res = SelfHealNotOwner
			return nil
		}
		res = SelfHealBound
		return bindHSet(ctx, r, name, nodeID, connID, false) // same connID → keep the live byte counters
	})
	return res, err
}

// bindHSet writes the routing fields + TTL (shared by bind + self-heal). resetBytes zeroes the
// live-scoped byte counters on a FRESH owner (new connID / absent) so a reconnect within the TTL window
// never sums onto the old session; a same-connID self-heal passes resetBytes=false to keep the ongoing
// counters. The identity-scoped traf: day/week quotas are separate keys and are NEVER touched here.
func bindHSet(ctx context.Context, r *Registry, name, nodeID, connID string, resetBytes bool) error {
	fields := []any{"node", nodeID, "connID", connID}
	if resetBytes {
		fields = append(fields, "bytes_in", 0, "bytes_out", 0)
	}
	pipe := r.rdb.Pipeline()
	pipe.HSet(ctx, key(name), fields...)
	pipe.PExpire(ctx, key(name), r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// LookupRoute returns the owning node and the phone-connection connID, or ok=false when no tunnel is bound.
func (r *Registry) LookupRoute(ctx context.Context, name string) (nodeID, connID string, ok bool, err error) {
	vals, err := r.rdb.HMGet(ctx, key(name), "node", "connID").Result()
	if err != nil {
		return "", "", false, err
	}
	node, _ := vals[0].(string)
	cid, _ := vals[1].(string)
	if node == "" {
		return "", "", false, nil
	}
	return node, cid, true, nil
}
```

[x] **Action 2.1.2** — modify `internal/router/registry.go`:
- Package comment: `tunnel:{name} stores {node, fingerprint, connID}` → `tunnel:{name} stores {node, connID}`.
- Delete `ErrNameHeldByOther` and its comment.
- `// SelfHealResult is the three-state outcome of BindIfAbsentOrOwner.` → `// SelfHealResult is the outcome of BindIfAbsentOrOwner.`
- `// SelfHealNotOwner: the route is held by a DIFFERENT connID (same fingerprint) — do NOT clobber.` → `// SelfHealNotOwner: the route is held by a DIFFERENT connID — do NOT clobber.`
- Delete `SelfHealConflict` and its comment.

Definition of Done:
- [x] `internal/router` (non-test) has no `fingerprint`, `ErrNameHeldByOther` or `SelfHealConflict`.

### [x] Task 2.2 — Phone connections

[x] **Action 2.2.1** — modify `internal/phoneconn/manager.go`:

```diff
-	BindRoute(ctx context.Context, name, nodeID, fingerprint, connID string) error
+	BindRoute(ctx context.Context, name, nodeID, connID string) error
@@
-	BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, fingerprint, connID string) (router.SelfHealResult, error)
+	BindRouteIfAbsentOrOwner(ctx context.Context, name, nodeID, connID string) (router.SelfHealResult, error)
@@ type conn struct
-	fingerprint  string // identity-CERT fingerprint (ban/route bookkeeping)
@@ register
-		err := m.router.BindRoute(ctx, c.name, m.nodeID, c.fingerprint, c.connID)
+		err := m.router.BindRoute(ctx, c.name, m.nodeID, c.connID)
@@ heartbeatLoop
-				if _, err := m.router.BindRouteIfAbsentOrOwner(ctx, c.name, m.nodeID, c.fingerprint, c.connID); err != nil && ctx.Err() == nil {
+				if _, err := m.router.BindRouteIfAbsentOrOwner(ctx, c.name, m.nodeID, c.connID); err != nil && ctx.Err() == nil {
```

[x] **Action 2.2.2** — modify `internal/phoneconn/listener.go`:

```diff
 // IssueFunc regenerates the identity + public certs for an mTLS-authenticated tunnel (name from the
-// client-cert CN). fp is the identity-cert fingerprint; ip is the phone's peer address for evidence.
-type IssueFunc func(ctx context.Context, name, fp, ip string, req IssueRequest) (IssueResponse, *IssueError)
+// client-cert CN). ip is the phone's peer address for evidence.
+type IssueFunc func(ctx context.Context, name, ip string, req IssueRequest) (IssueResponse, *IssueError)
@@
-// phoneIdentity is the validated identity extracted from the mTLS client cert: the derived tunnel
-// name, the cert fingerprint (ban/route bookkeeping), the KEY fingerprint (correlates conn-log events
-// with the registry record), and the cert serial (forensics).
+// phoneIdentity is the validated identity extracted from the mTLS client cert: the derived tunnel
+// name, the KEY fingerprint (correlates conn-log events with the registry record), and the cert serial
+// (forensics).
 type phoneIdentity struct {
-	name        string
-	fingerprint string    // sha256 of the cert (ban/route id)
-	keyFP       string    // sha256 of the PKIX SPKI (registry correlation)
-	certSerial  string    // hex
-	notAfter    time.Time // identity-cert expiry (the CA's exposure bound, enforced live)
+	name       string
+	keyFP      string    // sha256 of the PKIX SPKI (registry correlation)
+	certSerial string    // hex
+	notAfter   time.Time // identity-cert expiry (the CA's exposure bound, enforced live)
 }
@@ identity()
-		name: cn, fingerprint: ca.Fingerprint(leaf),
+		name: cn,
@@ ServeHTTP
-		h.serveIssue(w, r, id.name, id.fingerprint)
+		h.serveIssue(w, r, id.name)
@@
-func (h *Handler) serveIssue(w http.ResponseWriter, r *http.Request, name, fp string) {
+func (h *Handler) serveIssue(w http.ResponseWriter, r *http.Request, name string) {
@@
-	resp, ierr := h.onIssue(r.Context(), name, fp, peerIP(r), req)
+	resp, ierr := h.onIssue(r.Context(), name, peerIP(r), req)
@@ serveControl
-		name: id.name, fingerprint: id.fingerprint, keyFP: id.keyFP, certSerial: id.certSerial,
+		name: id.name, keyFP: id.keyFP, certSerial: id.certSerial,
@@
 	teardown, err := h.mgr.register(ctx, c)
 	if err != nil {
-		if errors.Is(err, router.ErrNameHeldByOther) {
-			http.Error(w, "bind conflict", http.StatusConflict)
-		} else {
-			if ctx.Err() == nil {
-				h.mgr.logger.Warn("phone route bind failed", "tunnel", c.name, "conn", c.connID, "err", err)
-			}
-			http.Error(w, "bind failed (retry)", http.StatusServiceUnavailable)
-		}
+		if ctx.Err() == nil {
+			h.mgr.logger.Warn("phone route bind failed", "tunnel", c.name, "conn", c.connID, "err", err)
+		}
+		http.Error(w, "bind failed (retry)", http.StatusServiceUnavailable)
 		return
 	}
```
Drop the `router` import (its only use was `router.ErrNameHeldByOther`); keep `errors` only if still used.

[x] **Action 2.2.3** — modify `internal/server/serve.go` (`issueFunc`): `return func(ctx context.Context, name, _, ip string, req phoneconn.IssueRequest) (…)` →
`return func(ctx context.Context, name, ip string, req phoneconn.IssueRequest) (…)`.

Definition of Done:
- [x] `internal/phoneconn` (non-test) has no `fingerprint` field, no `ErrNameHeldByOther` and no `StatusConflict`.

### [x] Task 2.3 — Route lookups elsewhere

[x] **Action 2.3.1** — modify `internal/edge/edge.go`:

```diff
-// Router resolves a tunnel name to its owner + fingerprint + connID.
+// Router resolves a tunnel name to its owner + connID.
 type Router interface {
-	LookupRoute(ctx context.Context, name string) (nodeID, fingerprint, connID string, ok bool, err error)
+	LookupRoute(ctx context.Context, name string) (nodeID, connID string, ok bool, err error)
 }
```

[x] **Action 2.3.2** — modify `internal/edge/bridge.go`: `nodeID, _, connID, ok, err :=` → `nodeID, connID, ok, err :=`;
`n2, _, c2, ok2, lerr :=` → `n2, c2, ok2, lerr :=`; the splice route check `if _, _, cur, ok, lerr := e.router.LookupRoute(ctx, name)` →
`if _, cur, ok, lerr := e.router.LookupRoute(ctx, name)`.

[x] **Action 2.3.3** — modify `internal/server/server.go:450` and `:498`: `owner, _, _, ok, err := reg.LookupRoute(r.Context(), name)` →
`owner, _, ok, err := reg.LookupRoute(r.Context(), name)`.

Definition of Done:
- [x] Every `LookupRoute` caller uses the 4-result form.

### [x] Task 2.4 — Remove the unused certificate fingerprint and fix the `ca` comments

[x] **Action 2.4.1** — modify `internal/ca/verify.go`: delete `Fingerprint` and its doc comment (`KeyFingerprint` stays).

[x] **Action 2.4.2** — modify `internal/ca/ca.go:2-3` (package comment): `identity + mesh-role certificates (see e2e.go), plus the stable cert fingerprint (verify.go). Pure` →
`identity + mesh-role certificates (see e2e.go). Pure`.

[x] **Action 2.4.3** — modify `internal/ca/ca.go:16-17` (D12): `// enroll handler maps this to 400 unsupported_key_type (docs/PROTOCOL.md §1).` →
`// enroll handler maps this to 400 unsupported_key_type.`

Definition of Done:
- [x] `grep -rn 'ca.Fingerprint\|Fingerprint(cert' --include=*.go .` is empty.

### [x] Task 2.5 — Tests for US2

[x] **Action 2.5.1** — add/update/delete the tests below.

| Test | Verifies | Notes |
|---|---|---|
| `TestBindRoute_NewConnectionReplacesOwner` (replaces `TestBindRouteRejectsDifferentFingerprint`, `internal/router/registry_test.go`) | bind (node1, conn1) then (node2, conn2) → `LookupRoute` = (node2, conn2); byte fields zeroed | |
| `TestBindRoute_WritesOnlyRoutingFields` (new, `internal/router/registry_test.go`) | after `BindRoute`, and after a `BindRouteIfAbsentOrOwner` on an absent key, `HGETALL tunnel:{name}` holds exactly `node`, `connID`, `bytes_in`, `bytes_out` | |
| `TestBindRouteIfAbsentOrOwner_TwoState` (replaces `…_ThreeState`) | absent → `SelfHealBound`; another connID → `SelfHealNotOwner`, nothing written; same connID → `SelfHealBound`, byte counters kept | |
| router / server / client / e2e callers (update) | `BindRoute` with 4 args and `LookupRoute` with 4 results in `router` tests (`registry_test`, `traffic_test`, `tunnels_test`), `server/admin_actions_test.go`, `client/datastream_test.go:210`, `client/harness_test.go:226`, `e2e/e2e_test.go:460`; edge `fakeRoute`/`fakeRouter` lose `fp` | mechanical |
| `internal/phoneconn` fakes and identities (update) | drop `fingerprint` from the `phoneIdentity{…}` / `conn{…}` literals in `listener_test.go` and `manager_test.go`; 4-arg fake router methods incl. `scriptedHBRouter.BindRouteIfAbsentOrOwner` (`manager_test.go:472`) and the 4-result `LookupRoute` at `manager_test.go:433`; in the `manager_test.go:419` comment remove ` (same fp → no conflict)` | |
| `client/harness_test.go:136` (update) | the `onIssue` literal takes the 4-parameter `IssueFunc` | |
| `TestServeControl_BindFailureStatuses` (update) | the 409 row is removed; a bind error answers 503 `bind failed (retry)`; in its comment `proves a fingerprint conflict answers 409, any other` + `(transient) bind failure answers 503 retryable.` → `proves any (transient) bind failure answers 503 retryable.` | |
| `TestControl_NewCertificateReplacesLiveConnection` (new, `internal/phoneconn`) | same node: connection A with identity cert 1 bound, then connection B for the same name with a different cert 2 → B 200, A closed with reason `phone-close`, the route holds B's connID | both through `ServeHTTP` as POSTs built like `tlsRequest` (method POST, `newBlockedReader()` body, `ProtoMajor = 2`), each in its own goroutine; a Manager over a miniredis `router.Registry` with a recording `Closed` hook (like `TestManager_Teardown_NotifiesClosedHook`) that sees A's reason |
| `TestHeartbeatMissingSelfHeals` (update) | self-heal with the 4-arg call | |
| `internal/ca` (update) | the `Fingerprint(cert) == ""` check in `ca_test.go:161` is removed; `TestFingerprintStableAndPrefixed` is deleted | `ca.Fingerprint` no longer exists |
| `TestE2E_RenewedIdentityTakesOverAcrossNodes` (new, `e2e/e2e_test.go`) | client A runs on replica 1; `A.Renew(ctx, client.FetchIssueNonce(…))`; client B built with `A.Identity()` runs on replica 2 and binds (route node = replica 2); the renewed identity cert's CN and the public cert's DNS SAN are still A's original name; a public connection through either replica reaches B's backend; A's `Run` returns within 20 s (replica 1 closed it at its heartbeat) | |
| `TestIntegration_EnrollConnectRoundtrip` (update, `internal/server/integration_test.go:277`, after its `c.Renew` at :337) | after `c.Renew`, the new identity cert's CN is still `ident.Name`, the public cert's DNS SAN is still `ident.Name + "." + tunnelDomain`, the registry record keeps that name and its `EnrolledAt`, and a new `client.New` with `c.Identity()` binds the same name (`LookupRoute` ok) | |

Definition of Done:
- [x] Every row is done.

## [x] User Story 3 — `/api/v1/control` refuses HTTP/1.x

Answer an HTTP/1.x control request with `505` instead of leaving it hanging (D3).

Acceptance criteria:
- [x] `POST /api/v1/control` with `ProtoMajor != 2` and a valid, unbanned identity → `505`, before any pre-bind slot or bind.
- [x] Every HTTP/1.x answer on `/api/v1/control` (505, and the ban / identity refusals that come first) carries `Connection: close` and is delivered at once although the request body stays open.
- [x] `/api/v1/data` (HTTP/1.1) and `/api/v1/issue` (HTTP/2 and HTTP/1.1) are unaffected.

### [x] Task 3.1 — Handler

[x] **Action 3.1.1** — modify `internal/phoneconn/listener.go` (`ServeHTTP`):

```diff
 func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
-	if r.URL.Path == wire.DialBackPath {
+	if r.URL.Path == wire.DialBackPath || (r.URL.Path == "/api/v1/control" && r.ProtoMajor != 2) {
 		w.Header().Set("Connection", "close")
 	}
@@
 	case "/api/v1/control":
 		if r.Method != http.MethodPost { // docs/PROTOCOL.md §3: the control stream is a POST /api/v1/control
 			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
 			return
 		}
+		if r.ProtoMajor != 2 {
+			http.Error(w, "http/2 required", http.StatusHTTPVersionNotSupported)
+			return
+		}
 		h.serveControl(w, r, id)
```
Context: without `Connection: close`, Go 1.27.2 `net/http` (`server.go` `chunkWriter.writeHeader`, lines 1450-1478)
first discards up to 256 KiB of an unread streaming request body before it sends the status, so an HTTP/1.1 answer
would never reach a phone that keeps its body open; `Connection: close` sets `closeAfterReply` (`server.go:1412`),
which skips that discard. The check order (IP ban first) is unchanged.

Definition of Done:
- [x] Every HTTP/1.x answer on `/api/v1/control` sets `Connection: close`; the 505 branch runs before `serveControl`.

### [x] Task 3.2 — Tests for US3

[x] **Action 3.2.1** — add the tests below.

| Test | Verifies | Notes |
|---|---|---|
| `TestServeHTTP_ControlOverHTTP1Refused` (new, `internal/phoneconn`) | a valid-identity `POST /api/v1/control` with `ProtoMajor = 1` → 505 with `Connection: close`; nothing registered | a POST built like `tlsRequest` (method POST, `newBlockedReader()` body, `ProtoMajor = 1`) |
| `TestServeHTTP_ControlHTTP1RefusalsArriveAtOnce` (new, `internal/phoneconn`) | over a real `httptest.NewServer` (plain HTTP/1.1, no read timeout) a `POST /api/v1/control` whose `io.Pipe` body stays open gets its answer within 2 s: an IP-banned peer → 403 `banned`; an unbanned peer without a client certificate → 403 `forbidden` | real sockets: the defect lives in `net/http`'s connection handling |
| `TestIntegration_ControlRefusesHTTP1` (new, `internal/server`, `//go:build integration`) | against the real `server.Run`: an HTTP/1.1-only client (`TLSNextProto` set to an empty map, identity from `client.Enroll`) POSTing a body that stays open (`io.Pipe`) to `/api/v1/control` gets 505 within 10 s; `POST /api/v1/issue` with `{}` over the same HTTP/1.1 client gets its JSON error answer (not 505) | |

Definition of Done:
- [x] Every row is done.

## [x] User Story 4 — Issuance answers

Give the real weekly-cap wait (D4), make signing failures retryable (D5), and bound the `/issue` handler (D6).

Acceptance criteria:
- [x] A weekly-cap `issuance_cap` carries `retry_after_seconds` = the time left on the name's window (rounded up to whole seconds).
- [x] `identity_sign_failed` → 503, `retryable: true`, on `/api/v1/enroll` and `/api/v1/issue`.
- [x] The whole `/api/v1/issue` handler (body read and `OnIssue`) runs under one 390 s deadline.
- [x] The word "rolling" is gone from `internal/limit/issuance.go`.

### [x] Task 4.1 — Limiter

[x] **Action 4.1.1** — modify `internal/limit/issuance.go`:
- Line 12: `… counts SUCCESSFUL public-cert issuances per rolling 7-day window.` → `… per 7-day window.`
- Line 111: `IssuanceRecord increments the rolling-7d success counter` → `IssuanceRecord increments the 7d success counter`.
- `IssuanceBegin` (doc comment unchanged) and a new helper `issuanceWindowLeft` (no comment):

```go
func (l *Limiter) IssuanceBegin(ctx context.Context, name string, maxN int) (ok bool, orderID string, retryAfter time.Duration, err error) {
	token := mintToken()
	got, err := l.rdb.SetNX(ctx, issLockKey(name), token, issLockTTL).Result()
	if err != nil {
		return false, "", 0, err
	}
	if !got {
		return false, "", 0, ErrIssuanceInFlight // another issuance in flight
	}
	n, err := l.rdb.Get(ctx, issuanceKey(name)).Int()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, "", 0, errors.Join(fmt.Errorf("issuance count read: %w", err), l.releaseIssLock(ctx, name, token))
	}
	if n >= maxN {
		if rerr := l.releaseIssLock(ctx, name, token); rerr != nil && ctx.Err() == nil { // over cap — release and refuse
			l.logger.Warn("issuance lock release failed (lock expires by TTL)", "tunnel", name, "err", rerr)
		}
		left, werr := l.issuanceWindowLeft(ctx, name)
		if werr != nil {
			return false, "", 0, werr
		}
		return false, "", left, nil
	}
	return true, token, 0, nil
}

func (l *Limiter) issuanceWindowLeft(ctx context.Context, name string) (time.Duration, error) {
	ttl, err := l.rdb.PTTL(ctx, issuanceKey(name)).Result()
	if err != nil {
		return 0, fmt.Errorf("issuance window read: %w", err)
	}
	switch {
	case ttl > 0:
		return (ttl + time.Second - 1).Truncate(time.Second), nil
	case ttl == -1:
		if err := l.rdb.ExpireNX(ctx, issuanceKey(name), issWindowTTL).Err(); err != nil {
			return 0, fmt.Errorf("issuance window restore: %w", err)
		}
		return issWindowTTL, nil
	default:
		return time.Second, nil
	}
}
```
Context: go-redis v9.23.0 `PTTL` yields the raw `-1` (no expiry) / `-2` (missing key) as the duration (`command.go`
`DurationCmd.readReply`); the `-1` branch gives a capped counter its TTL back (a capped name sees no further `INCR`,
so its `EXPIRE NX` would never run again); `-2` (the window ended between the two reads) means "retry now", 1 s.

Definition of Done:
- [x] `IssuanceBegin` returns the window left when capped and 0 otherwise.

### [x] Task 4.2 — Enroll service

[x] **Action 4.2.1** — modify `internal/enroll/enroll.go` (`Config.Limiter` is the concrete `*limit.Limiter`; no interface changes):

```diff
-	ok, orderID, err := s.cfg.Limiter.IssuanceBegin(ctx, name, s.cfg.IssuePerWeek)
+	ok, orderID, retryAfter, err := s.cfg.Limiter.IssuanceBegin(ctx, name, s.cfg.IssuePerWeek)
@@
 	if err != nil {
 		if ctx.Err() == nil {
-			s.logger.Warn("issuance lock acquire failed", "tunnel", name, "ip", ip, "err", err)
+			s.logger.Warn("issuance lock or cap check failed", "tunnel", name, "ip", ip, "err", err)
 		}
@@
-		return Result{}, &Error{Reason: "issuance_cap", Retryable: true, RetryAfter: 7 * 24 * time.Hour}
+		return Result{}, &Error{Reason: "issuance_cap", Retryable: true, RetryAfter: retryAfter}
@@ signError
-	return &Error{Reason: "identity_sign_failed"}
+	return &Error{Reason: "identity_sign_failed", Retryable: true}
```

[x] **Action 4.2.2** — modify `internal/enroll/enroll.go` (`Issue`): once the public certificate is issued, the
weekly-cap counter is recorded on its own 5 s context, detached from the request (the same bound as the existing
`IssuanceEnd` release):

```diff
 	t = s.logStep("issue step", "acme", t, "tunnel", name, "ip", ip, "ca", info.CA)
 
+	bctx, bcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
+	defer bcancel()
 	// Count this SUCCESSFUL issuance, then LWW-record the cert metadata.
-	if err := s.cfg.Limiter.IssuanceRecord(ctx, name); err != nil {
+	if err := s.cfg.Limiter.IssuanceRecord(bctx, name); err != nil {
```
Context: an issued certificate is counted against `--issue-per-week` even when the deadline or the phone's disconnect
cancels the request right after the ACME order (abuse caps fail safe). `recordCert` stays on the request context: a
certificate the phone never received must not be recorded, or the renewal watcher would wait for it instead of nudging
again. No time is reserved inside the 390 s for this bookkeeping (user, 2026-10-18).

Definition of Done:
- [x] Both answers changed; the in-flight `issuance_cap` keeps its 300 s; the counter write of an issued certificate cannot be cancelled by the request.

### [x] Task 4.3 — 390 s `/issue` cap

[x] **Action 4.3.1** — modify `internal/phoneconn/listener.go`: add `issueDeadline time.Duration` to `Handler` and
`IssueDeadline time.Duration` to `HandlerConfig` (no comments); in `NewHandler`, next to the `IssueBody` default,
`if cfg.IssueDeadline <= 0 { cfg.IssueDeadline = 390 * time.Second }` and `issueDeadline: cfg.IssueDeadline` in the
literal; in `serveIssue`, after the `onIssue == nil` check:

```diff
+	deadline := time.Now().Add(h.issueDeadline)
+	if err := http.NewResponseController(w).SetReadDeadline(deadline); err != nil {
+		h.mgr.logger.Warn("issue request read deadline not set", "tunnel", name, "err", err)
+	}
 	body, err := io.ReadAll(io.LimitReader(r.Body, h.issueBody))
@@
-	resp, ierr := h.onIssue(r.Context(), name, peerIP(r), req)
+	ictx, cancel := context.WithDeadline(r.Context(), deadline)
+	defer cancel()
+	resp, ierr := h.onIssue(ictx, name, peerIP(r), req)
```
Context: Go 1.27.2 implements `SetReadDeadline` for the HTTP/1 `response` (`server.go:501`, reset for the next request
at `server.go:2184-2200`) and the HTTP/2 `responseWriter` (`internal/http2/server.go:2716`); the control server has no
`ReadTimeout`, so without it a stalled upload would hold the handler. `server.Run` keeps the 390 s default.

Definition of Done:
- [x] The body read and `OnIssue` share one deadline started when the handler accepts the request.

### [x] Task 4.4 — Tests for US4

[x] **Action 4.4.1** — add/update the tests below.

| Test | Verifies | Notes |
|---|---|---|
| `TestLimiter_IssuanceBegin_CappedReturnsWindowLeft` (new, `internal/limit/issuance_test.go`) | table: window TTL 7 d − 1 h → `retryAfter = 7d − 1h`; TTL 1500 ms → 2 s (rounded up); under the cap → 0; the lock is released when capped | miniredis `FastForward` / `PExpire` |
| `TestLimiter_IssuanceBegin_CappedWithoutTTLRestoresWindow` (new) | counter at the cap with no TTL → `retryAfter = 7d`, the key gets a 7-day TTL | `mr.Set` |
| `TestLimiter_IssuanceWindowLeft_MissingKeyIsOneSecond` (new, internal) | `issuanceWindowLeft` on a missing key → 1 s | |
| `TestLimiter_IssuanceBegin_WindowReadErrorReturned` (new) | capped + `pttl` failing → `ok=false`, the error wraps `issuance window read` | `tunneltest.FailCommands(errInjected, "pttl")` |
| `TestLimiter_IssuanceBegin_WindowRestoreErrorReturned` (new) | capped counter without a TTL + `expire` failing → `ok=false`, the error wraps `issuance window restore` | `tunneltest.FailCommands(errInjected, "expire")` |
| `IssuanceBegin` callers (update) | 4 results in `issuance_test.go`, `window_test.go`, `limiter_test.go`, `internal/acme/chain_test.go`; the `over-cap release` case of `TestLimiter_IssuanceLock_CancelledCallerIsSilent` now expects a refusal whose error is the cancelled window read, still with nothing logged | |
| `TestIssueRecordsIssuanceAndCap` (update, `internal/enroll/enroll_fixes_test.go`) | after the first issuance, `mr.FastForward(time.Hour)`; the capped answer's `RetryAfter = 7d − 1h` | `newService` returns the miniredis |
| `internal/enroll/logging_test.go:162` (update) | the `issuance lock acquire fails` row expects `msg="issuance lock or cap check failed"` | |
| `TestIssue_CounterSurvivesCancelledRequest` (new, `internal/enroll`) | a fake issuer that cancels the request context just before it returns the certificate: `Issue` succeeds and the `iss:{name}` counter is 1 | `newService`'s miniredis |
| `TestSignError_RetryableAnd503` (new, `internal/enroll`, internal) | `signError(errors.New("x"))` → `identity_sign_failed`, retryable, `statusForError` = 503 (the status both enroll routes use); `signError(ca.ErrUnsupportedKeyType)` → `unsupported_key_type`, not retryable, 400 | |
| `TestServeIssue_RetryableErrorIs503` (new, `internal/phoneconn`) | an `OnIssue` answering `IssueError{Reason: "identity_sign_failed", Retryable: true}` → 503, body `retryable: true` | |
| `TestServeIssue_HandlerDeadline` (new, `internal/phoneconn`) | with the default config the ctx passed to `OnIssue` has a deadline in `(now, now+390s]` | fake `OnIssue` records the ctx |
| `TestServeIssue_StalledBodyAnsweredAtDeadline` (new, `internal/phoneconn`) | `IssueDeadline = 200ms`: over a real TLS `http.Server` without `ReadTimeout` (client cert from `newDBTestCA`, like `startDialBackEnv` but without its timeouts), a `POST /api/v1/issue` whose body never ends is answered 400 `bad_request` within 2 s and `OnIssue` is not called | |

Definition of Done:
- [x] Every row is done.

## [x] User Story 5 — Apps: prompt stop, bounded dial-back, clean control teardown, 400 s issue timeout

Fix the reference app and the soak app identically (D6, D7).

Acceptance criteria:
- [x] `Tunnel.stop()` cancels the in-flight control call; a frame read after stop is not acted on.
- [x] Every dial-back session/splice opened through a control connection is closed when that connection ends (including stop).
- [x] `DialBack.open` fails once connect + TLS + upgrade take longer than one 10 s deadline, however slowly the peer trickles bytes.
- [x] The duplex request body is closed on every `/control` outcome, including a non-200 answer.
- [x] A late renewal cannot recreate a forgotten identity: no renewal attempt (key generation + `/issue`) and no save runs for an identity that is no longer the saved one, and `forget` waits only for an attempt in flight, never for a retry sleep.
- [x] The `/issue` read timeout is 400 s in both apps; the enroll POST keeps 300 s.

Paths: `S = support/soak-app/app/src/main/java/com/example/soakapp`, `T = support/tunnel-app/app/src/main/java/com/example/tunnelapp`.

### [x] Task 5.1 — Session registry (new, identical in both apps)

[x] **Action 5.1.1** — create `S/Sessions.kt` and `T/Sessions.kt` (only the package line differs):

```kotlin
package com.example.soakapp

import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap

internal class Sessions(private val onCloseError: (Throwable) -> Unit) {
    private val open = ConcurrentHashMap.newKeySet<Closeable>()
    @Volatile private var shut = false

    fun isClosed(): Boolean = shut

    fun add(c: Closeable): Boolean {
        open.add(c)
        if (!shut) return true
        if (open.remove(c)) close(c)
        return false
    }

    fun release(c: Closeable) {
        open.remove(c)
    }

    fun closeAll() {
        shut = true
        for (c in open.toList()) if (open.remove(c)) close(c)
    }

    private fun close(c: Closeable) {
        try { c.close() } catch (t: Throwable) { onCloseError(t) }
    }
}
```

Definition of Done:
- [x] Both files exist with identical bodies.

### [x] Task 5.2 — Dial-back deadline (both apps)

[x] **Action 5.2.1** — modify `S/DialBack.kt` and `T/DialBack.kt`: add the constructor parameter
`private val timeoutMs: Int = TIMEOUT_MS`, a shared daemon scheduler and the state constants in the companion, and one
deadline around the whole upgrade. Soak shown; `T` is identical except that it keeps its `BufferedInputStream` and its
`Conn(s, input)` return:

```kotlin
        val raw = Socket()
        val state = AtomicInteger(OPENING)
        val deadline = DEADLINES.schedule(Callable<Unit> { if (state.compareAndSet(OPENING, TIMED_OUT)) raw.close() }, timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        try {
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(host, port), timeoutMs)
            raw.soTimeout = timeoutMs
            val s = if (useHttps) tls(raw, port, if (useMtls) mtls else serverTls) else raw
            s.getOutputStream().apply {
                write(
                    ("GET /api/v1/data HTTP/1.1\r\nHost: $controlHost\r\nConnection: Upgrade\r\n" +
                        "Upgrade: tunneld-dial\r\nX-Dial-Token: $token\r\n\r\n").toByteArray(Charsets.US_ASCII),
                )
                flush()
            }
            val status = readStatus(s.getInputStream())
            check(status == 101) { "dial-back refused: $status" }
            s.soTimeout = 0
            if (!state.compareAndSet(OPENING, OPENED)) throw IOException("dial-back socket closed by its deadline")
            deadline.cancel(false)
            return s
        } catch (t: Throwable) {
            if (state.compareAndSet(OPENING, FAILED)) {
                deadline.cancel(false)
                try { raw.close() } catch (c: Throwable) { t.addSuppressed(c) }
                throw t
            }
            val e = SocketTimeoutException("dial-back to $addr took longer than ${timeoutMs}ms")
            e.initCause(t)
            try { deadline.get() } catch (c: Throwable) { e.addSuppressed(c) }
            try { raw.close() } catch (c: Throwable) { e.addSuppressed(c) }
            throw e
        }
```
Companion additions:

```kotlin
        const val OPENING = 0
        const val OPENED = 1
        const val FAILED = 2
        const val TIMED_OUT = 3
        val DEADLINES = ScheduledThreadPoolExecutor(1) { r -> Thread(r, "dial-back-deadline").apply { isDaemon = true } }
            .apply { removeOnCancelPolicy = true }
```
Imports: `java.io.IOException`, `java.net.SocketTimeoutException`, `java.util.concurrent.Callable`,
`java.util.concurrent.ScheduledThreadPoolExecutor`, `java.util.concurrent.TimeUnit`, `java.util.concurrent.atomic.AtomicInteger`.
Context: on Android the layered TLS socket is Conscrypt's `ConscryptEngineSocket` (`OpenSSLSocketFactoryImpl`
builds only engine sockets), whose handshake reads through the raw socket's `InputStream`; closing `raw` wakes that
blocked read like any other (Android's `PlainSocketImpl.socketClose0` signals blocked threads through
`AsynchronousCloseMonitor`). The state CAS, not `Future.cancel`, decides who won — `FutureTask.cancel(false)` also returns `true` while
the task is running. After `OPENED` nothing in `open` can throw, so the catch sees only `OPENING` or `TIMED_OUT`; on
`TIMED_OUT`, `deadline.get()` waits for the deadline's close and attaches its error.

Definition of Done:
- [x] Both `DialBack.open` implementations enforce one deadline for connect + TLS + upgrade.

### [x] Task 5.3 — Control loop (both apps)

[x] **Action 5.3.1** — modify `S/Tunnel.kt` and `T/Tunnel.kt`: add `private val current = AtomicReference<Call?>(null)`;
replace `fun stop() = running.set(false)` with:

```kotlin
    fun stop() {
        running.set(false)
        current.get()?.cancel()
    }
```
Replace `serveControlOnce` (soak shown; `T` identical except its existing log texts without `phone $phone: `, its
`ControlWatchdog.watch("control", …)` label and `stats.connected(node.get(), everBound)`):

```kotlin
    private fun serveControlOnce() {
        var sink: BufferedSink? = null
        val body = duplexBody { sink = it }
        val call = client.newCall(Request.Builder().url(net.url(controlHost, "/api/v1/control")).post(body).build())
        current.set(call)
        if (!running.get()) call.cancel()
        val sessions = Sessions { Log.d(TAG, "phone $phone: dial-back session close failed", it) }
        val lastFrameAt = AtomicLong(System.nanoTime())
        val silent = AtomicBoolean(false)
        val watch = ControlWatchdog.watch("phone $phone", call, lastFrameAt, silent)
        var resp: Response? = null
        try {
            val r = call.execute()
            resp = r
            if (r.code != 200) {
                Log.w(TAG, "phone $phone: control connect rejected: ${r.code}")
                return
            }
            val s = sink ?: run {
                Log.w(TAG, "phone $phone: control request body was not opened")
                return
            }
            bound.countDown()
            if (running.get()) stats.connected(phone, node.get(), everBound)
            everBound = true
            val source = r.body.source()
            while (running.get()) {
                val frame = Frames.read(source) ?: break
                if (!running.get()) break
                lastFrameAt.set(System.nanoTime())
                when (frame.first) {
                    Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                    Frames.OPEN -> JSONObject(String(frame.second)).let { o ->
                        Thread {
                            try { handleOpen(o, sessions) } catch (t: Throwable) { Log.w(TAG, "phone $phone: dial-back handling failed", t) }
                        }.apply { isDaemon = true }.start()
                    }
                    Frames.RENEW_NUDGE -> JSONObject(String(frame.second)).optString("nonce")
                        .takeIf { it.isNotEmpty() }
                        ?.let { n ->
                            val started = renewals.launch("renewal") {
                                try {
                                    onRenewNudge(n)
                                } catch (t: Throwable) {
                                    Log.w(TAG, "phone $phone: renewal failed; keeping the current certs", t)
                                    stats.issueFailed("phone $phone: renewal failed: $t")
                                }
                            }
                            if (!started) Log.i(TAG, "phone $phone: renewal already in progress; RENEW_NUDGE ignored")
                        }
                        ?: Log.w(TAG, "phone $phone: RENEW_NUDGE without a nonce ignored")
                }
            }
        } finally {
            sessions.closeAll()
            sink?.let { try { it.close() } catch (t: Throwable) { Log.d(TAG, "phone $phone: control request body close failed", t) } }
            resp?.close()
            watch.cancel(false)
            current.compareAndSet(call, null)
            if (silent.get()) client.connectionPool.evictAll()
        }
    }
```
The request body is closed before the response on every path, as the current normal path does. Imports: `okhttp3.Call`, `okhttp3.Response`.

[x] **Action 5.3.2** — modify `S/Tunnel.kt` and `T/Tunnel.kt`: `handleOpen` takes the connection's sessions, `handleOpen(open: JSONObject, sessions: Sessions)`:
- Soak (`S/Tunnel.kt`):

```kotlin
        val remote = try {
            dialBack.open(token, addr, useHttps, useMtls)
        } catch (t: Throwable) {
            Log.w(TAG, "phone $phone: dial-back to $addr failed", t)
            stats.error("phone $phone: dial-back to $addr failed: $t")
            return
        }
        if (!sessions.add(remote)) return
        try {
            responder.serve(remote, controlHost)
        } catch (t: Throwable) {
            Log.d(TAG, "phone $phone: dial-back session from $addr ended", t)
            if (!sessions.isClosed()) stats.error("phone $phone: session from $addr ended: $t")
        } finally {
            sessions.release(remote)
        }
```
- Reference (`T/Tunnel.kt`):

```kotlin
        val local = try {
            LocalConnect.open(localServerPort())
        } catch (t: Throwable) {
            Log.w(TAG, "local server unreachable for a dial-back to $addr", t)
            stats.error("local server unreachable for a dial-back to $addr: $t")
            return
        }
        if (!sessions.add(local)) return
        val remote = try {
            dialBack.open(token, addr, useHttps, useMtls)
        } catch (t: Throwable) {
            Log.w(TAG, "dial-back to $addr failed", t)
            stats.error("dial-back to $addr failed: $t")
            sessions.release(local)
            try { local.close() } catch (c: Throwable) { Log.d(TAG, "local socket close failed", c) }
            return
        }
        if (!sessions.add(remote.socket)) {
            sessions.release(local)
            try { local.close() } catch (c: Throwable) { Log.d(TAG, "local socket close failed", c) }
            return
        }
        stats.connection()
        try {
            splice(local, remote)
        } finally {
            sessions.release(local)
            sessions.release(remote.socket)
        }
```

Definition of Done:
- [x] Both apps' `Tunnel.kt` match the blocks above (apart from the listed reference-app differences).

### [x] Task 5.4 — A late renewal cannot recreate or overwrite a forgotten identity

[x] **Action 5.4.1** — create `S/RenewGate.kt` and `T/RenewGate.kt` (only the package line differs):

```kotlin
package com.example.soakapp

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

internal class ForgottenIdentity(name: String) : RuntimeException("identity $name was forgotten")

internal class RenewGate {
    private val lock = ReentrantReadWriteLock()

    fun <T> renew(name: String, current: () -> Boolean, block: () -> T): T =
        lock.read { if (current()) block() else throw ForgottenIdentity(name) }

    fun renewal(name: String, current: () -> Boolean, issue: ((() -> Unit) -> Unit) -> Unit, commit: () -> Unit) {
        issue { attempt -> renew(name, current, attempt) }
        renew(name, current, commit)
    }

    fun <T> forget(block: () -> T): T = lock.write(block)
}
```
Context: the gate wraps ONE issuance attempt (key generation + `POST /api/v1/issue`) and the final commit, never a
retry sleep, so `forget` waits at most for one attempt in flight. `ForgottenIdentity` is neither an `EnrollError` nor an
`IOException`, so `IssueRetry.waitMs` returns null for it and `IssueRetry.run` rethrows it at once. The fresh-nonce
fetch between attempts is not gated (it creates nothing). An attempt that completes before `forget` leaves keys that
`forget`'s `Keys.deleteAll` removes, and the commit is then refused, so nothing survives.

[x] **Action 5.4.2** — modify `S/Enroll.kt` and `T/Enroll.kt` (`object Enroll`): `issue` takes the per-attempt wrapper:

```diff
-    fun issue(id: Identity, nonce: String?) {
+    fun issue(id: Identity, nonce: String?, attempt: (() -> Unit) -> Unit = { it() }) {
         synchronized(id.issueLock) {
-            IssueRetry.run(nonce, { n -> issueOnce(id, n) }, { freshNonce(id) }, { Thread.sleep(it) }) { n, wait, t ->
+            IssueRetry.run(nonce, { n -> attempt { issueOnce(id, n) } }, { freshNonce(id) }, { Thread.sleep(it) }) { n, wait, t ->
```
and, in `T/Enroll.kt` only:

```diff
-    fun renew(id: Identity) {
-        issue(id, null)
+    fun renew(id: Identity, attempt: (() -> Unit) -> Unit) {
+        issue(id, null, attempt)
     }
```
The enrollment-time `issue` calls keep the default wrapper.

[x] **Action 5.4.3** — modify `T/IdentityStore.kt`: add

```kotlin
    @Synchronized
    fun holds(id: Identity): Boolean = file.exists() && parse(file).name == id.name
```
and modify `T/TunnelRunner.kt`: add `private val gate = RenewGate()`;
- the renewal callback in `doEnroll`:

```kotlin
        { nonce ->
            synchronized(renewLock) {
                try {
                    gate.renewal(id.name, { st.holds(id) }, { attempt -> Enroll.issue(id, nonce, attempt) }) {
                        st.save(id)
                        id.tlsCredential().let { (k, c) -> srv.swapIdentity(k, c) }
                        stats.renewed()
                        installed(id)
                    }
                } catch (f: ForgottenIdentity) {
                    Log.i(TAG, "${f.message}; renewal skipped")
                }
            }
        }
```
- `doRefresh`:

```kotlin
    private fun doRefresh(filesDir: File) = guarded(filesDir, "refresh") {
        val id = identity ?: error("not enrolled")
        val st = store ?: error("not enrolled")
        val srv = server ?: error("not enrolled")
        synchronized(renewLock) {
            gate.renewal(id.name, { st.holds(id) }, { attempt ->
                try {
                    Enroll.renew(id, attempt)
                } catch (t: Throwable) {
                    if (t !is ForgottenIdentity) stats.issueFailed("refresh: $t")
                    throw t
                }
            }) {
                st.save(id)
                id.tlsCredential().let { (k, c) -> srv.swapIdentity(k, c) }
                stats.renewed()
                installed(id)
                writeReady(filesDir, id)
            }
        }
    }
```
- `doForget`: `val forgotten = gate.forget { IdentityStore(File(filesDir, "identity"), env).forget().also { Keys.deleteAll(Enroll.envAliasPrefix(env)) } }`
  replaces the two existing lines.

[x] **Action 5.4.4** — modify `S/PhoneStore.kt`: add

```kotlin
    @Synchronized
    fun holds(i: Int, id: Identity): Boolean {
        val f = file(i)
        return f.exists() && parse(f).name == id.name
    }
```
and modify `S/Soak.kt`: add `private val gate = RenewGate()`;
- the `bringUp` renewal callback:

```kotlin
        { nonce ->
            synchronized(renewLock) {
                try {
                    gate.renewal(id.name, { store.holds(i, id) }, { attempt -> Enroll.issue(id, nonce, attempt) }) {
                        stats.renewed(id.state().caId)
                        store.save(i, id)
                        id.tlsCredential().let { (k, c) -> responder.install(k, c) }
                    }
                } catch (f: ForgottenIdentity) {
                    Log.i(TAG, "phone $i: ${f.message}; renewal skipped")
                }
            }
        }
```
- `doForget`: `val forgotten = gate.forget { PhoneStore(root, env).forgetAll().also { Keys.deleteAll(Enroll.envAliasPrefix(env)) } }`
  replaces the two existing lines (still inside `synchronized(startLock)`).

Context: lock order — a renewal takes its `renewLock`, then the gate's read side for one attempt or the commit;
`forget` takes the write side (the soak app's inside `startLock`, which no renewal takes) — no cycle.

Definition of Done:
- [x] Every renewal in both apps goes through `gate.renewal` with the `holds` check, the save and every renewal side effect sit in its commit, no retry sleep runs inside the gate, and every `forget` runs inside `gate.forget`.

### [x] Task 5.5 — `/issue` read timeout

[x] **Action 5.5.1** — modify `T/Enroll.kt` and `S/Enroll.kt` (`object Enroll`): add

```kotlin
    internal fun enrollClient(client: OkHttpClient): OkHttpClient = client.newBuilder().readTimeout(300, TimeUnit.SECONDS).build()

    internal fun issueClient(client: OkHttpClient): OkHttpClient = client.newBuilder().readTimeout(400, TimeUnit.SECONDS).build()
```
`postJson` no longer builds a client:

```diff
     private fun postJson(client: OkHttpClient, url: String, json: String): Pair<Int, String> {
         val req = Request.Builder().url(url).post(json.toRequestBody("application/json".toMediaType())).build()
-        client.newBuilder().readTimeout(300, TimeUnit.SECONDS).build()
-            .newCall(req).execute().use { resp -> return resp.code to resp.body.string() }
+        client.newCall(req).execute().use { resp -> return resp.code to resp.body.string() }
     }
```
the `/api/v1/enroll` call becomes `postJson(enrollClient(server), …)` and the `/api/v1/issue` call
`postJson(issueClient(id.mtlsClient()), …)`.

Definition of Done:
- [x] Only the `/issue` POST uses 400 s; the enroll POST keeps 300 s.

### [x] Task 5.6 — Tests for US5

[x] **Action 5.6.1** — modify `support/soak-app/app/build.gradle.kts` and `support/tunnel-app/app/build.gradle.kts`:
in `android { … }` add `testOptions { unitTests.isReturnDefaultValues = true }` (AGP 9.4.1 `UnitTestOptions`; the
`Tunnel` code logs through `android.util.Log`); add `testImplementation("com.squareup.okhttp3:mockwebserver3:5.5.0")`
and `testImplementation("com.squareup.okhttp3:okhttp-tls:5.5.0")` to both, and `testImplementation("org.json:json:20260814")`
to the soak app (the reference app has it). All three are the latest releases on Maven Central (checked 2026-10-18).

[x] **Action 5.6.2** — create the shared control-server test harness `support/soak-app/app/src/test/java/com/example/soakapp/ControlServer.kt`
and `support/tunnel-app/app/src/test/java/com/example/tunnelapp/ControlServer.kt` (only the package line differs). An OkHttp duplex request body
needs HTTP/2, so the server speaks TLS (ALPN h2) with an okhttp-tls certificate for the control host, and every
`/api/v1/control` answer is a `SocketHandler` response so the test drives the raw HTTP/2 stream (mockwebserver3
5.5.0's builder sets `Content-Length: 0` by default, which would make OkHttp fail the first frame with a
`ProtocolException` (expected 0 bytes), so `answer` removes it):

```kotlin
package com.example.soakapp

import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.SocketHandler
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import okio.Socket
import java.net.InetAddress

internal object ControlServer {
    const val HOST = "connect.example.test"
    val held: HeldCertificate = HeldCertificate.Builder().commonName(HOST).addSubjectAlternativeName(HOST).build()
    private val serverCerts = HandshakeCertificates.Builder().heldCertificate(held).build()
    private val clientCerts = HandshakeCertificates.Builder().addTrustedCertificate(held.certificate).build()

    fun start(): MockWebServer = MockWebServer().also {
        it.useHttps(serverCerts.sslSocketFactory())
        it.start(InetAddress.getLoopbackAddress(), 0)
    }

    fun client(): OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager)
        .dns { listOf(InetAddress.getLoopbackAddress()) }
        .build()

    fun answer(code: Int, onStream: (Socket) -> Unit): MockResponse =
        MockResponse.Builder().code(code).removeHeader("Content-Length").socketHandler(object : SocketHandler {
            override fun handle(socket: Socket) = onStream(socket)
        }).build()

    fun frame(type: Int, payload: String = ""): ByteArray {
        val p = payload.toByteArray()
        return Buffer().writeByte(type).writeInt(p.size).write(p).readByteArray()
    }
}
```
Each `TunnelTest` builds its `Tunnel` against `Net(null, server.port)` (the URL then names `HOST` and the server's
port), `ControlServer.client()`, `ControlServer.HOST`, `DialBack(ControlServer.HOST, SSLContext.getDefault(),
SSLContext.getDefault())` and a fresh `Stats()`; the soak app's `Responder(0, stats)` gets
`install(ControlServer.held.keyPair.private, arrayOf(ControlServer.held.certificate))`; the reference app's
`localServerPort` returns the port of a test `ServerSocket`. It runs `tunnel.run()` on a daemon thread and closes the
server in `@After`.

[x] **Action 5.6.3** — add the tests below.

| Test | Verifies | Notes |
|---|---|---|
| `TunnelTest.nonOkAnswerClosesTheRequestBody` (both apps, JVM) | the server answers `503`; the request body then ends with a clean end of stream (reading it to the end does not throw) within 5 s | the `answer(503)` handler closes `socket.sink`, then reads `socket.source.buffer()` to the end |
| `TunnelTest.stopCancelsTheControlCallAtOnce` (both apps, JVM) | after `awaitBound`, `stop()` makes `run()` return and the server-side read of the request body end within 2 s | `answer(200)` that only reads the request body |
| `TunnelTest.framesAfterStopAreIgnored` (both apps, JVM) | the server writes a `RENEW_NUDGE` and an `OPEN` only after `stop()`; `onRenewNudge` is not called and no dial-back connection reaches the dial-back `ServerSocket` within 1 s | the handler waits on a latch the test opens after `stop()` |
| `TunnelTest.controlEndClosesItsSessions` (both apps, JVM) | the server sends `OPEN` (plain, `use_https=false`) pointing at a test dial-back `ServerSocket`; only after that socket has accepted the dial-back and written `101` (and, in the reference app, the local-server `ServerSocket` has accepted too) does the handler end the response stream; then every accepted socket reads end-of-stream within 2 s; the soak app records no error in `stats.snapshot(…)` for it | the handler waits on latches set by the test sockets |
| `TunnelTest.stopClosesItsSessions` (both apps, JVM) | the same open dial-back session as above, but the test calls `stop()` instead of ending the stream; every accepted socket reads end-of-stream within 2 s; the soak app records no error for it | |
| `SessionsTest` (both apps, JVM) | `closeAll` closes registered items and sets `isClosed`; `add` after `closeAll` closes the item and returns false; a released item is not closed; a close error reaches the callback | plain `Closeable` fakes |
| `DialBackTest` (both apps, JVM) | `timeoutMs = 500`: in plain mode a peer that sends one byte of the status line every 100 ms, and with `useHttps = true` a peer that sends a TLS record header announcing a 16 KiB handshake record and then one byte every 100 ms, each make `open` throw `SocketTimeoutException` within 2 s although no single read times out; a peer that answers `101` at once returns a socket with `soTimeout == 0`; a `404` answer throws `dial-back refused: 404` | local `ServerSocket`; `SSLContext.getDefault()` for the unused contexts |
| `RenewGateTest` (both apps, JVM) | `renew` runs its block and returns its value while `current()` is true, and throws `ForgottenIdentity` without running it when false; a `forget` issued while a `renew` block runs returns only after that block ends; `renewal` runs every attempt and then the commit while `current()` stays true; when `current()` turns false between the last attempt and the commit, the commit does not run and `ForgottenIdentity` is thrown; with `issue` = `IssueRetry.run` whose first attempt fails with an `IOException`, a `forget` issued during the (latch-held) retry sleep returns at once, and after the sleep `renewal` throws `ForgottenIdentity` with no second attempt and no commit | latches; `current()` reads an `AtomicBoolean` the test flips the way `forget` deletes the record |
| `IdentityStoreTest.holds…` (tunnel app, JVM) | `holds` is true for the saved identity, false after the file is deleted, false for an identity of another name | delete/replace the file directly (`forget` needs the Android keystore) |
| `PhoneStoreTest` (soak app, JVM, new) | the same three cases for `PhoneStore.holds(i, id)` | identity built like `IdentityStoreTest` |
| `EnrollTimeoutTest` (both apps, JVM) | `Enroll.issueClient(OkHttpClient()).readTimeoutMillis == 400_000` and `Enroll.enrollClient(OkHttpClient()).readTimeoutMillis == 300_000` | |
| `TestE2E_ReferenceTunnelAppStopUnbindsAtOnce` (new, `e2e/app_rules_test.go`, device) | after `stop`, `tunnel:{name}` is unbound within 5 s | `router.NewRegistry` over `inf.redisURL`, like `e2e_test.go` |
| `TestE2E_SoakAppStopUnbindsAtOnce` (new, `e2e/app_rules_test.go`, device) | after the soak app's `stop`, the routes of its started e2e phones are unbound within 5 s | `forgetSoakPhones` first; `startSoakPhones(…, 2)` and `files/names.txt` |

Definition of Done:
- [x] Every row is done.

## [x] User Story 6 — Documentation

Make PROTOCOL.md (canonical) and the other docs match the code and the decisions (D2, D3, D6, D8, D9, D11).

Acceptance criteria:
- [x] PROTOCOL.md carries every change in Task 6.1, and no statement contradicts the code.
- [x] ARCHITECTURE.md describes the ban model, the route fields, the 505, the newest-connection rule and the 390 s cap.
- [x] PROJECT.md, README.md and `.claude/rules/project.md` describe the new ban model.
- [x] No plan number is added to any doc or rules file.
- [x] No Mermaid chart is changed (the ARCHITECTURE "ban check" step is the edge's peer-address check, unchanged).

### [x] Task 6.1 — `docs/PROTOCOL.md`

[x] **Action 6.1.1** — modify `docs/PROTOCOL.md`, §1:
- `presents the same identity certificate on each dial-back connection (§4) when the OPEN sets use_mtls.` →
  `presents its current identity certificate on each dial-back connection (§4) when the OPEN sets use_mtls. A renewal does not revoke the previous identity certificate: every unexpired generation is accepted. An identity certificate is valid for --cert-validity (default 4380 h = 182.5 days) from the issuance that produced it.`
- Revocation bullet →
  `Revocation is the ban engine ONLY (no CRL): ip / cidr / country bans on the peer address, and tunnel-name bans. A banned name is refused when the phone connects (/api/v1/control, /api/v1/issue, the mTLS dial-back); on a ban reload the node holding its control connection closes it and the splices opened through it end on every node (§3). The public edge checks only the client's address, never the tunnel. Each node reloads its own ban files, so until every node has loaded a ban the phone can still connect to one that has not.`

[x] **Action 6.1.2** — modify `docs/PROTOCOL.md`, §2 predicate paragraph: append
  `The root set is fetched from --attest-root-url (default https://android.googleapis.com/attestation/root) and refreshed every --attest-refresh (default 1 h); no root is pinned in the binary. Any status-list entry for a certificate of the chain counts as revoked, whatever its status (SUSPENDED included). The signer allowlist file holds one hex SHA-256 signing-certificate digest per line (case-insensitive; # starts a comment, also after a digest; blank lines are ignored; any even number of hex digits is accepted, the length is not otherwise checked); a line that is not valid hex, an odd number of digits included, rejects the whole file (fatal at startup, the last good set is kept at runtime); an empty file allows no signer.`
  and `fails the chain (attest-untrusted).` → `fails the chain (the phone gets 401 unauthorized; attest-untrusted is the server's metric label).`

[x] **Action 6.1.3** — modify `docs/PROTOCOL.md`, §2 Phase-1 surface:
- Nonce bullet → `GET /api/v1/enroll/nonce → {"nonce": "<hex>"} — 32 random bytes as hex, single-use, valid 5 minutes. The attestation challenge is the hex-DECODED bytes. The nonce route and POST /api/v1/enroll share the per-IP enroll windows (--limit-enroll-minute, default 2; --limit-enroll-hour, default 20): each nonce call, and each POST that passes parsing and the read-only rate pre-check, spends one slot, so an attempt (nonce + POST) spends two.`
- After `` `400` otherwise. `` append: `Reasons: bad_source_ip 400 (not reachable through the edge); banned 403; enroll_rate 429 on the nonce route and 503 on POST (retryable, retry_after_seconds = time to the next window); bad_request, bad_json, bad_nonce, bad_attestation_chain, bad_identity_csr 400; invalid_nonce 503 retryable; unauthorized 401; name_unavailable 503; internal 503; unsupported_key_type 400; identity_sign_failed 503 retryable. An unknown path or method on --enroll-host gets a plain-text 404.`
- `Every POST /api/v1/enroll consumes its nonce, so the next attempt first fetches a fresh one` →
  `A request that reaches the nonce check consumes the nonce, even if it fails later; one refused before it (ban, a body that does not parse, the rate limit) leaves it unused until it expires. Either way the next attempt first fetches a fresh one`.

[x] **Action 6.1.4** — modify `docs/PROTOCOL.md`, §3 opening: replace `The phone opens ONE outbound HTTP/2 connection … carries:` and its two bullets with:
  `The control stream is a POST /api/v1/control on an HTTP/2 connection to --control-host (mTLS, identity client cert); over HTTP/1.x it is refused with 505 (an IP ban, a rejected certificate, a banned name or a non-POST method is answered first, as below; every HTTP/1.x answer carries Connection: close). Its request body is the phone→server frame stream (only PONG) and its response body the server→phone frame stream (OPEN, PING, RENEW_NUDGE), both length-framed as below; the server flushes each frame and the stream stays open for the connection's lifetime. POST /api/v1/issue (below) may use the same connection or another one, over HTTP/2 or HTTP/1.1: the server authenticates every request by its client certificate.`
  followed by a `/api/v1/control` answers paragraph:
  `200 + the stream. 403 forbidden (a mesh-role or invalid-name certificate, or, with --dialback-mtls=false, no certificate; with the default --dialback-mtls=true a missing, untrusted or expired certificate fails the TLS handshake, with no HTTP answer) or banned, JSON. 405 non-POST, 505 HTTP/1.x, 503 "too many pending" (more than --limit-stream-pending, default 64, handshakes waiting to bind) and 503 "bind failed (retry)", plain text. 400 bad_source_ip, JSON (not reachable through the edge). A new control connection for a name REPLACES the previous one, on any node and whatever identity-certificate generation it presents: the old connection is closed at once on the same node, or at its next route heartbeat (every --route-ttl/3, 10 s by default) on another node. There is no 409.`

[x] **Action 6.1.5** — modify `docs/PROTOCOL.md`, §3 Liveness: `and drops a phone that misses three PONGs.` →
  `It sends the first PING one interval after the stream opens and closes the connection when no PONG arrived for more than three intervals, checked at each PING: 90–120 s after the phone went silent with the default 30 s (about 90 s for a phone that never answers). Frames other than PONG are ignored and do not count as liveness; a frame whose payload exceeds 1 MiB closes the connection.` (the phone's 90 s rule unchanged).

[x] **Action 6.1.6** — modify `docs/PROTOCOL.md`, §3 frame table: `RENEW_NUDGE` payload `{nonce, ari_window}` → `{nonce, ari_window?}`; below the table add:
  `ari_window is optional and is NOT an ACME ARI window: it is the RFC 3339 renewal time the server computed (now or already past); an admin reissue omits it; for a tunnel with no certificate yet it is a year-1 placeholder (0001-01-01T00:00:00Z + 160 h − --acme-renew-margin, 0001-01-05T16:00:00Z by default). Clients may ignore it. Each node's renewal watcher scans its own control connections hourly (the first scan 1 h after start) and nudges a tunnel whose certificate is due: a Let's Encrypt certificate at NotAfter − --acme-renew-margin (default 48 h), or at NotBefore + 160 h − margin while that node's Let's Encrypt client is not built yet; a GTS or ZeroSSL certificate, or none, at NotBefore + 160 h − margin. With the default shortlived profile (160 h certificates) every rule gives a renewal 112 h (≈4.7 days) after issuance.`

[x] **Action 6.1.7** — modify `docs/PROTOCOL.md`, §3 splice paragraph, append: `A ban eviction closes the control connection with close reason ban-evict, which every node keeps for the splices it ends.`

[x] **Action 6.1.8** — modify `docs/PROTOCOL.md`, §3 `/api/v1/issue`:
- `` `tls_csr` MUST request `<name>.<tunnel-domain>`. `` → `tls_csr MUST request exactly <name>.<tunnel-domain> (byte-exact, lowercase): as its single DNS SAN or, with no SAN, as its CN; a non-empty CN must equal it; no IP / email / URI SAN; anything else is 400 csr_domain_mismatch (not retryable).`
- Response → `{identity_cert, public_cert, ca} — the regenerated identity + public certs; ca is the issuing CA's id (letsencrypt, gts or zerossl), not a certificate.`
- Latency → `… so the phone MUST allow at least 400 s for it; the server gives up on the request after 390 s. A phone that gives up earlier can lose the issued certificate (the server discards an order whose requester is gone).`
- After `` `400` otherwise. `` append: `Reasons: bad_source_ip 400 (not reachable through the edge); forbidden (as for /api/v1/control), banned 403; method_not_allowed 405; bad_request, bad_json, bad_nonce, bad_attestation, bad_identity_csr, bad_tls_csr 400; invalid_nonce 503; unauthorized 401; name_unknown 400; csr_domain_mismatch 400; unsupported_key_type 400; identity_sign_failed 503; issuance_cap 503; acme_rate_limited 503; acme_transient 503 (retry_after_seconds 60); acme_failed 400; internal 503.`
- `Every attempt CONSUMES its single-use nonce, including a failed one, and the enroll and issue nonces share ONE namespace, so` → `An attempt that reaches the nonce check consumes its nonce, even if it fails later, and one refused before it leaves it unused; the enroll and issue nonces share ONE namespace, so`.
- `the same reason with 604800 (7 days) means the weekly issuance cap (--issue-per-week) is reached.` →
  `this 300 s is a fixed pacing hint (the other issuance may run up to 390 s). The weekly issuance cap allows --issue-per-week (default 3) SUCCESSFUL issuances per name in a fixed 7-day window that starts at the first success (failures never count); once it is reached the answer is 503 issuance_cap with retry_after_seconds = the time left in that window.`

[x] **Action 6.1.9** — modify `docs/PROTOCOL.md`, §3 renewal paragraph: `The connection stays up on the old certs until the response installs the new ones.` →
  `Renewal does not change the live control connection: it keeps the certificate it was opened with; the new identity certificate is used from the next TLS handshake (a reconnect, a dial-back), and the previous one stays valid until it expires. An identity certificate expires 182.5 days (by default) after the issuance that produced it, so a phone that has not renewed successfully for that long — being offline alone is not the cause — can no longer connect or renew: it must enroll again and gets a NEW name; an old name is never reassigned. A control connection still open at that moment is closed by the server at its next PING (close reason cert-expired).`

[x] **Action 6.1.10** — modify `docs/PROTOCOL.md`, §4 dial-back:
- After the request block: `The server checks the method (GET), exactly HTTP/1.1, the X-Dial-Token, and Upgrade: tunneld-dial (case-insensitive); Host must be present and well-formed but its value is not checked, and Connection is not checked. With use_mtls any unexpired identity-certificate generation is accepted.`
- `` `404` unknown, expired, already-used token or a token of another tunnel `` → `404 unknown, expired or already-used token, or — with use_mtls — a token of another tunnel (without use_mtls the token alone authorises the dial-back)`.
- `If the open fails, the entry node takes ONE fresh route lookup and retries once (same token) when the route changed, then closes the client.` →
  `If the open fails — the OPEN could not be delivered, or no dial-back arrived within --limit-dialback-timeout — the entry node takes ONE fresh route lookup and, when the route changed, sends a second OPEN with the SAME token; if that also fails, or the route did not change, it closes the client. A phone can therefore receive one token twice; a dial-back for a token already used gets 404. A 101 does not guarantee a splice: when the wait is already over (timed out, another dial-back for the token won, or the node is shutting down), the connection is closed right after the 101.`
- New paragraph after it: `Public connection limits: the entry node closes a public connection once it is older than both 60 s and --limit-conn-min-grace (default 60 s) and carried fewer than --limit-conn-min-rate (default 2 KiB) bytes over the last 60 s, both directions together; with the defaults an idle public connection therefore lasts about 60 s, and --limit-conn-idle (default 120 s without any byte) only matters when set below that.`

[x] **Action 6.1.11** — modify `docs/PROTOCOL.md`, §5 errors sentence, append: `403 a non-mesh-role certificate; 404 any other path; 400 a body that is not valid JSON within its first 4096 bytes; error bodies are plain text. renew answers applied:false when the node holds no live connection for the tunnel or its send buffer is full; terminate answers applied = whether a live phone connection existed on that node.`

[x] **Action 6.1.12** — modify `docs/PROTOCOL.md`, §6, append: `- An IP-ban 403 on /api/v1/enroll or /api/v1/control comes only on a connection opened before the ban was loaded; a new connection from a banned address is closed by the edge before TLS.`

Definition of Done:
- [x] Every PROTOCOL.md statement above matches the code after this plan.

### [x] Task 6.2 — Other docs

[x] **Action 6.2.1** — modify `docs/ARCHITECTURE.md`:
- `:64` `internal/phoneconn` row: `` `/api/v1/control` stream (OPEN dial-back, PING, RENEW_NUDGE) `` → `` `/api/v1/control` stream (HTTP/2 only, HTTP/1.x → 505; OPEN dial-back, PING, RENEW_NUDGE; the newest connection for a name replaces the previous one) ``; `` `/api/v1/issue` cert generation `` → `` `/api/v1/issue` cert generation (390 s handler deadline) ``.
- `:214` `owner/fp/connID` → `owner/connID`.
- `:246-249` (§7) `on a reload, evicts BOTH the newly-banned tunnel's live phone control connection (EvictBanned) AND its in-flight public splices (EvictBannedStreams, close_reason=ban-evict) — bans are the only revocation, so a reload must stop live traffic, not just new admissions.` →
  `on a reload, closes the newly-banned tunnel's live phone control connection (EvictBanned, tunnel-name bans); the splices opened through it then end on every node through the evict broadcast (close_reason=ban-evict), the per-splice route check being the fallback — bans are the only revocation, so a reload stops live traffic, not just new admissions. The public edge checks only the client address.`

[x] **Action 6.2.2** — modify `docs/PROJECT.md`:
- `:76-79` Revocation bullet → `Revocation is the ban engine ONLY (no CRL): a tunnel-name ban refuses the phone at the control plane (control connection, /api/v1/issue, mTLS dial-back) and, on ban reload, closes its live control connection; the splices opened through it then end on every node (close_reason=ban-evict) — live traffic is stopped, not only new admissions. The public edge checks only the client address (ip / cidr / country).`
- `:149` ban kinds: `` `tunnel-name`, `tunnel-fingerprint`. `` → `` `tunnel-name`. ``

[x] **Action 6.2.3** — modify `README.md`:
- `:126`: delete the `tunnel-fingerprint sha256:<hex>` line of the ban-file example.
- `:134-136` Revocation paragraph → `**Revocation** (there is no CRL — bans are the only revocation): revoke a tunnel (tunnel-name) or a source (ip / cidr / country) by editing deploy/banfiles/bans.txt on the host (bind-mounted read-only at /banfiles-manual/bans.txt); each node hot-reloads it within --ban-poll. A banned source can no longer open connections (the edge closes them before TLS; connections it already has are not cut). A banned tunnel is refused at the control plane, and the node holding its control connection closes it, which ends its splices on every node.`

[x] **Action 6.2.4** — modify `.claude/rules/project.md`:
- `:111-114` (user direction) → `- **Revocation is the ban engine ONLY** (no CRL): tunnel-name bans are enforced at the phone control plane — on connect (/api/v1/control, /api/v1/issue, the mTLS dial-back) and live on ban reload via the EvictBanned hook (the owner closes the phone control connection; its splices then end on every node through the evict broadcast, close_reason=ban-evict). The public edge checks only the client address (ip/cidr/country). These points MUST stay wired.`
- "MANDATORY: Read These First" item 4: append `Route ownership and the ban model are described by docs/ARCHITECTURE.md and docs/PROTOCOL.md, which are canonical for them.` (no plan number).

Definition of Done:
- [x] `grep -rn 'tunnel-fingerprint\|EvictBannedStreams\|owner/fp\|identity-fingerprint\|604800\|evicts any live matching' docs/PROJECT.md docs/ARCHITECTURE.md docs/PROTOCOL.md README.md .claude/rules/` is empty.
- [x] `git diff main -- docs/PROJECT.md docs/ARCHITECTURE.md docs/PROTOCOL.md README.md .claude/rules/` adds no plan number.

## [x] User Story 7 — Ground-up verification

Re-check everything from the ground up against D1–D12, so nothing ships that diverges from the decisions or fails a gate.

Acceptance criteria:
- [x] Every action is done and matches D1–D12; every deviation is recorded below.
- [x] Every quality gate is green, and `make test-e2e` ran with the device connected with no device test skipped.
- [x] The nodes' ban files were checked for `tunnel-fingerprint` lines and the result reported to the user.

### [x] Task 7.1 — Final verification (LAST)

[x] **Action 7.1.1** — re-read this plan from disk; confirm every action is done and matches D1–D12; record any needed deviation below.
[x] **Action 7.1.2** — `grep` sweeps over non-test Go and Kotlin code and the docs: no fingerprint ban, two-argument `MatchTunnel`,
`EvictBannedStreams`, `banTun`, `ErrNameHeldByOther`, `SelfHealConflict`, `StatusConflict` in `internal/phoneconn`, `ca.Fingerprint`,
`rolling` in `internal/limit/issuance.go`, `§1` in `internal/ca/ca.go`, `§6` in `internal/ban/dbip.go`; in both apps the
`/api/v1/issue` POST goes through `issueClient`, the `/api/v1/enroll` POST through `enrollClient`, and `postJson` builds no client.
[x] **Action 7.1.3** — review the full diff: no comment text added (only wrong parts removed), no unrelated change.
[x] **Action 7.1.4** — quality gates, each run once with `tee` to `/tmp/plan18-<gate>.log`: `make lint` (all four tags, 0 issues),
`make vet`, `make govulncheck`, `make build`, `make test-unit`, `make test-integration`, `make test-staging`,
`make test-scripts`, `make compose-config`, `make soak-app tunnel-app` (JVM tests + both APK fixtures; commit the
rebuilt fixtures, `signers.allow` unchanged); then tell the user that `make test-e2e` reinstalls both apps on the
connected phone and run it with the device connected — no device test may skip.
[x] **Action 7.1.5** — before any rollout (operational, not code): read-only check of each node's ban files for
`tunnel-fingerprint` lines, reported to the user.

Definition of Done:
- [x] All gates green, all checkboxes ticked, results reported to the user.

## Deviations

- Tasks 1.5 and 2.5 (e2e tests): `echoPhone` now delegates to a new `echoPhoneRun` helper that also returns the
  client's `Run`-done channel, so `TestE2E_TunnelNameBanEndsSplicesOnEveryNode` and
  `TestE2E_RenewedIdentityTakesOverAcrossNodes` can observe the control connection closing. Every existing
  `echoPhone` caller is unchanged.
- Task 4.4: the planned `TestLimiter_IssuanceBegin_WindowReadErrorReturned` and
  `TestLimiter_IssuanceBegin_WindowRestoreErrorReturned` are one table-driven test,
  `TestLimiter_IssuanceBegin_WindowErrorsReturned` (go.md: table-driven tests by default); both cases are covered.
- Task 5.2 (code review): the Context of Action 5.2.1 said the Android TLS handshake waits in Conscrypt's `sslSelect`;
  current Conscrypt has no such call (only a stale header comment names it). The Context now gives the verified path
  (engine socket reading the raw socket's stream; Android wakes a read blocked on a closed socket). No code change.
- Task 4.4 (code review): `TestServeIssue_StalledBodyAnsweredAtDeadline` is table-driven over HTTP/1.1 and HTTP/2, so
  the read deadline is tested on HTTP/2, the protocol phones use for `/api/v1/issue`.
- Task 5.6 (device tests): the two "stop unbinds at once" tests share two small helpers in `e2e/app_rules_test.go`,
  `e2eRegistry` (a router over the e2e Valkey) and `assertStopUnbinds` (bound before stop, unbound within 5 s after).
