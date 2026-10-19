<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 4 — Full-Codebase Audit Remediation

Fixes all 47 findings of the adversarial audit of `main` @ 220c050 **except I-17** (fetcher floating
`alpine:3` + per-start `apk add` — explicitly accepted by the user for simplicity) and **except the
W-10 RNG-failure sub-point** (a `crypto/rand` failure fallback is explicitly out of scope by user
decision). Finding IDs (C-1…C-3, W-1…W-24, I-1…I-20) refer to the audit report reviewed with the user.

Agreed designs (decision record — MUST NOT be deviated from):

- **C-2**: `no-route` rejections → metric + **Debug-level plain log only** (no caplog, no dedup on that
  path). caplog dedup unchanged for all other reasons.
- **W-1**: ALL startup construction (reserved-cert issuance included) happens BEFORE binding `:443`;
  listeners bind dead last.
- **W-3**: async conn-log writer — bounded channel (cap **5000**), **8** workers, per-item exponential
  retry; queue full → **drop-newest + increment a dropped-events counter metric**; drain flushes the
  queue at shutdown (also fixes W-2's lost end events). Event reordering is accepted (end events are
  self-contained).
- **W-10**: connID/streamID = **4 crypto/rand bytes (8 lowercase hex)**, time prefix dropped;
  collision handled by **detect-and-retry at the existing serialization points** (route bind re-roll;
  pending-stream duplicate refusal) — NO separate SETNX reservation keys.
- **W-17**: per-name inflight **hash** `iss_inflight:{name}` (field = order id, value = deadline ms),
  purged lazily inside the acquire Lua script; **10 s heartbeat / 30 s slot deadline**; slot freed on
  completion (success AND failure); `iss:{name}` still counts successes only; NO `HEXPIRE`, NO cleanup
  goroutine.
- **W-18**: `conc:{name}` TTL derived = **3 × `--limit-conn-idle`**, refreshed by a `PEXPIRE`
  piggybacked on the per-chunk `claimTrafficScript` (`PEXPIRE` on a missing key is a no-op — verified
  against valkey.io — so a torn-down counter is never resurrected).
- **I-17 / fetcher**: unchanged, on purpose.

Verified upstream facts relied on below: x/net v0.58.0 `http2.responseWriter.SetWriteDeadline` with a
past deadline resets the stream immediately, failing an in-flight flow-control-blocked write
(`golang.org/x/net@v0.58.0/http2/server.go` `SetWriteDeadline`/`onWriteTimeout`); Valkey `PEXPIRE` on a
nonexistent key returns 0 and never creates the key (valkey.io/commands/pexpire).

---

## [x] US1 — Fail-fast configuration & logging validation (W-20, I-11, I-12, I-13)

Silent misconfigurations must fail at startup, not at runtime.

Acceptance criteria:
- [x] `--s3-endpoint` without an `http(s)://` scheme is rejected by `Validate()`.
- [x] `--attest-status-max-stale` ≤ `--attest-refresh` is rejected.
- [x] `--acme-gts-validity` ≤ (160h − `--acme-renew-margin`) is rejected (cert would expire before the fixed non-LE renewal point).
- [x] A `--log` spec containing two `output=` keys is a parse error (not silent std-wins).

### [x] Task 1.1 — config cross-field guards

- [x] Action: modify `internal/config/config.go` — add `{"--s3-endpoint", c.S3Endpoint}` to the
  existing URL-prefix loop (the loop currently checks the five ACME/attest URLs).
- [x] Action: modify `internal/config/config.go` — after the duration loop, add:

```go
if c.AttestStatusMaxStale <= c.AttestRefresh {
	return fmt.Errorf("--attest-status-max-stale (%s) must exceed --attest-refresh (%s): a staleness bound at or below the refresh cadence refuses enrollment for the tail of every refresh window", c.AttestStatusMaxStale, c.AttestRefresh)
}
if c.ACMEGTSValidity <= shortlivedLifetime-c.ACMERenewMargin {
	return fmt.Errorf("--acme-gts-validity (%s) must exceed %s (the fixed non-LE renewal point = 160h shortlived − --acme-renew-margin): shorter GTS certs would expire before the renewal nudge fires", c.ACMEGTSValidity, shortlivedLifetime-c.ACMERenewMargin)
}
```

- [x] Definition of Done: both guards reject the bad values and accept the defaults (`24h`/`1h`,
  `168h`/`48h`); `Validate()` unit tests cover accept + reject per guard.

### [x] Task 1.2 — duplicate `output=` keys rejected

- [x] Action: modify `internal/logging/logging.go` `parseSpec` — in the `case "output":` branch, add
  before the existing logic:

```go
if haveOutput {
	return spec{}, fmt.Errorf("duplicate output= in log spec %q (use one --log flag per sink)", raw)
}
```

- [x] Definition of Done: `output=std;output=/x.log` and `output=/x.log;output=std` both error; a
  single `output=` still parses.

### [x] Task 1.3 — US1 tests

| Test | Verifies |
|---|---|
| `TestServeCmd_Validate_S3EndpointScheme` | scheme-less `--s3-endpoint` rejected; `http://` accepted |
| `TestServeCmd_Validate_AttestStaleVsRefresh` | max-stale ≤ refresh rejected; default accepted |
| `TestServeCmd_Validate_GTSValidityVsRenewal` | 72h validity + 48h margin rejected; default 168h accepted |
| `TestParseSpecs_DuplicateOutput` | both duplicate orderings error; message names the spec |

- [x] Definition of Done: all four tests present and passing (tests run at Stage-4 quality gates only).

---

## [x] US2 — Connection/stream ID scheme with deterministic collision handling (W-10)

Phone connIDs currently carry 16 bits of entropy (`NewConnID(now, now)` zeroes the 3 time bytes for
every phone conn by construction); the owner-conditional route guarantee is only probabilistic. New
scheme: 4 random bytes, collisions detected and re-rolled at the two serialization points.

Acceptance criteria:
- [x] `store.NewConnID()` returns 8 lowercase hex chars from 4 `crypto/rand` bytes; no time argument.
- [x] `BindRoute` refuses a bind whose connID equals the currently-stored connID for the name (re-roll signal); the phone bind re-mints and retries (bounded).
- [x] `OpenStream` refuses a duplicate pending streamID instead of overwriting; the edge re-mints once and retries (local and mesh paths).
- [x] The unused `startedAt` route field and every signature carrying it are removed.

### [x] Task 2.1 — `store.NewConnID`

- [x] Action: modify `internal/store/event.go` — replace `NewConnID` (and its doc comment):

```go
// NewConnID mints an 8-lowercase-hex connection/stream id (4 crypto/rand bytes). Uniqueness among
// the live ids of one tunnel is enforced by the consumers (route-bind re-roll on collision;
// pending-stream duplicate refusal) — a collision is detected and retried, never silent.
func NewConnID() (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: conn id rand: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}
```

  Drop the now-unused `binary` import. `LogKey`'s `conn8` slicing needs no change (ids are now 8 chars).
- [x] Definition of Done: every minted id is 8 lowercase hex chars; no caller passes time arguments.

### [x] Task 2.2 — router: connID-collision re-roll + `startedAt` removal

- [x] Action: modify `internal/router/route_e2e.go` — `bindRouteScript` becomes:

```lua
local fp = redis.call('HGET', KEYS[1], 'fingerprint')
if fp and fp ~= ARGV[2] then
  return 'conflict'
end
if redis.call('HGET', KEYS[1], 'connID') == ARGV[3] then
  return 'reroll'
end
redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return 'ok'
```

  `selfHealRouteScript` drops the `startedAt` HSET field (self-heal's connID-equality path is the
  OWNER path and stays permitted). New sentinel `var ErrConnIDCollision = errors.New("router: connID collides with the current route owner")`;
  `BindRoute(ctx, name, nodeID, fingerprint, connID string) error` returns it on `'reroll'`.
  `BindRouteIfAbsentOrOwner` and `LookupRoute` drop `startedAt` from signature/return; the file-top
  comment about the conn-id epoch is deleted. Add the `errors` import to `route_e2e.go` (the
  sentinel; per-file imports) and drop its now-unused `strconv` and `time` imports.
- [x] Action: modify `internal/phoneconn/manager.go` — `Router` interface: drop `startedAt` params.
  `register` re-rolls on collision (inside the Task 3.3 stripe lock):

```go
for attempt := 0; ; attempt++ {
	err := m.router.BindRoute(ctx, c.name, m.nodeID, c.fingerprint, c.connID)
	if err == nil {
		break
	}
	if !errors.Is(err, router.ErrConnIDCollision) || attempt >= 2 {
		return nil, err
	}
	c.connID = mustConnID() // collision with the previous conn's id — re-mint and retry
}
```

  `heartbeatLoop`'s self-heal call drops `c.sessionStart`. `mustConnID` in
  `internal/phoneconn/listener.go` becomes zero-argument (`store.NewConnID()`, fallback `"00000000"`).
  Add the `errors` import to `manager.go` (the sentinels + `errors.Is`).
- [x] Action: modify `internal/edge/edge.go` + `internal/edge/bridge.go` — `Router` interface
  `LookupRoute` drops `startedAt`; both `store.NewConnID(...)` streamID mints become
  `store.NewConnID()`; delete the now-unused `startedAt`/`s2` variables.
- [x] Definition of Done: `grep -r startedAt internal/ client/` finds no route-record remnant; a bind
  colliding with the stored connID re-rolls (bounded) instead of binding.

### [x] Task 2.3 — pending-stream duplicate refusal + edge re-mint

- [x] Action: modify `internal/phoneconn/manager.go` — new sentinel
  `var ErrDuplicateStreamID = errors.New("phoneconn: duplicate stream id")`; in `OpenStream`, under
  `c.mu` before registering the waiter:

```go
if _, exists := c.pending[streamID]; exists {
	c.mu.Unlock()
	return nil, ErrDuplicateStreamID
}
```

- [x] Action: modify `internal/mesh/listener.go` — the current handler commits the 200 response
  BEFORE `BridgeMesh` runs, so an open-phase error could never change the status. Restructure the
  owner side into an explicit open phase followed by the splice — `Bridge` becomes two-phase (mesh
  MUST NOT import phoneconn, so the error crosses as a mesh-owned sentinel):

```go
// ErrDuplicateStream reports a dial-back stream id already pending on the owner's phone connection
// (the entry node re-mints the id and retries once).
var ErrDuplicateStream = errors.New("mesh: duplicate stream id")

// Bridge opens the local phone dial-back stream (open phase — BEFORE the mesh response commits, so
// an open failure can still pick the HTTP status) and then splices it with the mesh client stream.
type Bridge interface {
	OpenMesh(ctx context.Context, tunnel, streamID string) (io.ReadWriteCloser, error)
	SpliceMesh(ds, client io.ReadWriteCloser)
}
```

  `ServeHTTP` becomes: header/role/owner checks unchanged → `ds, err := h.bridge.OpenMesh(r.Context(), tunnel, streamID)`;
  on `errors.Is(err, ErrDuplicateStream)` → `http.Error(w, "duplicate stream", http.StatusUnprocessableEntity)`
  (409 stays = not-owner); on any other error → `http.Error(w, "dial-back failed", http.StatusBadGateway)`;
  ONLY on success `w.WriteHeader(http.StatusOK)` + flush → build the `ownerStream` → `h.bridge.SpliceMesh(ds, cs)`
  → `<-cs.done`. Add the `errors` import.
- [x] Action: modify `internal/server/serve.go` — `bridgeAdapter` implements the two-phase `Bridge`:
  `OpenMesh` is the current `BridgeMesh` dial-back logic (bounded by `dialBackTimeout`) returning the
  stream, translating `phoneconn.ErrDuplicateStreamID` → `mesh.ErrDuplicateStream` (wrap:
  `fmt.Errorf("…: %w", mesh.ErrDuplicateStream)` or return the sentinel directly); `SpliceMesh` is the
  existing `bridgeCopy(ds, client)`. Delete `BridgeMesh`. Add the
  `github.com/danielealbano/android-remote-control-mcp-tunneld/internal/mesh` import.
- [x] Action: modify `internal/mesh/client.go` — `OpenStream` maps the response status:
  200 → stream; `http.StatusUnprocessableEntity` → `ErrDuplicateStream`; any other → `ErrNoOwner`
  (as today).
- [x] Action: modify `internal/edge/bridge.go` `handleTunnel` — before the existing stale-route retry,
  add ONE duplicate-stream retry that re-mints the streamID and re-opens against the SAME route:

```go
far, closeFar, ferr := e.openFar(ctx, name, nodeID, connID, streamID)
if isDuplicateStream(ferr) {
	streamID, _ = store.NewConnID()
	far, closeFar, ferr = e.openFar(ctx, name, nodeID, connID, streamID)
}
```

  with `func isDuplicateStream(err error) bool { return errors.Is(err, phoneconn.ErrDuplicateStreamID) || errors.Is(err, mesh.ErrDuplicateStream) }`.
  Add the `errors`, `phoneconn`, and `mesh` imports to `bridge.go` (imports are per-file:
  `bridge.go` does not import phoneconn today — `edge.go`/`accept.go` do — and mesh imports nothing
  from edge, so no cycle).
- [x] Definition of Done: a duplicate pending streamID is refused (never overwritten) on both paths;
  the edge retries exactly once with a fresh id.

### [x] Task 2.4 — US2 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestNewConnID_Format` | 8 lowercase hex, hex-parseable, non-constant across a handful of mints | NO large-sample distinctness assert: 10k draws from 2^32 collide ~1.2% of runs, and collisions are handled by design (re-roll) |
| `TestRegistry_BindRoute_ConnIDCollisionRerolls` | bind with the stored connID → `ErrConnIDCollision`; different id succeeds | miniredis |
| `TestManager_Register_RerollsOnCollision` | fake Router returning collision twice → third id bound; three failures → error | |
| `TestManager_OpenStream_DuplicateRefused` | second OpenStream with the same id → `ErrDuplicateStreamID`, first waiter intact | |
| `TestEdge_HandleTunnel_DuplicateStreamRetries` | duplicate-stream error from the dialer → one re-mint + successful retry | fake LocalDialer |
| `TestEdge_HandleTunnel_MeshDuplicateRetries` | `mesh.ErrDuplicateStream` from the mesh dialer → one re-mint + successful retry | fake MeshDialer |
| `TestMeshHandler_DuplicateStreamAnswers422` | fake Bridge `OpenMesh` → `ErrDuplicateStream` ⇒ 422 before any body; other error ⇒ 502; success ⇒ 200 | |
| `TestMeshClient_Maps422ToDuplicateStream` | h2 test server answering 422 → `ErrDuplicateStream`; 409 → `ErrNoOwner` | |
| `TestBridgeAdapter_TranslatesDuplicateStreamID` | fake manager returning `phoneconn.ErrDuplicateStreamID` → `mesh.ErrDuplicateStream` from `OpenMesh` | |

- [x] Definition of Done: all router/phoneconn/edge tests updated for the removed `startedAt`
  parameters; no reference to the old 10-char id format survives outside git history.

---

## [x] US3 — Phone control plane: teardown deadlock, race-free lifecycle (C-1, W-7, W-8, I-3, I-4, I-5)

Acceptance criteria:
- [x] `DataStream.Close` (and mesh `ownerStream.Close`) unblocks a flow-control-blocked `Write` and never deadlocks.
- [x] A dead connection's heartbeat can never re-bind its route after teardown started (heartbeat fully stopped before unbind).
- [x] Two concurrent binds for one name are serialized: the local winner is always the Valkey owner.
- [x] A transient bind failure answers 503 retryable; a fingerprint conflict stays 409.
- [x] A pathological `--route-ttl` cannot panic the heartbeat ticker.
- [x] A bound phone whose identity cert passes `NotAfter` is closed (`cert-expired`).

### [x] Task 3.1 — C-1: interruptible stream writes

- [x] Action: modify `internal/phoneconn/stream.go` — add an `unblock func()` field to
  `httpDataStream`; `Close` calls it BEFORE taking the mutex:

```go
func (d *httpDataStream) Close() error {
	d.once.Do(func() {
		// Reset the HTTP/2 stream FIRST: an in-flight Write blocked on stream flow control (a peer
		// withholding WINDOW_UPDATE) fails immediately and releases d.mu — otherwise Close would
		// deadlock on the mutex and pin the watcher, both copies, and every held slot.
		if d.unblock != nil {
			d.unblock()
		}
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		close(d.done)
	})
	return nil
}
```

- [x] Action: modify `internal/phoneconn/listener.go` `serveData` — wire the unblock through
  `http.NewResponseController` (supported by the x/net h2 response writer at the pinned version):

```go
rc := http.NewResponseController(w)
ds := &httpDataStream{r: r.Body, w: w, flush: flusher.Flush, done: done,
	unblock: func() { _ = rc.SetWriteDeadline(time.Now()) }}
```

- [x] Action: modify `internal/mesh/listener.go` — identical `unblock` field + `Close` ordering on
  `ownerStream`, wired in `ServeHTTP` via `http.NewResponseController(w)`. Add the `time` import
  (the immediate deadline).
- [x] Definition of Done: no code path takes `d.mu`/`o.mu` while performing a network write that
  `Close` cannot interrupt.

### [x] Task 3.2 — W-7: heartbeat fully stopped before unbind

- [x] Action: modify `internal/phoneconn/manager.go` — `conn` gains `hbDone chan struct{}` (created in
  `serveControl`'s conn literal); `heartbeatLoop` gains `defer close(c.hbDone)`. `register`'s teardown
  is reordered:

```go
teardown := func() {
	c.close("phone-close") // cancel the conn ctx FIRST: no further heartbeat/self-heal can run
	<-c.hbDone             // wait for the heartbeat loop (incl. an in-flight self-heal) to exit
	m.mu.Lock()
	if m.conns[c.name] == c {
		delete(m.conns, c.name)
	}
	m.mu.Unlock()
	tctx, cancel := context.WithTimeout(context.Background(), teardownTimeout)
	defer cancel()
	if err := m.router.Unbind(tctx, c.name, c.connID); err != nil {
		m.logger.Warn("route unbind failed (route expires by TTL)", "tunnel", c.name, "err", err)
	}
	m.writeEvent(tctx, c, "end", c.closeReason())
	m.rec.PhoneConnClose(c.closeReason())
}
```

  Note `c.close("phone-close")` moves from last to first (first-close-wins keeps any earlier real
  reason). The heartbeat goroutine is ALWAYS started when teardown can run (`serveControl` has no
  return between `register` and the `go` statements), so `<-c.hbDone` cannot hang.
- [x] Definition of Done: after teardown returns, no self-heal rebind of that connID is possible.

### [x] Task 3.3 — W-8: per-name bind serialization

- [x] Action: modify `internal/phoneconn/manager.go` — `Manager` gains
  `bindMu [64]sync.Mutex` and

```go
// bindLock returns the striped per-name mutex serializing BindRoute + the local-map insert, so a
// concurrent same-name bind can never leave the Valkey owner different from the local winner.
func (m *Manager) bindLock(name string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return &m.bindMu[h.Sum32()%uint32(len(m.bindMu))]
}
```

  `register` wraps the bind-reroll loop (Task 2.2) AND the supersede-and-insert critical section in
  `l := m.bindLock(c.name); l.Lock(); defer l.Unlock()`. Add the `hash/fnv` import.
- [x] Definition of Done: with two concurrent registers for one name, the conn left in `m.conns` is
  the one whose connID Valkey holds.

### [x] Task 3.4 — I-3 / I-4 / I-5

- [x] Action: modify `internal/phoneconn/listener.go` `serveControl` — distinguish bind failures:

```go
teardown, err := h.mgr.register(ctx, c)
if err != nil {
	if errors.Is(err, router.ErrNameHeldByOther) {
		http.Error(w, "bind conflict", http.StatusConflict)
	} else {
		http.Error(w, "bind failed (retry)", http.StatusServiceUnavailable)
	}
	return
}
```

  Add the
  `github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router` import to
  `listener.go` (`errors` is already imported there).
- [x] Action: modify `internal/phoneconn/manager.go` `heartbeatLoop` — guard the ticker like the node
  heartbeat: `interval := m.routeTTL / 3; if interval <= 0 { interval = time.Second }`.
- [x] Action: modify `internal/store/event.go` — add `CloseCertExpired = "cert-expired"` to the
  close-reason enum.
- [x] Action: modify `internal/phoneconn/listener.go` — `phoneIdentity` gains `notAfter time.Time`
  (set from `leaf.NotAfter` in `identity()`); `conn` gains `notAfter time.Time` (set in the
  `serveControl` literal); the ping tick adds, before the liveness check:

```go
if !c.notAfter.IsZero() && time.Now().After(c.notAfter) {
	c.close(store.CloseCertExpired) // the CA's exposure bound is enforced live, not only at reconnect
	return
}
```

- [x] Definition of Done: conflict→409 / transient→503 verified; a tiny route-ttl cannot panic; an
  expired identity cert closes the conn as `cert-expired` within one ping interval.

### [x] Task 3.5 — US3 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestHTTPDataStream_CloseUnblocksBlockedWrite` | `Write` blocked in a stub writer; `Close` returns promptly once `unblock` fires; writer released | stub writer blocks until unblock func called |
| `TestOwnerStream_CloseUnblocksBlockedWrite` | same for the mesh ownerStream | |
| `TestManager_Teardown_StopsHeartbeatBeforeUnbind` | fake Router records call order: no Heartbeat/self-heal after Unbind | |
| `TestManager_ConcurrentSameNameBind_LocalMatchesValkey` | 2 goroutines × register same name (miniredis): surviving local conn's id == stored connID | run with `-race` |
| `TestServeControl_BindFailureStatuses` | conflict → 409; other error → 503 | |
| `TestServeControl_CertExpiryCloses` | conn with past `notAfter` closed `cert-expired` on the ping tick | injectable clock or short ping interval |
| `TestHeartbeatLoop_TinyRouteTTLNoPanic` | `routeTTL=1ns` does not panic | |

- [x] Definition of Done: all above passing; existing phoneconn tests updated for the new teardown
  ordering and signatures.

---

## [x] US4 — Edge: attacker-proof logging, accept-loop and slot correctness (C-2, W-5, W-6, W-9, W-12, W-14, I-1)

Acceptance criteria:
- [x] `no-route` rejections write NO caplog entry and NO WARN — metric + Debug line only.
- [x] The accept loop backs off exponentially on persistent accept errors (cap 1 s).
- [x] SNI dispatch and tunnel-name derivation are case-insensitive; config hosts are normalized once.
- [x] A ban reload kills matching ACTIVE public splices (`close_reason=ban-evict`), not just the phone control conn.
- [x] A fail-open stream admission never DECRs `conc:{name}`; evict-and-retry releases the victim's slot synchronously so the retry actually admits.
- [x] A banned fresh route on the retry path records reason `ban`.

### [x] Task 4.1 — C-2: no-route → metric + debug only

- [x] Action: modify `internal/metrics/recorder.go` `Reject`:

```go
func (p *PromRecorder) Reject(reason, tunnelName, clientIP string) {
	if _, ok := knownRejectReasons[reason]; !ok {
		p.log.Error("unregistered rejection reason refused", "reason", reason, "tunnel", tunnelName)
		return
	}
	p.m.rejections.WithLabelValues(reason).Inc()
	if reason == "no-route" {
		// The tunnel value on this path is attacker-controlled (raw SNI / unrouted name): it must
		// never key the dedup map or emit per-hit WARNs. Metric + debug-only line.
		p.log.Debug("no-route rejection", "sni", tunnelName, "client_ip", clientIP)
		return
	}
	p.caplog.Hit(tunnelName, reason, clientIP)
}
```

- [x] Definition of Done: no `caplog` state is created for any `no-route` hit; all other reasons
  unchanged.

### [x] Task 4.2 — W-5 + W-2 groundwork: accept backoff + handler WaitGroup

- [x] Action: modify `internal/edge/accept.go` `acceptLoop` + `internal/edge/edge.go`:

```go
// edge.go: Edge gains `wg sync.WaitGroup`; new method:
// Wait blocks until every in-flight public-connection handler has returned or ctx expires (server
// drain: end events must be enqueued before the conn-log queue is flushed).
func (e *Edge) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// accept.go:
func (e *Edge) acceptLoop(ctx context.Context, ln net.Listener) {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Exponential backoff (5ms→1s): persistent errors (e.g. EMFILE) must not hot-spin.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			continue
		}
		delay = 0
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.handleConn(ctx, conn)
		}()
	}
}
```

- [x] Definition of Done: persistent accept errors are paced (≤1 s cap, reset on success); `Wait`
  returns once all handler goroutines finish (or ctx expires).

### [x] Task 4.3 — W-6: case-insensitive SNI + normalized config hosts

- [x] Action: modify `internal/server/server.go` `Run` — normalize once at entry (before any use):

```go
cfg.TunnelDomain = strings.ToLower(cfg.TunnelDomain)
cfg.EnrollHost = strings.ToLower(cfg.EnrollHost)
cfg.ControlHost = strings.ToLower(cfg.ControlHost)
```

  Add the `strings` import to `server.go` and to `internal/edge/accept.go` (the lowered-SNI dispatch).

- [x] Action: modify `internal/edge/accept.go` `handleConn` — dispatch on the lowered SNI:
  `sni := strings.ToLower(info.SNI)` and switch on `sni` (raw `info.SNI` stays in logs/JA4 untouched).
- [x] Action: modify `internal/edge/bridge.go` `tunnelName` — operate on
  `sni = strings.ToLower(sni)` first.
- [x] Definition of Done: an uppercased client SNI reaches the right listener; a mixed-case
  `TUNNELD_ENROLL_HOST` works.

### [x] Task 4.4 — W-12 + W-14: slot accounting via a per-stream release-once

- [x] Action: modify `internal/edge/bridge.go` — `activeStream` gains
  `fp string`, `banned atomic.Bool`, `release func()`. In `handleTunnel`, replace the acquire/release
  block:

```go
acq, aerr := e.lim.AcquireStream(ctx, name, e.cfg.Concurrent)
if aerr != nil {
	acq = true
} else if !acq && e.evictLeastActive(name) {
	acq, aerr = e.lim.AcquireStream(ctx, name, e.cfg.Concurrent)
	if aerr != nil {
		acq = true
	}
}
if !acq {
	e.rec.Reject("stream-cap", name, peerAddr(client))
	_ = client.Close()
	return
}
// Release-once: fires only when a slot was REALLY acquired (a fail-open admission must not DECR a
// slot it never took) and at most once (the saturation evictor releases the victim's slot
// synchronously so the retry can admit). The release error stays intentionally ignored: the global
// conc:{name} counter self-heals at its TTL, so a transient Valkey failure at worst delays freeing
// one slot — and there is no logger on the edge's hot path.
slotHeld := aerr == nil
var slotOnce sync.Once
releaseSlot := func() {
	if slotHeld {
		slotOnce.Do(func() { _ = e.lim.ReleaseStream(context.Background(), name) })
	}
}
defer releaseSlot()
```

  `as.fp` and `as.release = releaseSlot` are set in/immediately after the `activeStream` literal,
  BEFORE `trackStream` publishes it (the `e.smu` critical sections give the evictor a happens-before
  on both fields).
- [x] Action: modify `internal/edge/bridge.go` `evictLeastActive` — after `victim.cancel()`:

```go
if victim.release != nil {
	victim.release() // free the Valkey slot NOW; the victim's own deferred release becomes a no-op
}
```

- [x] Definition of Done: fail-open streams never DECR; after an eviction the immediate re-acquire
  sees the freed slot.

### [x] Task 4.5 — W-9: ban reload kills active public splices

- [x] Action: modify `internal/edge/bridge.go` — new method:

```go
// EvictBannedStreams cancels every ACTIVE public splice whose (tunnel, fingerprint) matches: bans are
// the ONLY revocation, so a reload must stop in-flight traffic, not only new admissions.
func (e *Edge) EvictBannedStreams(match func(name, fingerprint string) bool) {
	e.smu.Lock()
	var victims []*activeStream
	for s := range e.streams {
		if match(s.tunnel, s.fp) {
			victims = append(victims, s)
		}
	}
	e.smu.Unlock()
	for _, s := range victims {
		s.banned.Store(true)
		s.cancel()
	}
}
```

  In the splice watcher's `<-ctx.Done()` case, attribute in order:
  `banned → store.CloseBanEvict`, `evicted → store.CloseEvicted`, else `store.CloseServerShutdown`.
- [x] Action: modify `internal/server/server.go` — the `ban.Watch` reload hook additionally calls
  `ed.EvictBannedStreams(func(name, fp string) bool { _, b := e.MatchTunnel(name, fp); return b })`.
- [x] Definition of Done: banning a tunnel terminates its in-flight public connections within one
  ban-poll interval, logged `close_reason=ban-evict`.

### [x] Task 4.6 — I-1: ban recorded on the retry path

- [x] Action: modify `internal/edge/bridge.go` `handleTunnel` retry block — split the ban check out of
  the retry predicate:

```go
if ferr != nil {
	n2, fp2, c2, ok2, lerr := e.router.LookupRoute(ctx, name)
	if lerr == nil && ok2 && (n2 != nodeID || c2 != connID) {
		if e.banTun != nil && e.banTun(name, fp2) {
			e.rec.Reject("ban", name, peerAddr(client))
			_ = client.Close()
			return
		}
		fp = fp2 // the splice now targets the re-bound route: the active stream must carry ITS fingerprint (ban sweeps match on it)
		streamID, _ = store.NewConnID()
		far, closeFar, ferr = e.openFar(ctx, name, n2, c2, streamID)
	}
}
```

  (signature already updated by US2; the duplicate-stream retry from Task 2.3 sits before this block).
- [x] Definition of Done: a banned fresh route rejects with reason `ban`; a successful retry leaves
  `as.fp` = the fresh route's fingerprint.

### [x] Task 4.7 — US4 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestPromRecorder_Reject_NoRouteDebugOnly` | metric incremented; caplog untouched; nothing above Debug logged | capture slog handler |
| `TestAcceptLoop_BackoffOnPersistentError` | erroring listener → bounded call rate (no hot spin), recovers | fake listener |
| `TestHandleConn_SNICaseInsensitive` | uppercased enroll-host SNI reaches the enroll listener | |
| `TestTunnelName_CaseInsensitive` | `NAME.Example.TEST` resolves | |
| `TestHandleTunnel_FailOpenNeverReleases` | acquire error → no `ReleaseStream` call | fake limiter |
| `TestEvictLeastActive_ReleasesVictimSlotOnce` | evict → one release; victim's defer no-ops | |
| `TestEvictBannedStreams_KillsMatching` | matching active stream cancelled, reason `ban-evict`; others untouched | |
| `TestHandleTunnel_RetryPathBanRecordsBan` | banned fresh route → reason `ban`, not `no-route` | |

- [x] Definition of Done: all US4 tests present and passing at the Stage-4 gates.

---

## [x] US5 — Mesh pool reap must not orphan active connections (W-11)

Acceptance criteria:
- [x] A pool with ANY active stream is never reaped, regardless of `lastUse`.

### [x] Task 5.1 — active-stream count on the pool

- [x] Action: modify `internal/mesh/client.go` — `peerPool` gains `active atomic.Int64`. `pool()`
  increments it under `c.mu` before returning (so the increment is atomic with map membership vs the
  reaper); `OpenStream` decrements on EVERY failure return, and `clientStream` gains `p *peerPool`
  with `Close` decrementing once:

```go
func (s *clientStream) Close() error {
	s.once.Do(func() {
		_ = s.pw.Close()
		_ = s.resp.Body.Close()
		s.p.active.Add(-1)
	})
	return nil
}
```

  `Run`'s reap loop skips pools with `p.active.Load() > 0` (they are carrying live streams —
  `CloseIdleConnections` would orphan the busy conn forever).
- [x] Definition of Done: a pool idle by `lastUse` but with an open stream survives the reaper; it is
  reaped on the first tick after the stream closes.

### [x] Task 5.2 — US5 tests

| Test | Verifies |
|---|---|
| `TestClient_ReapSkipsActivePools` | pool with active=1 survives a reap tick; reaped after Close |
| `TestClient_OpenStreamErrorDecrementsActive` | dial failure leaves active back at 0 |

- [x] Definition of Done: both US5 tests present and passing at the Stage-4 gates.

---

## [x] US6 — Limits: clock-safe bandwidth, crash-safe issuance cap, live stream-counter TTL (W-13, W-17, W-18)

Acceptance criteria:
- [x] The bandwidth bucket's `last` anchor never moves backward.
- [x] `--issue-per-week` counts committed + in-flight orders atomically; a crashed order's slot frees in ≤ 30 s; failed orders don't burn the weekly window.
- [x] `conc:{name}`'s TTL = 3 × `--limit-conn-idle` and is refreshed by every traffic chunk, only if the key exists.

### [x] Task 6.1 — W-13: monotone refill anchor

- [x] Action: modify `internal/limit/limiter.go` `claimBandwidthScript` — replace the elapsed/HSET
  section:

```lua
local elapsed = (now - last) / 1e9
if elapsed > 0 then
  tokens = math.min(burst, tokens + elapsed * rate)
else
  now = last -- clock skew / step-back: never move the refill anchor backward
end
local granted = math.min(want, tokens)
if granted < 0 then granted = 0 end
tokens = tokens - granted
redis.call('HSET', KEYS[1], 'tokens', tokens, 'last', now)
redis.call('PEXPIRE', KEYS[1], ttl)
return math.floor(granted)
```

- [x] Definition of Done: a `now < last` call grants from the existing tokens without advancing or
  regressing `last`.

### [x] Task 6.2 — W-18: derived TTL + per-chunk refresh

- [x] Action: modify `internal/limit/concurrency.go` — delete the `streamCapTTL` const; `AcquireStream`
  uses `l.streamTTL`.
- [x] Action: modify `internal/limit/limiter.go` — `Limiter` gains `streamTTL time.Duration`;
  `NewLimiter(rdb redis.UniversalClient, bwRate, dayCap, weekCap int64, streamTTL time.Duration) *Limiter`.
  `claimTrafficScript` gains `KEYS[3]` = `conc:{name}` and `ARGV[6]` = the TTL — the full modified
  script (the PEXPIRE sits BEFORE the final `return`, which must stay the last statement):

```lua
local n = tonumber(ARGV[1])
local dayCap = tonumber(ARGV[2])
local weekCap = tonumber(ARGV[3])
local dayTTL = tonumber(ARGV[4])
local weekTTL = tonumber(ARGV[5])
local d = redis.call('INCRBY', KEYS[1], n)
if d == n then redis.call('PEXPIRE', KEYS[1], dayTTL) end
local w = redis.call('INCRBY', KEYS[2], n)
if w == n then redis.call('PEXPIRE', KEYS[2], weekTTL) end
-- Refresh the global stream counter's TTL from the active data path. PEXPIRE on a missing key is a
-- no-op (returns 0, never creates the key), so a torn-down tunnel's counter is never resurrected.
redis.call('PEXPIRE', KEYS[3], ARGV[6])
local dayOK = 1
local weekOK = 1
if d > dayCap then dayOK = 0 end
if w > weekCap then weekOK = 0 end
return {dayOK, weekOK}
```

  `ClaimTraffic` passes `"conc:" + name` and `l.streamTTL.Milliseconds()`.
- [x] Action: modify `internal/server/server.go` — `limit.NewLimiter(rdb, bwRate, dayCap, weekCap, 3*cfg.LimitConnIdle)`.
- [x] Definition of Done: a stream older than the TTL whose tunnel still moves ≥1 chunk per idle
  window keeps its counter alive; all limiter constructor call sites (tests included) updated.

### [x] Task 6.3 — W-17: inflight issuance slots

- [x] Action: modify `internal/limit/issuance.go` — replace `IssuanceAllowed` (delete it and its uses)
  with the slot API. `iss:{name}` semantics unchanged (successes only):

```go
const (
	// issuanceSlotTTL is the per-slot deadline: a crashed node's order slot self-expires after this
	// and is purged lazily by the next acquire — no cleanup goroutine.
	issuanceSlotTTL = 30 * time.Second
	// issuanceHeartbeatEvery refreshes a live order's slot deadline (3 missed beats = expiry).
	issuanceHeartbeatEvery = 10 * time.Second
	// issuanceKeyTTLMargin pads the hash key's own TTL past the newest slot deadline.
	issuanceKeyTTLMargin = 30 * time.Second
)

func inflightKey(name string) string { return "iss_inflight:" + name }

// issuanceBeginScript purges expired slots, gates committed+inflight against the cap, and inserts
// this order's slot — all in ONE script so concurrent /issue calls cannot both pass.
// KEYS[1]=iss:{name} KEYS[2]=iss_inflight:{name} ARGV: maxN, nowMs, orderID, slotTTLms, keyTTLms.
var issuanceBeginScript = redis.NewScript(`
local now = tonumber(ARGV[2])
local fields = redis.call('HGETALL', KEYS[2])
local inflight = 0
for i = 1, #fields, 2 do
  if tonumber(fields[i+1]) < now then
    redis.call('HDEL', KEYS[2], fields[i])
  else
    inflight = inflight + 1
  end
end
local committed = tonumber(redis.call('GET', KEYS[1]) or '0')
if committed + inflight >= tonumber(ARGV[1]) then
  return 0
end
redis.call('HSET', KEYS[2], ARGV[3], now + tonumber(ARGV[4]))
redis.call('PEXPIRE', KEYS[2], ARGV[5])
return 1
`)

// issuanceHeartbeatScript refreshes ONLY a still-present slot (an expired-and-purged slot must not
// resurrect). KEYS[1]=iss_inflight:{name} ARGV: orderID, nowMs, slotTTLms, keyTTLms.
var issuanceHeartbeatScript = redis.NewScript(`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then
  redis.call('HSET', KEYS[1], ARGV[1], tonumber(ARGV[2]) + tonumber(ARGV[3]))
  redis.call('PEXPIRE', KEYS[1], ARGV[4])
end
return 1
`)
```

  Public API (`orderID` = `store`-independent 4-byte hex minted locally with `crypto/rand`):

```go
// IssuanceBegin reserves an in-flight issuance slot for name (committed successes + live slots < maxN).
func (l *Limiter) IssuanceBegin(ctx context.Context, name string, maxN int) (ok bool, orderID string, err error)
// IssuanceHeartbeatLoop refreshes the slot every issuanceHeartbeatEvery until ctx is done.
func (l *Limiter) IssuanceHeartbeatLoop(ctx context.Context, name, orderID string)
// IssuanceEnd frees the slot (called on success AND failure — failed orders never burn the window).
func (l *Limiter) IssuanceEnd(ctx context.Context, name, orderID string) error
```

  `IssuanceEnd` = `HDEL`. Slot deadlines use `l.now().UnixMilli()` passed from Go (matches the
  existing `claimBandwidthScript` convention; inter-node skew > 30 s costs at most one transient slot
  purge, bounded and NTP-assumed).
- [x] Action: modify `internal/enroll/enroll.go` `Issue` — replace the `IssuanceAllowed` block:

```go
ok, orderID, err := s.cfg.Limiter.IssuanceBegin(ctx, name, s.cfg.IssuePerWeek)
if err != nil {
	return Result{}, &Error{Reason: "internal", Retryable: true}
}
if !ok {
	s.rec.Reject("issuance-cap", name, ip)
	return Result{}, &Error{Reason: "issuance_cap", Retryable: true, RetryAfter: 7 * 24 * time.Hour}
}
defer func() {
	ectx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.cfg.Limiter.IssuanceEnd(ectx, name, orderID); err != nil {
		s.logger.Warn("issuance slot release failed (slot self-expires)", "tunnel", name, "err", err)
	}
}()
hbCtx, hbStop := context.WithCancel(ctx)
defer hbStop()
go s.cfg.Limiter.IssuanceHeartbeatLoop(hbCtx, name, orderID)
```

  `IssuanceRecord` stays post-success and unchanged. Add the `crypto/rand` and `encoding/hex`
  imports to `issuance.go` (the locally-minted order id).
- [x] Definition of Done: concurrent `/issue` calls for one name admit at most `maxN − committed`
  orders; a heartbeat-less slot frees in ≤ 30 s; a failed order leaves the weekly window unconsumed.

### [x] Task 6.4 — US6 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestClaimBandwidth_ClockStepBackNoInflation` | `now < last` grants without moving `last`; later refill unaffected | injected clock |
| `TestClaimTraffic_RefreshesConcTTLOnlyIfExists` | existing `conc:` key TTL refreshed; missing key NOT created | miniredis TTL inspect |
| `TestAcquireStream_UsesDerivedTTL` | TTL == configured streamTTL | |
| `TestIssuanceBegin_ConcurrentGate` | committed=2, cap=3 → exactly 1 of N concurrent Begins wins | |
| `TestIssuanceBegin_PurgesExpiredSlots` | expired slot purged; new order admitted | injected clock |
| `TestIssuanceHeartbeat_RefreshesOnlyPresent` | purged slot not resurrected by a late heartbeat | |
| `TestIssuanceEnd_FreesSlotOnFailure` | Begin→End (no Record) leaves the weekly window unconsumed | |
| `TestIssue_ConcurrentCallsRespectCap` (enroll) | two parallel Issues, cap 1 → one `issuance_cap` | stub issuer that blocks |

- [x] Definition of Done: all US6 tests present and passing at the Stage-4 gates.

---

## [x] US7 — Ban engine: silent-unban and silent-drop hazards (W-15, W-16, I-9, I-10)

Acceptance criteria:
- [x] A 4-in-6 CIDR with prefix < /96 is warn-and-skipped, never silently ignored.
- [x] A configured ban file/CSV that VANISHES at runtime keeps the previous snapshot (Error-logged, retried); first-deploy absence stays a benign skip.
- [x] A file changing mid-reload is detected and reloaded (bounded retry), so a torn read cannot hold for a full poll interval.
- [x] `ban.Reason`'s doc comment matches reality.

### [x] Task 7.1 — W-15: mapped-prefix guard

- [x] Action: modify `internal/ban/parse.go` — in the `case "cidr":` branch:

```go
if a := pfx.Addr(); a.Is4In6() {
	if pfx.Bits() < 96 {
		log.Warn("skipping 4-in-6 cidr with prefix < /96 (not mappable to IPv4)", "file", path, "line", lineNo, "value", value)
		continue
	}
	pfx = netip.PrefixFrom(a.Unmap(), pfx.Bits()-96)
}
```

- [x] Definition of Done: `::ffff:a.b.c.d/N` with N<96 is warned-and-skipped; N≥96 still maps.

### [x] Task 7.2 — W-16 + I-10: watcher vanish-guard and torn-read retry

- [x] Action: modify `internal/ban/engine.go` `Load` — gain a `required map[string]struct{}`
  parameter (paths that MUST exist because they were present at the last successful load): in the
  ban-file not-exist branch and the CSV not-exist branch, a REQUIRED path returns the error WITHOUT
  swapping (previous snapshot preserved even when the deletion lands mid-load); a non-required absent
  path keeps today's benign skip-and-warn (first deploy). Signature:
  `Load(files []string, csvPath string, required map[string]struct{}, log *slog.Logger) error`
  (a nil map = nothing required; update ALL existing call sites: `internal/server/server.go`, the
  watcher below, and the test callers in `internal/ban/engine_test.go` and
  `internal/ban/dbip_test.go` — pass `nil` where no requirement applies).
- [x] Action: modify `internal/ban/watch.go` `tick`:

```go
func (w *watcher) tick() {
	cur := w.fingerprint()
	if w.last != nil && sameStates(w.last, cur) {
		return
	}
	// A path that existed at the last successful load and has now VANISHED is an operator error or a
	// tooling race, NOT a request to unban: keep the previous snapshot and retry every tick (delete
	// the entry from config + restart to drop a file on purpose). Load's `required` set
	// enforces the same refusal even when the deletion lands between this check and the file reads.
	req := w.required()
	if p, vanished := w.vanished(cur); vanished {
		w.log.Error("ban input file disappeared; refusing reload and keeping the previous bans", "file", p)
		return
	}
	// Torn-read guard: a non-atomic external writer can be caught mid-truncate; reload until the
	// fingerprint is stable across the load (bounded).
	for attempt := 0; attempt < 3; attempt++ {
		if err := w.e.Load(w.files, w.csv, req, w.log); err != nil {
			w.log.Warn("ban reload error; keeping previous snapshot (will retry)", "err", err)
			return
		}
		after := w.fingerprint()
		if p, vanished := w.vanished(after); vanished {
			// The deletion landed mid-tick: Load already refused via `required`, but a stability pass
			// here must never commit the vanished state as the new baseline.
			w.log.Error("ban input file disappeared during reload; keeping the previous bans", "file", p)
			return
		}
		if sameStates(cur, after) {
			w.last = cur
			if w.onReload != nil {
				w.onReload(w.e)
			}
			return
		}
		cur = after
	}
	w.log.Warn("ban files kept changing during reload; retrying next tick")
}

// required returns the paths present at the last successful load (they MUST still exist).
func (w *watcher) required() map[string]struct{} {
	req := map[string]struct{}{}
	for p, st := range w.last {
		if st.exists {
			req[p] = struct{}{}
		}
	}
	return req
}

// vanished reports the first last-loaded path absent from states, if any.
func (w *watcher) vanished(states map[string]fileState) (string, bool) {
	for p, prev := range w.last {
		if prev.exists && !states[p].exists {
			return p, true
		}
	}
	return "", false
}
```

  (`initial()` passes `nil` as `required` — first-deploy absence remains skip-and-warn.)
- [x] Action: modify `internal/ban/entry.go` — rewrite the `Reason` doc comment to state reality:
  rejection metrics use the literal `"ban"` label at every site; `Source.Reason` feeds logs/detail
  only.
- [x] Definition of Done: a vanished previously-loaded input can never swap OR commit a reduced
  table — pre-check, in-Load `required` refusal, and post-load check all hold; the `Reason` comment
  no longer claims a metric wiring that does not exist.

### [x] Task 7.3 — US7 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestParseFile_4in6ShortPrefixSkippedWithWarn` | `::ffff:1.2.3.4/64` skipped + warned; `/120` still maps to `/24` | capture handler |
| `TestWatcher_VanishedFileKeepsSnapshot` | delete a loaded ban file → bans still enforced; Error logged; restore → reload | drive `tick()` directly |
| `TestWatcher_VanishedCSVKeepsSnapshot` | delete the loaded CSV → country bans still enforced | |
| `TestWatcher_FirstDeployAbsenceStillSkips` | never-existed file → benign skip (regression) | |
| `TestWatcher_TornReadRetries` | fingerprint changes between pre/post → reload retried within the tick | fake fingerprint sequence via file mutation |

- [x] Definition of Done: all US7 tests present and passing at the Stage-4 gates.

---

## [x] US8 — Store: async conn-log pipeline and S3 correctness (W-3, W-2-part, W-19, I-6, I-14)

Acceptance criteria:
- [x] No S3 conn-log write ever blocks an admission, splice, or teardown path: enqueue is O(1); 8 workers drain with exponential per-item retry; full queue drops-newest and increments `tunneld_connlog_dropped_total`.
- [x] Shutdown drains the queue (bounded) — `server-shutdown` end events land.
- [x] `isNotFound` no longer matches bucket-level/transport 404s.
- [x] A transient claim-verify GET error retries and then fails the enrollment — it NEVER draws a new name (no orphaned claims).
- [x] `EnsureLifecycles` merges with existing bucket rules instead of replacing the whole configuration.

### [x] Task 8.1 — async conn-log writer

- [x] Action: create `internal/store/async.go`:

```go
package store

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	asyncLogWorkers  = 8
	asyncLogQueue    = 5000
	asyncLogAttempts = 5
	asyncLogBackoff  = time.Second // doubles per retry: 1s, 2s, 4s, 8s
)

// AsyncConnLog decouples connection-log writes from the data/teardown paths: PutConnLog enqueues and
// returns immediately; a fixed worker pool drains with per-item exponential retry. A FULL queue drops
// the new event (never blocks a caller) and reports it via onDrop; Drain flushes the queue at
// shutdown (bounded by ctx) so end events are not lost.
type AsyncConnLog struct {
	inner  ConnLogStore
	onDrop func()
	logger *slog.Logger

	mu     sync.RWMutex
	closed bool
	ch     chan Event
	wg     sync.WaitGroup
}

func NewAsyncConnLog(inner ConnLogStore, onDrop func(), logger *slog.Logger) *AsyncConnLog {
	if onDrop == nil {
		onDrop = func() {}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	a := &AsyncConnLog{inner: inner, onDrop: onDrop, logger: logger, ch: make(chan Event, asyncLogQueue)}
	for range asyncLogWorkers {
		a.wg.Add(1)
		go a.worker()
	}
	return a
}

// PutConnLog enqueues (drop-newest on a full queue). Always returns nil: delivery is the workers' job.
func (a *AsyncConnLog) PutConnLog(_ context.Context, ev Event) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		a.onDrop()
		return nil
	}
	select {
	case a.ch <- ev:
	default:
		a.onDrop()
	}
	return nil
}

func (a *AsyncConnLog) worker() {
	defer a.wg.Done()
	for ev := range a.ch {
		backoff := asyncLogBackoff
		var err error
		for attempt := 0; attempt < asyncLogAttempts; attempt++ {
			if attempt > 0 {
				time.Sleep(backoff)
				backoff *= 2
			}
			if err = a.inner.PutConnLog(context.Background(), ev); err == nil {
				break
			}
		}
		if err != nil {
			a.onDrop()
			a.logger.Warn("conn-log write dropped after retries", "tunnel", ev.Tunnel, "event", ev.Event, "err", err)
		}
	}
}

// Drain stops intake and waits for the queue to flush or ctx to expire (server shutdown).
func (a *AsyncConnLog) Drain(ctx context.Context) {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.ch)
	}
	a.mu.Unlock()
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		a.logger.Warn("conn-log drain incomplete at shutdown deadline")
	}
}
```

  (Note: per-item retry sleeps run on worker goroutines only; the inner S3 client already carries a
  30 s per-request HTTP timeout, so one worker's item cycle is bounded.)
- [x] Action: modify `internal/metrics/metrics.go` — register a new counter
  `tunneld_connlog_dropped_total` ("connection-log events dropped: queue full or retries exhausted")
  and expose it (e.g. `func (m *Metrics) ConnLogDropped() prometheus.Counter`) for server wiring.
- [x] Action: modify `internal/server/server.go` — construct
  `asyncLogs := store.NewAsyncConnLog(st, m.ConnLogDropped().Inc, logger)`; pass it as
  `phoneconn.Config.Logs` and as the `edgeLogSink.st`. (`edgeLogSink` keeps converting; its field type
  is already the `ConnLogStore` shape.) Rejected-enrollment evidence stays synchronous (not a data-path
  write).
- [x] Definition of Done: no `PutConnLog` call on the S3Store remains outside the workers; the
  `teardownTimeout` path no longer bounds an S3 write (enqueue only).

### [x] Task 8.2 — W-19: strict not-found

- [x] Action: modify `internal/store/s3.go` `isNotFound` — remove the blanket
  `*awshttp.ResponseError` 404 branch:

```go
// isNotFound reports whether err is a definitive KEY-absence (NoSuchKey / HeadObject NotFound). A
// bucket-level or transport 404 (e.g. NoSuchBucket) is NOT key absence: callers map non-not-found
// errors to retryable failures, and a bucket outage must never read as name_unknown.
func isNotFound(err error) bool {
	if _, ok := errors.AsType[*types.NoSuchKey](err); ok {
		return true
	}
	if _, ok := errors.AsType[*types.NotFound](err); ok {
		return true
	}
	if ae, ok := errors.AsType[smithy.APIError](err); ok && (ae.ErrorCode() == "NoSuchKey" || ae.ErrorCode() == "NotFound") {
		return true
	}
	return false
}
```

  Drop the now-unused `net/http` import (keep `awshttp` only if still used by the client setup).
- [x] Definition of Done: a bucket-level 404 surfaces as a wrapped (retryable-class) error, never
  `ErrNotFound`; key absence still maps to `ErrNotFound`.

### [x] Task 8.3 — I-6: claim-verify never draws a new name on error

- [x] Action: modify `internal/enroll/enroll.go` `claimName` — replace the verify-GET error handling:

```go
got, gerr := s.cfg.Names.GetName(ctx, cand)
for r := 0; r < 2 && gerr != nil && !errors.Is(gerr, store.ErrNotFound); r++ {
	s.sleep(time.Second)
	got, gerr = s.cfg.Names.GetName(ctx, cand)
}
if errors.Is(gerr, store.ErrNotFound) {
	continue // our PUT definitively did not land — this candidate is clean to abandon
}
if gerr != nil {
	// Persistent verify failure: fail the enrollment (retryable) rather than drawing a new name —
	// if the PUT landed, moving on would orphan the claim forever.
	return "", "", fmt.Errorf("enroll: claim verify: %w", gerr)
}
if got.ClaimNonce == nonce {
	return cand, nonce, nil
}
// Lost the race — new name.
```

  Add the `fmt` import to `enroll.go`.
- [x] Definition of Done: a persistent verify error consumes exactly one candidate and fails
  retryably; a definitive NotFound still draws a new candidate.

### [x] Task 8.4 — I-14: lifecycle merge, not replace

- [x] Action: modify `internal/store/s3.go` `EnsureLifecycles` — read-merge-put by rule ID:

```go
// EnsureLifecycles upserts tunneld's two expiration rules by ID, PRESERVING any operator-added rules
// on the bucket (a blanket replace would silently delete them at every boot).
func (s *S3Store) EnsureLifecycles(ctx context.Context, connLogDays, rejectedDays int) error {
	ours := []types.LifecycleRule{ /* the two existing rules, unchanged */ }
	var merged []types.LifecycleRule
	cur, err := s.cli.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &s.bucket})
	switch {
	case err == nil:
		for _, r := range cur.Rules {
			if r.ID == nil || (*r.ID != "tunnel-logs-expire" && *r.ID != "rejected-enroll-expire") {
				merged = append(merged, r)
			}
		}
	case isNoLifecycle(err):
		// no configuration yet — start from empty
	default:
		return fmt.Errorf("store: read lifecycles: %w", err)
	}
	merged = append(merged, ours...)
	_, err = s.cli.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: &s.bucket, LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: merged},
	})
	if err != nil {
		return fmt.Errorf("store: ensure lifecycles: %w", err)
	}
	return nil
}

// isNoLifecycle matches the absent-lifecycle-configuration error.
func isNoLifecycle(err error) bool {
	ae, ok := errors.AsType[smithy.APIError](err)
	return ok && ae.ErrorCode() == "NoSuchLifecycleConfiguration"
}
```

  The `NoSuchLifecycleConfiguration` code MUST be verified against the real backend in the
  integration tier (MinIO) — the integration test below is the verification.
- [x] Definition of Done: operator-added rules survive startup; the two tunneld rules land; a second
  run is idempotent.

### [x] Task 8.5 — US8 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestAsyncConnLog_EnqueueNonBlocking` | Put returns immediately with a stalled inner store | inner blocks on channel |
| `TestAsyncConnLog_FullQueueDropsNewest` | queue at cap → onDrop fired, no block | |
| `TestAsyncConnLog_RetriesThenDrops` | inner fails N times → retried; permanent failure → onDrop + warn | short injected backoff via small const or inner latch |
| `TestAsyncConnLog_DrainFlushes` | queued events all written before Drain returns | |
| `TestIsNotFound_BucketErrorsNotMatched` | `NoSuchBucket`-shaped APIError → false; `NoSuchKey` → true | constructed smithy errors |
| `TestClaimName_VerifyErrorFailsWithoutNewName` | persistent verify error → error return, ONE candidate consumed | counting fake NameStore |
| `TestClaimName_VerifyNotFoundDrawsNewName` | verify NotFound → next candidate (regression) | |
| `TestEnsureLifecycles_MergePreservesForeignRules` (integration) | pre-existing operator rule survives; our two rules land; second run idempotent | MinIO testcontainer |

- [x] Definition of Done: all US8 tests present and passing at the Stage-4 gates.

---

## [x] US9 — Server assembly: construct-then-bind, atomic persist, ordered drain (W-1, W-2, W-4, I-2, I-7, I-8)

Acceptance criteria:
- [x] `:443` and `:9443` are bound only after ALL construction (reserved-cert issuance included) completes; nothing is ever bound-but-unserved.
- [x] Shutdown: close listeners → close phones → drain HTTP → join public handlers → drain the conn-log queue → final admin flush + caplog flush → deregister.
- [x] The reserved-cert cache persists atomically (single-file bundle + rename); a legacy triple-file cache still loads.
- [x] Construction error paths close any already-bound listener.
- [x] An admin flush error re-accumulates the delta; pending caplog summaries flush at shutdown.

### [x] Task 9.1 — W-1: bind last

- [x] Action: modify `internal/server/server.go` `Run` — move BOTH `net.Listen` calls (raw + mesh) to
  AFTER `newReservedCerts` and all other construction, immediately before the errgroup block. The edge
  is constructed from a resolved static address instead of the live listener:

```go
edgeAddr, err := net.ResolveTCPAddr("tcp", cfg.Listen)
if err != nil {
	return fmt.Errorf("resolve %s: %w", cfg.Listen, err)
}
ed := edge.New(edge.Config{ /* unchanged */ }, rdb, banIP, banTunnel, rec,
	reg, phoneMgr, meshClient, lim, &edgeLogSink{...}, edgeAddr)
// ... reserved certs, TLS servers, internal server constructed here ...
rawLn, err := net.Listen("tcp", cfg.Listen)
if err != nil {
	return fmt.Errorf("listen %s: %w", cfg.Listen, err)
}
meshLn, err := net.Listen("tcp", cfg.MeshListen)
if err != nil {
	_ = rawLn.Close() // never leak a bound listener on a construction error
	return fmt.Errorf("mesh listen %s: %w", cfg.MeshListen, err)
}
```

  The `http2.ConfigureServer` calls (fallible) run BEFORE the binds. Update the `newReservedCerts`
  doc comment ("NEVER blocks startup") to state the new truth: it runs BEFORE any listener binds, so a
  cold-start issuance delays readiness but never leaves a bound-unserved socket.
- [x] Definition of Done: between process start and the first `Accept`, no socket is bound while
  unserved; the integration suite's 120 s readiness allowance still passes.

### [x] Task 9.2 — W-4: atomic reserved-cert cache

- [x] Action: modify `internal/server/reserved.go` — persist ONE atomic bundle; load prefers the
  bundle, falls back to the legacy triple (upgrade path):

```go
// certBundle is the single-file cache: one atomic rename replaces cert+key+meta together, so a crash
// mid-persist can never mix a new key with an old cert.
type certBundle struct {
	CertPEM string          `json:"cert_pem"`
	KeyPEM  string          `json:"key_pem"`
	Info    store.CertInfo  `json:"info"`
}

func (rc *reservedCerts) persist(host string, certPEM, keyPEM []byte, info store.CertInfo) {
	dir := rc.hostDir(host)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		rc.logger.Warn("reserved-host cert dir create failed", "host", host, "err", err)
		return
	}
	raw, _ := json.Marshal(certBundle{CertPEM: string(certPEM), KeyPEM: string(keyPEM), Info: info})
	tmp := filepath.Join(dir, "bundle.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		rc.logger.Warn("reserved-host cert persist failed", "host", host, "err", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, "bundle.json")); err != nil {
		rc.logger.Warn("reserved-host cert persist rename failed", "host", host, "err", err)
	}
}
```

  `loadCached` reads `bundle.json` first (parse → `tls.X509KeyPair` → NotAfter fallback as today);
  when absent, it falls back to the existing `cert.pem`/`key.pem`/`meta.json` reads (legacy caches
  from before this change keep working; the next persist writes the bundle).
- [x] Definition of Done: kill-between-any-two-syscalls leaves either the old complete bundle or the
  new complete bundle.

### [x] Task 9.3 — I-7/I-8: flush integrity + ordered drain

- [x] Action: modify `internal/metrics/recorder.go`:
  - `flush` re-accumulates failed deltas:

```go
for name, e := range drained {
	if e.bytesIn != 0 {
		if err := p.admin.Incr(ctx, name, "bytes_in", e.bytesIn); err != nil {
			p.accum(name, func(a *aggEntry) { a.bytesIn += e.bytesIn }) // retried next flush
			p.log.Warn("admin counter flush failed (delta re-queued)", "tunnel", name, "field", "bytes_in", "err", err)
		}
	}
	// bytes_out identically
}
```

  - `RunFlusher`'s `ctx.Done()` case returns WITHOUT flushing (the final flush moves to the ordered
    drain below): `case <-ctx.Done(): return ctx.Err()`.
  - New methods (note `FinalFlush` owns the shutdown bound, keeping the existing
    `flushShutdownTimeout` const in use — no orphaned constant):

```go
// FinalFlush drains the accumulated deltas once, bounded by flushShutdownTimeout (called from the
// ordered server drain AFTER every producer has stopped).
func (p *PromRecorder) FinalFlush() {
	ctx, cancel := context.WithTimeout(context.Background(), flushShutdownTimeout)
	defer cancel()
	p.flush(ctx)
}

// FlushCapLog emits any pending cap-hit summaries (shutdown).
func (p *PromRecorder) FlushCapLog() { p.caplog.Flush() }
```
- [x] Action: modify `internal/server/server.go` — the shutdown sequence becomes:

```go
sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
defer cancel()
_ = rawLn.Close()
phoneMgr.CloseAll(store.CloseServerShutdown)
_ = enrollSrv.Shutdown(sctx)
_ = controlSrv.Shutdown(sctx)
_ = meshSrv.Shutdown(sctx)
_ = internalSrv.Shutdown(sctx)
ed.Wait(sctx) // every public handler (splice + end-event enqueue + slot release) has returned
werr := g.Wait()
asyncLogs.Drain(sctx) // queued conn-log events (incl. server-shutdown end events) land
rec.FinalFlush()  // after ALL producers stopped — no late deltas lost (self-bounded)
rec.FlushCapLog() // pending cap-hit summaries
if err := reg.DeregisterNode(sctx, nodeID); err != nil {
	logger.Warn("node deregister failed (expires by TTL)", "err", err)
}
```

- [x] Definition of Done: a drain with live public conns writes their `server-shutdown` end events
  before `Run` returns (integration-verified below).

### [x] Task 9.4 — US9 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestReservedCerts_PersistAtomicBundle` | bundle written via rename; tmp never left on success | temp dir |
| `TestReservedCerts_LoadLegacyTriple` | pre-existing cert.pem/key.pem/meta.json still loads | |
| `TestReservedCerts_CorruptBundleTreatedAbsent` | truncated bundle.json → load reports absent (no crash) | |
| `TestPromRecorder_FlushErrorRequeuesDelta` | failed Incr → delta present in next flush | failing fake admin |
| `TestRunFlusher_NoFlushOnCancel` | ctx cancel → no flush call (FinalFlush owns it) | |
| `TestPromRecorder_FlushCapLogEmitsPending` | pending multi-hit summary emitted by `FlushCapLog` | capture slog handler |
| `TestIntegration_DrainWritesShutdownEndEvents` (integration) | live public conn at drain → `close_reason=server-shutdown` end event lands in MinIO | real `server.Run` |
| `TestIntegration_MeshListenFailureClosesRawListener` (integration) | mesh port pre-occupied → `Run` errors AND `cfg.Listen` is immediately rebindable (rawLn closed) | I-2 |
| `TestIntegration_StartupBindsAfterConstruction` (integration) | all three ACME directory URLs point at an in-process accept-and-hang listener; a `:443` dial probe 500 ms after `Run` starts MUST fail with connection-refused (construction still in flight, nothing bound); then cancel the ctx and require `Run` to return | race-free: the assertion window is the deliberately-hung construction, not the readiness edge |

- [x] Definition of Done: all US9 tests present and passing at the Stage-4 gates.

---

## [x] US10 — Deployment, scripts, CI supply chain (C-3, W-21, W-24, W-22, I-16)

Acceptance criteria:
- [x] `/acme` is an operator-owned bind mount — ACME accounts + reserved certs actually persist across restarts under `DEPLOY_UID`.
- [x] The manual ban file has a host-side, documented write path (bind mount), hot-reloaded.
- [x] Fetch scripts: bounded curl, collision-free temp names, temp cleanup on failure; atomic `mv` preserved.
- [x] Dependabot actually runs (gomod + github-actions + docker).
- [x] Release image description no longer says "HTTP tunnel server".

### [x] Task 10.1 — C-3 + W-21: compose mounts

- [x] Action: modify `deploy/docker-compose.yml`:
  - `acme:/acme` → `./acme:/acme` (bind mount, operator-owned like `./logs`); remove `acme: {}` from
    the `volumes:` section.
  - Add `./banfiles:/banfiles-manual:ro` to the tunneld service (the named `banfiles` volume stays for
    fetcher-produced files); comment: manual bans are edited on the HOST in `deploy/banfiles/bans.txt`
    and hot-reload within `--ban-poll`.
- [x] Action: modify `deploy/tunneld.env.example` —
  `TUNNELD_BAN_FILE=/banfiles-manual/bans.txt,/banfiles/droplist.bans`.
- [x] Action: modify `README.md` quickstart — the deploy setup step creates the operator dirs
  (`mkdir -p deploy/ca deploy/attest deploy/logs deploy/acme deploy/banfiles` — adjust to the existing
  quickstart wording) and the Ban/geo section documents: "revoke by editing `deploy/banfiles/bans.txt`
  on the host (hot-reloaded within `--ban-poll`)".
- [x] Definition of Done: `make compose-config` passes; a fresh `docker compose up` persists
  `./acme/**` across restarts; editing the host `bans.txt` bans live.

### [x] Task 10.2 — W-24: fetch scripts

- [x] Action: modify `deploy/scripts/fetch-droplist.sh` — PID-suffixed temps, curl timeout, cleanup:

```sh
feed="$OUT_DIR/droplist.feed.tmp.$$"
tmp="$OUT_DIR/droplist.bans.tmp.$$"
trap 'rm -f "$feed" "$tmp"' EXIT

curl -fsS --max-time 300 "$DROP_URL" -o "$feed"
jq -r 'select(.cidr) | "cidr \(.cidr)"' "$feed" > "$tmp"
mv "$tmp" "$OUT_DIR/droplist.bans"
```

  (drop the trailing `rm -f "$feed"` — the trap owns cleanup).
- [x] Action: modify `deploy/scripts/fetch-dbip.sh` — same pattern:
  `gz="$OUT_DIR/dbip-country-lite.csv.gz.tmp.$$"`, `csvtmp="$OUT_DIR/dbip-country-lite.csv.tmp.$$"`,
  `trap 'rm -f "$gz" "$csvtmp"' EXIT`, `curl -fsS --max-time 300 "$url" -o "$gz"`; drop the explicit
  `rm -f "$gz"`.
- [x] Definition of Done: two overlapping runs cannot interleave into one temp file; a hung download
  aborts at 300 s leaving the previous output untouched; `make test-scripts` updated + passing;
  `shellcheck` clean.

### [x] Task 10.3 — W-22 + I-16

- [x] Action: modify `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

- [x] Action: modify `.goreleaser.yaml` — both image-description labels →
  `org.opencontainers.image.description=Self-hosted end-to-end-encrypted tunnel server (tunneld)`.
- [x] Definition of Done: dependabot config lists the three ecosystems; both goreleaser labels
  updated; no other release field touched.

### [x] Task 10.4 — US10 script tests

| Test | Verifies |
|---|---|
| script-test: droplist temp uniqueness | two concurrent invocations produce a valid final file (distinct `$$` temps) |
| script-test: failure leaves no temp litter | forced curl failure → no `*.tmp.*` remains, previous output intact |

- [x] Definition of Done: `make test-scripts` covers and passes both cases; `shellcheck` clean.

---

## [x] US11 — Go client library hygiene (W-23, I-15)

Acceptance criteria:
- [x] No code path leaks a pooled TLS connection: `Enroll`/`FetchIssueNonce` close their transports; `Client` has `Close`.
- [x] The `CERT_PUSH` ghost is gone from the docs comments.

### [x] Task 11.1 — transport lifecycle

- [x] Action: modify `client/enroll.go` — hold the transports and close them:

```go
// in Enroll:
tr := serverTLSTransport(dialAddr, enrollHost, caPool)
defer tr.CloseIdleConnections()
hc := &http.Client{Transport: tr}
...
mtlsTr := newMTLSTransport(dialAddr, controlHost, caPool, func() *tls.Certificate { return &bootCert })
defer mtlsTr.CloseIdleConnections()
mtls := &http.Client{Transport: mtlsTr}

// in FetchIssueNonce:
tr := serverTLSTransport(dialAddr, enrollHost, caPool)
defer tr.CloseIdleConnections()
hc := &http.Client{Transport: tr}
```

- [x] Action: modify `client/control.go` — `Client` keeps `tr *http2.Transport` (set in `New`
  alongside `c.hc`); add:

```go
// Close releases the control client's pooled TLS connections. Call it once Run has returned.
func (c *Client) Close() {
	c.tr.CloseIdleConnections()
}
```

  and fix the `Client` doc comment: identity is rotated via the mTLS `POST /issue` exchange
  (`Renew`), not a `CERT_PUSH` frame (audit I-15).
- [x] Action: modify `e2e`/client tests to `defer`/`t.Cleanup` the new `Close` where a `Client` is
  constructed.
- [x] Definition of Done: no `http.Client` in `client/` outlives its use with pooled conns
  unreleased.

### [x] Task 11.2 — US11 tests

| Test | Verifies | Notes |
|---|---|---|
| `TestEnroll_ClosesTransports` (integration tier where a server exists, else unit via httptest) | after Enroll returns, no live TCP conns remain from its transports | count via `httptest` server ConnState or netstat-free check on close notifications |
| `TestClient_CloseReleasesControlTransport` | Close → transport idle conns closed | |

- [x] Definition of Done: both US11 tests present and passing at the Stage-4 gates.

---

## [x] US12 — e2e test hygiene (I-18, I-19, I-20)

Acceptance criteria:
- [x] The eviction test leaks no conns inside its own assertion loop.
- [x] The quota test asserts a QUOTA signal, not just "some error".
- [x] The adb gate enforces exactly one device.

### [x] Task 12.1 — fixes

- [x] Action: modify `e2e/e2e_test.go` `startReplica` — record the internal address:
  `e2eInfra` gains `internal map[string]string` (edge addr → internal addr), populated before return.
- [x] Action: modify `e2e/e2e_test.go` `TestE2E_Quota` — after the cut assertion, add a metrics
  assertion:

```go
if !waitBool(10*time.Second, func() bool {
	return metricCounterPositive(inf.internal[edge], "tunneld_quota_exhausted_total")
}) {
	t.Fatal("the cut must be attributed to the quota (tunneld_quota_exhausted_total)")
}
```

  with helper `metricCounterPositive(internalAddr, family string) bool` — GET `/metrics`, scan for a
  line starting with the family name whose value parses > 0.
- [x] Action: modify `e2e/e2e_test.go` `TestE2E_Eviction` — close the conn on a failed echo inside the
  retry closure:

```go
if !waitBool(15*time.Second, func() bool {
	c3, err = dialTunnelTLS(edge, fqdn, inf.pebble.IssuingRoots)
	if err != nil {
		return false
	}
	if eerr := echoOn(c3); eerr != nil {
		_ = c3.Close() // a leaked conn would join the eviction population under test
		err = eerr
		return false
	}
	return true
}) {
```

- [x] Action: modify `e2e/device_attestation_test.go` `adbHasDevice` — count and require exactly one:

```go
count := 0
for _, line := range strings.Split(string(out), "\n")[1:] {
	if strings.HasSuffix(strings.TrimSpace(line), "\tdevice") {
		count++
	}
}
return count == 1
```

- [x] Definition of Done: `make test-e2e` passes with the strengthened assertions.

---

## [x] US13 — Documentation sync

The canonical docs must reflect every behavioral change above (agent.md: docs ALWAYS current).

Acceptance criteria:
- [x] No statement in `docs/ARCHITECTURE.md`, `docs/PROJECT.md`, `docs/PROTOCOL.md`, `README.md`, or `.claude/rules/project.md` contradicts the implemented behavior.
- [x] The §9 shutdown Mermaid chart shows the new drain sequence and validates via `mmdc`.

### [x] Task 13.1 — doc updates

- [x] Action: modify `docs/ARCHITECTURE.md`:
  - §8 (observability/caplog): `no-route` is metric + debug-only (attacker-controlled key — no dedup
    state); all other cap hits stay deduped. Conn-log writes are ASYNC: bounded queue (5000) + 8
    workers + exponential retry + `tunneld_connlog_dropped_total`; drop-newest on overflow.
  - §9 (shutdown): update the text AND the Mermaid chart to the new sequence (close listeners → close
    phones → drain HTTP → join public handlers → drain conn-log queue → final admin/caplog flush →
    deregister).
  - Startup: note that ALL construction (reserved-cert issuance included) precedes the listener binds.
  - §5 (Valkey state): the route-record line "`route:{name}` → owner/fp/connID/epoch" loses the
    epoch (`startedAt` is removed) → "owner/fp/connID"; grep ARCHITECTURE.md and PROJECT.md for any
    other `startedAt`/`epoch`/conn-id-format statement and update it.
  - §7 (revocation): ban reload evicts the phone control conn AND kills active public splices
    (`ban-evict`); conn/stream ids are 8-hex random with bind-time re-roll; ban-input files that
    vanish at runtime are refused (previous snapshot kept).
  - Close reasons: add `cert-expired`.
- [x] Action: modify `docs/PROJECT.md` — cap-hit dedup paragraph (no-route exception), revocation
  paragraph (active-splice kill), state paragraph if it mentions the conn-id epoch.
- [x] Action: modify `docs/PROTOCOL.md` — only if it mentions the conn-id time prefix / route
  `startedAt` (grep `startedAt`, `epoch`, `conn id`); the wire frames are untouched by this plan.
- [x] Action: modify `.claude/rules/project.md` — Hard Project Invariants: revocation bullet (all
  three points + live-splice eviction), observability bullet (async conn-log + no-route exception);
  Bandwidth bullet unchanged; note `conc:{name}` TTL = 3× idle refreshed on the accounting script.
- [x] Definition of Done: no doc statement contradicts the implemented behavior; the modified
  shutdown Mermaid chart validates (checked again in US14).

---

## [x] US14 — Ground-up verification (FINAL)

Every prior story is re-verified from the ground up before the change is considered done.

Acceptance criteria:
- [x] Every action of US1–US13 is implemented exactly as specified or has a recorded `## Deviations` entry.
- [x] All quality gates pass with ZERO errors/warnings on the final code.
- [x] All touched Mermaid charts validate.
- [x] No file outside this plan's scope is modified.

### [x] Task 14.1 — plan-vs-tree verification

- [x] Action: re-read this ENTIRE plan from disk; verify EVERY action of every user story is
  implemented in the working tree exactly as specified (or has a recorded entry in `## Deviations`);
  verify every checkbox above is checked.
- [x] Definition of Done: zero unimplemented actions; zero unchecked boxes; every deviation recorded.

### [x] Task 14.2 — ground-up code re-read

- [x] Action: re-read the changed code from the ground up: every file touched by US1–US13, checking
  for TODOs, placeholders, dead code, unused imports/params left by the refactors (e.g. `startedAt`
  remnants, `IssuanceAllowed` remnants, `binary` import in event.go, `strconv`/`time` in
  route_e2e.go).
- [x] Definition of Done: zero TODOs/placeholders/dead code/unused imports in the touched files.

### [x] Task 14.3 — quality gates

- [x] Action: run each gate `tee`'d to `/tmp/p4-<gate>.log`:
  - [x] `make lint 2>&1 | tee /tmp/p4-lint.log | tail -5` — ZERO issues (all three tag runs + shellcheck + compose-config)
  - [x] `make vet 2>&1 | tee /tmp/p4-vet.log | tail -5`
  - [x] `make govulncheck 2>&1 | tee /tmp/p4-govulncheck.log | tail -5`
  - [x] `make build 2>&1 | tee /tmp/p4-build.log | tail -5`
  - [x] `make test-unit 2>&1 | tee /tmp/p4-test-unit.log | tail -10`
  - [x] `make test-integration 2>&1 | tee /tmp/p4-test-integration.log | tail -10`
  - [x] `make test-e2e 2>&1 | tee /tmp/p4-test-e2e.log | tail -10`
  - [x] `make test-scripts 2>&1 | tee /tmp/p4-test-scripts.log | tail -10`
- [x] Definition of Done: every gate exits 0 with zero errors/warnings; failures fixed and the FULL
  affected gates re-run until clean.

### [x] Task 14.4 — Mermaid validation

- [x] Action: the shutdown chart in `docs/ARCHITECTURE.md` is modified by US13 — validate ALL Mermaid
  blocks in every touched Markdown file per `development_pipeline.md` §9 (`make mermaid-check` covers
  README + docs).
- [x] Definition of Done: `make mermaid-check` exits 0.

### [x] Task 14.5 — scope boundary

- [x] Action: verify `git status` shows NO modified file outside this plan's actions; `docs/plans/`
  untouched except this file's checkmarks/Deviations.
- [x] Definition of Done: the diff against `main` contains only in-scope files.

## Deviations

(recorded during implementation per agent.md §2)

- **Task 4.4 (`internal/edge/edge.go`) — `Edge.lim` field type.** The plan's Task 4.7 mandates a
  `TestHandleTunnel_FailOpenNeverReleases` test driven by a "fake limiter", which the concrete
  `*limit.Limiter` field cannot accept. Introduced a consumer-side interface `StreamLimiter`
  (the five data-plane limiting methods the edge uses: `AcquireStream`, `ReleaseStream`, `ClaimTraffic`,
  `ClaimBandwidth`, `TrafficExhausted`) and changed `Edge.lim` + the `New(...)` parameter from
  `*limit.Limiter` to `StreamLimiter`. `*limit.Limiter` still satisfies it (compile-asserted), so the
  `server.Run` wiring and every existing test are unchanged; the change only enables the required fake
  and follows go.md's "accept interfaces" rule (mirrors the Task 2.3 `dialBackOpener` deviation).

- **Task 2.3 (`internal/server/serve.go`) — `bridgeAdapter.mgr` field type.** The plan's code block kept
  `mgr *phoneconn.Manager` (a concrete type). Task 2.4 mandates a `TestBridgeAdapter_TranslatesDuplicateStreamID`
  test driven by a "fake manager", which a concrete `*phoneconn.Manager` field cannot accept. Introduced a
  narrow consumer-side interface `dialBackOpener` (single method `OpenStream(ctx, name, streamID) (phoneconn.DataStream, error)`)
  and changed the field to `mgr dialBackOpener`. `*phoneconn.Manager` still satisfies it, so the
  `server.Run` wiring (`&bridgeAdapter{mgr: phoneMgr, ...}`) is unchanged; the change only enables the
  required unit test and follows go.md's "accept interfaces" rule.

- **Task 7.2 (`internal/ban/watch.go`) — added a per-path stat seam on `watcher`.** The plan's Task 7.3
  mandates `TestWatcher_TornReadRetries` ("fake fingerprint sequence via file mutation"). A torn read —
  the file changing between the pre-load and post-load fingerprints WITHIN one tick — cannot be produced
  deterministically single-threaded (`Load` never mutates the file) and a concurrent mutator would be
  non-deterministic (forbidden by the no-flake rule). Added an unexported `stat func(string) fileState`
  field (nil → `os.Stat`) and routed the pre-existing `fingerprint()` through a new `statePath` helper.
  Production behaviour is unchanged (nil seam = os.Stat); the plan's `tick`/`initial` code is verbatim
  (still calling `w.fingerprint()`). Follows go.md's testability rule.

- **Task 7.2 (`internal/ban/engine_test.go`) — updated the pre-existing
  `TestWatcher_DetectsDeletionAndEqualMtime` deletion assertion.** That test predated US7 and asserted a
  deleted previously-loaded file RELOADS (the silent-unban behaviour US7 fixes). Its deletion sub-block
  now asserts the vanish-guard: the reload is refused and the previous bans stay enforced. The
  equal/older-mtime detection portion is unchanged. Required to keep the suite green under the mandated
  behaviour change.

- **Task 9.4 (`internal/server/integration_test.go`) — shared integration-harness refactor for the US9
  tests.** To implement the three mandated US9 integration tests without duplicating the large (and
  fragile-to-validate) `ServeCmd` literal, the config construction in `startIntegrationServer` was
  extracted verbatim into a new `itServeConfig(...)` builder (the ACME directory URLs, mesh address and
  DNS resolvers are parameterized) that both `startIntegrationServer` and the new tests call — the values
  are unchanged, so `TestIntegration_EnrollConnectRoundtrip` reuses the identical known-good config. Also
  added an idempotent (`sync.Once`) `drain()` on `itEnv` so a shutdown-exercising test can trigger and
  await Run's return while the pre-existing `t.Cleanup` remains safe (the second `drain` is a no-op
  returning the recorded result). No production code changed.

- **Task 9.4 (`internal/server/drain_startup_integration_test.go`) — hang-listener `release()` fast-fail.** The
  plan specifies an "accept-and-hang" ACME listener for `TestIntegration_StartupBindsAfterConstruction`.
  lego's directory fetch at client construction does not honor context cancellation (verified: lego
  v4.35.2 `lego/client_config.go` `createDefaultHTTPClient` builds an `http.Client` with fixed
  `TLSHandshakeTimeout`/`Timeout`, no ctx seam), so a bare hang would leave `Run` blocked for up to
  ~30 s per CA after cancel. `release()` therefore closes the held connections and the listener, which
  makes the in-flight obtain fail immediately (EOF) and every subsequent CA attempt fail fast
  (connection-refused), bounding the post-cancel return. The +500 ms connection-refused assertion — the
  actual W-1 proof — is unchanged.

- **Task 10.4 (`deploy/scripts/scripts_test.sh`) — updated the existing "droplist converts feed to cidr
  lines" cleanup assertion.** Task 10.2 renamed the work temps to `*.tmp.$$`, so that test's literal
  `[ ! -f "$t/droplist.feed.tmp" ]` check now referenced a filename the script never creates (vacuously
  true). Added a `no_tmp_litter <dir>` helper (a POSIX glob loop over `*.tmp.*`) and routed the success
  test — plus the two new Task 10.4 tests — through it, so the success path still verifies no temp litter
  remains. No production behaviour changed.

- **Task 11.2 (`client/harness_test.go` + `client/enroll_test.go`) — added a connection-counting
  listener seam to the client test harness.** `TestClient_CloseReleasesControlTransport` must observe that
  `Client.Close` releases the control transport's pooled TCP connection, and `TestEnroll_ClosesTransports`
  the same for `Enroll`'s two transports. Introduced test-only `countingListener`/`countingConn` wrappers
  (in `enroll_test.go`) and wrapped the harness listener in `startTestServer` (exposed via a new
  `testServer.conns` field). This follows the plan Note's "netstat-free check on close notifications"
  option and mirrors the US2/US4 test-seam deviations. The `Enroll` server harness uses the repo's
  existing `net.Listen` + `http2` + mTLS pattern (as `startTestServer` already does) rather than
  `httptest.Server`, because `Enroll` needs both HTTP/1.1 (Phase 1) and mTLS HTTP/2 (Phase 2) with a
  CA-signed server cert and `VerifyClientCertIfGiven` — which `httptest`'s fixed cert/ClientAuth cannot
  provide. No production code changed.

- **Task 13.1 (`docs/ARCHITECTURE.md`) — conn/stream-id fact placed in §5, not §7.** The plan's §7
  bullet asks for the "conn/stream ids are 8-hex random with bind-time re-roll" fact, but ARCHITECTURE §7
  is the *Ban engine* section — an id-format sentence there is incoherent. The fact was documented in §5
  (Valkey state), the section that already describes the route record and `connID`, keeping the doc
  coherent; §7 carries the two ban-eviction/vanish-guard facts as specified. Additionally, the
  `conc:{name}` TTL = 3 × `--limit-conn-idle` (per-chunk `PEXPIRE` refresh) note was added to
  ARCHITECTURE §5 as well as `.claude/rules/project.md` — the plan required it only for `project.md`, but
  ARCHITECTURE §5 already enumerates the concurrency counter, so the added detail keeps that description
  accurate and non-contradicting. No behavioral claim changed beyond the implemented behavior.

- **Task 13.1 (`docs/PROTOCOL.md`) — no change required.** A grep for `startedAt` / `epoch` / conn-id
  time-prefix / char-count found no format claim to update; §1's revocation line ("live eviction on ban
  reload") already matches the implemented behavior and the wire frames are untouched by Plan 4. The
  action is checked as verified-no-change.
- **Task 11.1 (`client/control.go`) — `Run` gains a deterministic cancellation watcher.** The Stage-4
  unit gate exposed that `Run` relied solely on the transport's ctx propagation to unblock the control
  frame read after cancel, which is not deterministic under load (`TestClient_CloseReleasesControlTransport`
  hung in the full suite, passed in isolation). A ctx-scoped watcher now closes the response body and
  the request pipe on cancel, guaranteeing `Run` returns promptly; the watcher itself exits via a
  deferred channel close, so no goroutine leaks. Test fixes: the reserved-cert legacy tests now assert
  the `bundle.json` persist artifact, and the Close test honors `Close`'s contract (waits for `Run` to
  return, then polls `Close` while the transport quiesces).
