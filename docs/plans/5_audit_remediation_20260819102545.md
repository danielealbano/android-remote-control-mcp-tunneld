<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 5 — Audit Remediation (full-codebase deep audit)

Remediation of the findings from the ground-up adversarial audit of 2026-08-19. Every finding is fixed
(agent.md: "known/documented limitations are bugs"). Two findings are EXCLUDED **by explicit user
decision** and MUST NOT be implemented:

- **D-005** (fetcher on `alpine:3` + `apk add` at start): user decision — keep it simple, no image
  build, no version pin, no guard line. The fetcher `deploy/fetcher/command.sh` and its compose service
  stay EXACTLY as they are. Do NOT touch them for this reason.
- **D-006** (ntfy alert delivery path to the phone): user decision — deferred; will be designed later
  as a deliberate authenticated public exposure. Do NOT change ntfy exposure or the alert-path docs.

All other findings are in scope. Finding IDs from the audit are cross-referenced in each task title
**for traceability in this plan only** — per agent.md, NO plan/finding ID may appear in code comments,
commit messages, or any non-plan artifact; code comments cite `docs/` only.

## Global implementation rules (apply to EVERY task)

- Reconcile every code block below with the CURRENT source before editing (the audit line numbers are a
  snapshot). Preserve existing bugfixes; record any necessary divergence in `## Deviations`.
- NO new `//nolint`, NO suppression. Fix root causes.
- Tests are MANDATORY for every behavioral change (go.md). Unit tier stays fast (miniredis/httptest/fake
  clock); integration/e2e stay testcontainers-backed and build-tagged.
- Quality gates run ONCE at the end (US14), never per task: `make build`, `make lint`, `make vet`,
  `make govulncheck`, `make test-unit`, `make test-integration`, `make test-e2e`, `make test-scripts`,
  `make compose-config`, `make tidy`.
- No Mermaid chart is added or modified by this plan, so NO `mmdc` validation step is required (§9).

---

## [x] US1 — Attestation: require TEE-asserted verified-boot evidence (CRITICAL C1)

**Why:** `ParseKeyDescription` walks `softwareEnforced` and `teeEnforced` into one struct with no
presence tracking, so `rootOfTrust` from the software-enforced list is honored, and when it is absent
from BOTH lists `VerifiedBootState` defaults to `0` == `BootVerified` and `DeviceLocked` to `false` —
predicate point (5) can pass with zero TEE evidence. The project supports TEE/StrongBox devices ONLY.

**Acceptance criteria:**
- [x] `rootOfTrust` (tag 704) is parsed ONLY from `teeEnforced`; a copy in `softwareEnforced` is ignored.
- [x] Absence of `rootOfTrust` in `teeEnforced` makes `Verify` FAIL (`ErrBootState`), never default to pass.
- [x] `securityLevel`, `verifiedBootState`, `deviceLocked` continue to be enforced exactly as the
      seven-point predicate documents (no other predicate point weakened).
- [x] Negative tests cover "no rootOfTrust anywhere" and "rootOfTrust only in softwareEnforced".

### [x] Task 1.1 — Track `rootOfTrust` presence and source-list in the parser

- [x] **modify** `internal/attest/keydescription.go`
  - [x] Add a presence flag to the decoded struct:
    ```go
    // KeyDescription is the decoded, semantically-meaningful subset the verifier needs.
    type KeyDescription struct {
        // ... existing fields ...
        DeviceLocked      bool
        VerifiedBootState int
        HasRootOfTrust    bool // rootOfTrust was present in the TEE-enforced authorization list
        // ... existing fields ...
    }
    ```
  - [x] Make `walkAuthList` accept whether it is walking the TEE-enforced list and record `rootOfTrust`
        ONLY from it:
    ```go
    // ParseKeyDescription ... rootOfTrust is read ONLY from teeEnforced (a copy in softwareEnforced is
    // ignored); its ABSENCE from teeEnforced is a hard failure at Verify (see verify.go point 5).
    func ParseKeyDescription(leaf *x509.Certificate) (*KeyDescription, error) {
        // ... unchanged decode of kd ...
        if err := walkAuthList(kd.SoftwareEnforced.Bytes, out, false); err != nil {
            return nil, fmt.Errorf("attest: softwareEnforced: %w", err)
        }
        if err := walkAuthList(kd.TeeEnforced.Bytes, out, true); err != nil {
            return nil, fmt.Errorf("attest: teeEnforced: %w", err)
        }
        return out, nil
    }

    func walkAuthList(raw []byte, out *KeyDescription, tee bool) error {
        // ... unchanged loop, EXCEPT the rootOfTrust case: ...
        case tagRootOfTrust:
            if !tee {
                continue // rootOfTrust is only trustworthy from the TEE-enforced list
            }
            var rot rootOfTrust
            if _, err := asn1.Unmarshal(rv.Bytes, &rot); err != nil {
                return fmt.Errorf("rootOfTrust: %w", err)
            }
            out.HasRootOfTrust = true
            out.DeviceLocked = rot.DeviceLocked
            out.VerifiedBootState = int(rot.VerifiedBootState)
        // ...
    }
    ```
  - [x] Update the package/parse doc comments to state the TEE-only placement and the fail-on-absent
        contract accurately (agent.md: comments must not misstate the code).

**Definition of Done:**
- [x] `continue` in the non-TEE `rootOfTrust` branch; `attestationApplicationId` and the patch/version
      tags are still read from whichever list carries them (unchanged).
- [x] Comments describe the actual behavior.

### [x] Task 1.2 — Fail `Verify` when TEE `rootOfTrust` is absent

- [x] **modify** `internal/attest/verify.go` — predicate point (5), before the `VerifiedBootState` check:
  ```go
  // (5) verifiedBootState == Verified — but ONLY when rootOfTrust was TEE-asserted. A chain whose
  // teeEnforced list carries no rootOfTrust proves nothing about boot state and is rejected (the
  // defaults would otherwise read as Verified+unlocked). See docs/PROTOCOL.md §2.
  if !kd.HasRootOfTrust {
      return Result{}, ErrBootState
  }
  if kd.VerifiedBootState != BootVerified {
      return Result{}, ErrBootState
  }
  ```

**Definition of Done:**
- [x] Points (1)-(4), (6), (7) unchanged; only the boot-state gate gains the presence precondition.

### [x] Task 1.3 — Tests

- [x] **modify** `internal/attest/keydescription_test.go` and/or `internal/attest/verify_test.go`
- [x] **modify** `internal/attest/fixtures_test.go` if a fixture builder is needed to place `rootOfTrust`
      in a chosen list / omit it.

| Test | Verifies | Setup notes |
|---|---|---|
| `TestParseKeyDescription_RootOfTrustOnlyFromTEE` | a `rootOfTrust` present only in `softwareEnforced` yields `HasRootOfTrust==false` and zero boot fields | fixture with RoT in software list only |
| `TestVerify_NoRootOfTrustAnywhere_Fails` | `Verify` returns `ErrBootState` when neither list has `rootOfTrust` | otherwise-valid Google-rooted chain |
| `TestVerify_RootOfTrustOnlyInSoftware_Fails` | `Verify` returns `ErrBootState` even when the software-list RoT says `Verified`+`locked` | RoT `{Verified, deviceLocked:true}` in software list only |
| `TestVerify_TEERootOfTrust_StillPasses` | a valid TEE-asserted `rootOfTrust{Verified,locked}` still passes point (5)/(6) | regression guard on the happy path |

**Definition of Done:**
- [x] All four tests are present and green; the fixture builder can place/omit `rootOfTrust` per list.

---

## [x] US2 — Secret & durable-state protection (CRITICAL C2 + W-A7, W-D2, W-D3, W-D7)

**Why:** operator key material and abuse data can be committed by a bulk `git add` or destroyed by a
silent ACME account-key overwrite.

**Acceptance criteria:**
- [x] `git status` on a configured deployment checkout shows NO secret/operator file as untracked-stageable.
- [x] An existing-but-unparseable (or existing-but-unreadable) ACME account key aborts startup; it is
      NEVER overwritten.
- [x] The Docker build context excludes all secret/generated material.
- [x] The ntfy bridge token lives in a gitignored file with a committed example.

### [x] Task 2.1 — Ignore operator secrets & data (C2, W-D2, W-D7)

- [x] **modify** `.gitignore` — extend the "Operator secrets & generated material" block:
  ```gitignore
  /deploy/ca/
  /deploy/.env
  /deploy/tunneld.env
  /deploy/logs/
  /deploy/acme/
  /deploy/banfiles/
  /deploy/attest/
  /deploy/ntfy-alertmanager/config.scfg
  ```

**Definition of Done:**
- [x] `git check-ignore` matches each of `/deploy/acme/`, `/deploy/banfiles/`, `/deploy/attest/`,
      `/deploy/ntfy-alertmanager/config.scfg`.

### [x] Task 2.2 — ntfy bridge token: example + gitignored real file (W-D7)

- [x] **create** `deploy/ntfy-alertmanager/config.scfg.example` — copy of the current committed
      `config.scfg` content, token line kept as the placeholder `access-token changeme-write-token`.
- [x] **modify** (git) — `git rm --cached deploy/ntfy-alertmanager/config.scfg` so the real file becomes
      untracked (now gitignored via Task 2.1); the working copy stays for local use. The compose mount
      (`./ntfy-alertmanager/config.scfg:...`) is ALREADY correct and MUST NOT change.
- [x] **modify** `README.md` step 7 — instruct copying `config.scfg.example` → `config.scfg` before
      setting the token (the copy step, alongside the existing "set the token" instruction).
  - Context: the bridge reads scfg only (no env-var config — verified upstream); this mirrors the
    existing `.env`/`.env.example`, `tunneld.env`/`tunneld.env.example` convention.

**Definition of Done:**
- [x] `config.scfg.example` is tracked with the placeholder token; `config.scfg` is untracked; the compose
      mount path is unchanged.

### [x] Task 2.3 — Add `.dockerignore` (W-D3)

- [x] **create** `.dockerignore` at repo root:
  ```dockerignore
  .git
  bin/
  dist/
  deploy/ca
  deploy/.env
  deploy/tunneld.env
  deploy/acme
  deploy/logs
  deploy/banfiles
  deploy/attest
  deploy/ntfy-alertmanager/config.scfg
  ```
  Context: the compose build uses `context: ..` + `COPY . .`; without this, secrets enter builder layers
  and the BuildKit cache.

**Definition of Done:**
- [x] `.dockerignore` exists at the repo root and excludes every secret/generated path above; the compose
      build (US14 gate) still succeeds.

### [x] Task 2.4 — ACME account key: fail hard, never overwrite (W-A7)

- [x] **modify** `internal/server/acmewire.go` — `loadAccountKey` returns an error. An existing file that
      cannot be READ (non-not-exist error) or PARSED (SEC1 or PKCS#8) aborts startup — it is NEVER
      overwritten. A genuinely ABSENT file still generates + best-effort-persists a new key (a
      generation/mkdir/write failure stays non-fatal with a Warn + nil/ephemeral key, exactly as today —
      that path is unchanged):
  ```go
  // loadAccountKey loads the per-CA ACME account key under dir/<caid>.key. If the file EXISTS but cannot
  // be read or parsed as an EC private key (SEC1 or PKCS#8), startup FAILS — an unreadable existing key
  // means something is wrong (corruption / wrong file / bad permissions), and silently minting a new
  // account would abandon the existing (EAB-bound) account. A new key is generated ONLY when the file is
  // absent; generation/persistence there is best-effort (a failure costs a re-registered account).
  func loadAccountKey(dir, caID string, logger *slog.Logger) (crypto.PrivateKey, error) {
      path := filepath.Join(dir, caID+".key")
      raw, err := os.ReadFile(path)
      switch {
      case err == nil:
          key, perr := parseECPrivateKey(raw)
          if perr != nil {
              return nil, fmt.Errorf("acme account key %s exists but is unparseable (refusing to overwrite): %w", path, perr)
          }
          return key, nil
      case errors.Is(err, fs.ErrNotExist):
          // absent → generate + best-effort persist below
      default:
          return nil, fmt.Errorf("acme account key %s exists but could not be read (refusing to continue): %w", path, err)
      }
      key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
      if gerr != nil {
          // Absent-path generation failure stays NON-fatal (unchanged from today): a nil key makes
          // NewLegoClient self-generate an ephemeral account key. Only an existing-but-unreadable/
          // unparseable key is fatal (above).
          logger.Warn("acme account key generation failed; lego will use an ephemeral key", "ca", caID, "err", gerr)
          return nil, nil
      }
      if merr := os.MkdirAll(dir, 0o700); merr != nil {
          logger.Warn("acme account dir create failed; using an ephemeral account key", "ca", caID, "err", merr)
          return key, nil
      }
      if der, merr := x509.MarshalECPrivateKey(key); merr == nil {
          if werr := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); werr != nil {
              logger.Warn("acme account key persist failed; using an ephemeral account key", "ca", caID, "err", werr)
          }
      }
      return key, nil
  }

  // parseECPrivateKey accepts an EC key in SEC1 or PKCS#8 encoding.
  func parseECPrivateKey(pemRaw []byte) (*ecdsa.PrivateKey, error) {
      block, _ := pem.Decode(pemRaw)
      if block == nil {
          return nil, errors.New("no PEM block")
      }
      if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
          return k, nil
      }
      k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
      if err != nil {
          return nil, err
      }
      ec, ok := k.(*ecdsa.PrivateKey)
      if !ok {
          return nil, fmt.Errorf("account key is %T, want *ecdsa.PrivateKey", k)
      }
      return ec, nil
  }
  ```
- [x] **modify** `internal/server/acmewire.go` — `buildACMEChain` calls `loadAccountKey` (3×, for the
      three `AccountKey:` fields); change `buildACMEChain` to return `(acmeChain, error)` and propagate any
      `loadAccountKey` error (a corrupt/unreadable existing key aborts construction).
- [x] **modify** `internal/server/server.go` — the `chain := buildACMEChain(cfg, lim, rec, logger)` call
      site (~line 114): handle the new error return and `return` it fatally from `Run` (BEFORE any listener
      binds, consistent with the other fatal construction steps).
- [x] **modify** `internal/server/acmewire.go` imports as needed (`errors`, `io/fs`, `fmt`).

**Definition of Done:**
- [x] Existing-unreadable/unparseable key → construction error → `Run` returns before any listener binds;
      the file bytes are unchanged. Absent key → generated; absent-path generation/persist failure stays a
      Warn (non-fatal). `buildACMEChain` returns `(acmeChain, error)` and its call site propagates it.

### [x] Task 2.5 — Tests

- [x] **create/modify** the `acmewire` test file in `internal/server/`.

| Test | Verifies | Setup notes |
|---|---|---|
| `TestLoadAccountKey_AbsentGenerates` | absent file → new key generated and persisted (0600) | temp dir |
| `TestLoadAccountKey_SEC1RoundTrip` | a persisted SEC1 key reloads to the same key | write via first call |
| `TestLoadAccountKey_PKCS8Accepted` | a PKCS#8-encoded EC key loads without error and is NOT overwritten | write a PKCS#8 EC key, assert file bytes unchanged after load |
| `TestLoadAccountKey_UnparseableIsFatal` | a garbage/non-EC file returns an error and the file is left untouched | write junk, assert error + file bytes unchanged |
| `TestBuildACMEChain_CorruptAccountKeyAborts` | a corrupt existing `<caid>.key` makes `buildACMEChain`/`server.Run` return an error at startup (propagation seam, not just `loadAccountKey`) | seed a junk key file in the account dir |

**Definition of Done:**
- [x] All five tests present and green; the corrupt-key propagation test asserts the error reaches
      `buildACMEChain`/`Run`.

---

## [x] US3 — Ban-engine enforcement integrity (W-A1, W-S1, W-I5, W-D4, W-E1)

**Why:** several paths can silently unban (double-load vanish gap, torn live snapshot, vanished signer
allowlist, empty droplist) or let a banned tunnel keep a live splice through the dial-back window. Bans
are the ONLY revocation.

**Acceptance criteria:**
- [x] Ban inputs are loaded exactly ONCE at startup; a file that vanishes after that first load is
      refused on the next poll (never silently unbans).
- [x] A torn (mid-write) ban file is NEVER swapped into the live engine; the previous snapshot serves
      until a stable read commits.
- [x] A vanished signer-digest allowlist is refused (kept) and logged, mirroring the ban engine.
- [x] `fetch-droplist.sh` refuses to install an empty result.
- [x] A ban reload evicts a splice that is still in its dial-back window; a dial-back never completes on
      an already-closed phone connection.

### [x] Task 3.1 — Build-then-verify-then-swap in the ban engine (W-S1)

- [x] **modify** `internal/ban/engine.go` — split `Load` so the atomic swap is separable from the build
      (unexported, same package as the watcher):
  ```go
  // build parses+expands into a fresh snapshot WITHOUT swapping it in, so a caller can verify input
  // stability before committing. Same absent/vanished/corrupt/zero-row semantics as Load. See
  // docs/ARCHITECTURE.md §7.
  func (e *Engine) build(files []string, csvPath string, required map[string]struct{}, log *slog.Logger) (*snapshot, error) {
      // ... the CURRENT body of Load, EXCEPT the final e.current.Store(...) ...
      return &snapshot{table: table, names: names, fps: fps}, nil
  }

  // commit atomically swaps a built snapshot in.
  func (e *Engine) commit(s *snapshot) { e.current.Store(s) }

  // Load builds and immediately commits (used at first load, where no live traffic needs protecting from
  // a torn read; the watcher uses build+commit to gate on read stability).
  func (e *Engine) Load(files []string, csvPath string, required map[string]struct{}, log *slog.Logger) error {
      s, err := e.build(files, csvPath, required, log)
      if err != nil {
          return err
      }
      e.commit(s)
      return nil
  }
  ```

**Definition of Done:**
- [x] `build` returns a snapshot without swapping; `Load` = `build`+`commit`; the absent/vanished/corrupt/
      zero-row semantics are byte-for-byte the current ones (only the swap point moved).

### [x] Task 3.2 — Single-load watcher; commit only on a stable read (W-A1, W-S1)

- [x] **modify** `internal/ban/watch.go` — restructure `Watch` into constructor + synchronous initial
      load + poll loop, and gate the poll's swap on read stability:
  ```go
  // NewWatcher builds the poll state. Initial() runs the ONE startup load synchronously (before the
  // caller binds listeners); Run() then polls and, on any change, reloads with build-verify-commit.
  func NewWatcher(e *Engine, files []string, csvPath string, poll time.Duration, log *slog.Logger) *watcher {
      return &watcher{e: e, files: files, csv: csvPath, poll: poll, log: log}
  }

  // Initial performs the single startup load and records the baseline fingerprint (and thus the
  // `required` set). It does NOT fire onReload (no live connections exist yet). A load error leaves the
  // baseline unrecorded so Run() retries on the first tick (best-effort, matching the previous behavior).
  func (w *watcher) Initial() {
      cur := w.fingerprint()
      if err := w.e.Load(w.files, w.csv, nil, w.log); err != nil {
          w.log.Warn("initial ban load error; engine stays at empty snapshot until a successful load", "err", err)
          return
      }
      w.last = cur
  }

  // Run polls until ctx is done; onReload fires on each SUCCESSFUL reload after a detected change.
  func (w *watcher) Run(ctx context.Context, onReload func(*Engine)) {
      ticker := time.NewTicker(w.poll)
      defer ticker.Stop()
      for {
          select {
          case <-ctx.Done():
              return
          case <-ticker.C:
              w.tick(onReload)
          }
      }
  }
  ```
  - [x] `tick` gains build-verify-commit (replaces the in-loop `w.e.Load`):
    ```go
    func (w *watcher) tick(onReload func(*Engine)) {
        cur := w.fingerprint()
        if w.last != nil && sameStates(w.last, cur) {
            return
        }
        req := w.required()
        if p, vanished := w.vanished(cur); vanished {
            w.log.Error("ban input file disappeared; refusing reload and keeping the previous bans", "file", p)
            return
        }
        for attempt := 0; attempt < 3; attempt++ {
            snap, err := w.e.build(w.files, w.csv, req, w.log)
            if err != nil {
                w.log.Warn("ban reload error; keeping previous snapshot (will retry)", "err", err)
                return
            }
            after := w.fingerprint()
            if p, vanished := w.vanished(after); vanished {
                w.log.Error("ban input file disappeared during reload; keeping the previous bans", "file", p)
                return
            }
            if sameStates(cur, after) {
                w.e.commit(snap) // swap in ONLY a snapshot built from a stable read
                w.last = cur
                if onReload != nil {
                    onReload(w.e)
                }
                return
            }
            cur = after
        }
        w.log.Warn("ban files kept changing during reload; retrying next tick")
    }
    ```
  - [x] Add `poll time.Duration` to the `watcher` struct.
  - [x] Keep the top-level `Watch(...)` function ONLY if an existing test still calls it (as a thin
        `NewWatcher(...).Initial()/.Run(...)` wrapper); otherwise update the callers and remove it — do
        NOT leave a dead wrapper.
- [x] **modify** `internal/server/server.go`:
  - Remove the direct pre-load block (current lines 70-73). Construct the watcher and run its Initial()
    load synchronously right there (before all other construction / listener binds):
    ```go
    banEng := ban.NewEngine()
    banWatcher := ban.NewWatcher(banEng, cfg.BanFile, cfg.DBIPCountryLiteCSV, cfg.BanPoll, logger)
    banWatcher.Initial() // single startup load; records the baseline so a later vanish is refused
    banIP := func(ip netip.Addr) bool { _, b := banEng.Match(ip); return b }
    banTunnel := func(name, fp string) bool { _, b := banEng.MatchTunnel(name, fp); return b }
    ```
  - Replace the ban-watcher goroutine (current lines 252-258) with:
    ```go
    g.Go(func() error {
        banWatcher.Run(gctx, func(e *ban.Engine) {
            phoneMgr.EvictBanned(func(name, fp string) bool { _, b := e.MatchTunnel(name, fp); return b })
            ed.EvictBannedStreams(func(name, fp string) bool { _, b := e.MatchTunnel(name, fp); return b })
        })
        return nil
    })
    ```

**Definition of Done:**
- [x] Exactly ONE startup load (no `banEng.Load` + separate watcher initial load); the poll's swap happens
      only after a stable re-read; the eviction hooks (`EvictBanned` + `EvictBannedStreams`) stay wired on
      `onReload`.

### [x] Task 3.3 — Signer allowlist: refuse & log a vanished file (W-I5)

- [x] **modify** `internal/attest/signers.go` — in `Watch`, when `os.Stat` fails for the configured
      allowlist file, log an Error (rate-limited to once per state transition, mirroring the ban engine's
      vanished-file handling) and keep the previous set instead of silently continuing. Fix the two
      comments to describe the ACTUAL retry semantics (a failed reload does not advance mtime, so it
      retries every tick).
  - Context: match `internal/ban`'s "vanished required file is refused, Error-logged, retried" pattern;
    do NOT clear the allowlist on a stat failure.

**Definition of Done:**
- [x] A vanished allowlist file logs Error and keeps the previous digest set; the two comments match the
      code.

### [x] Task 3.4 — Droplist fetcher: refuse an empty result (W-D4)

- [x] **modify** `deploy/scripts/fetch-droplist.sh` — after the `jq` extraction, before the `mv`:
  ```sh
  jq -r 'select(.cidr) | "cidr \(.cidr)"' "$feed" > "$tmp"

  # Refuse to install an EMPTY result: an upstream schema change (or an HTTP-200 empty body) would
  # otherwise atomically replace the live droplist with zero entries — a silent mass-unban. Mirrors the
  # DB-IP zero-row refusal in internal/ban/dbip.go.
  [ -s "$tmp" ] || { echo "fetch-droplist: empty droplist output, keeping previous file" >&2; exit 1; }

  mv "$tmp" "$OUT_DIR/droplist.bans"
  ```
- [x] **modify** `deploy/scripts/scripts_test.sh` — add a case asserting an empty jq result leaves the
      previous `droplist.bans` untouched and exits non-zero (stub `curl`/`jq` to yield empty output).
  - NOTE: this is D-004's fix on `fetch-droplist.sh`; it is NOT the excluded fetcher service (D-005).

**Definition of Done:**
- [x] An empty extraction leaves the previous `droplist.bans` intact and exits non-zero; `scripts_test.sh`
      covers it and passes `shellcheck`.

### [x] Task 3.5 — Close the ban-evict dial-back escape window (W-E1)

- [x] **modify** `internal/edge/bridge.go` — in `handleTunnel`, AFTER `trackStream(as)` and BEFORE
      starting the splice, re-check the tunnel ban on the (possibly re-bound) fingerprint and abort if
      now banned. The early return MUST close the client socket like every sibling rejection path:
  ```go
  e.trackStream(as)
  defer e.untrackStream(as)

  // A ban reload during the dial-back wait sweeps only tracked streams; re-check now that we are tracked
  // so a tunnel banned in that window does not get one live splice (docs/PROJECT.md §2 — a reload stops
  // live traffic, not only new admissions).
  if e.banTun != nil && e.banTun(name, fp) {
      e.rec.Reject("ban", name, peerAddr(client))
      _ = client.Close()
      return
  }
  ```
  (The deferred `untrackStream`, `closeFar`, and slot release also run on this early return.)
- [x] **modify** `internal/phoneconn/manager.go` — `deliverStream` MUST refuse delivery on an
      already-closed connection so a dial-back does not complete after `EvictBanned`/`CloseAll` closed it:
  ```go
  func (m *Manager) deliverStream(name, streamID string, ds DataStream) bool {
      c, ok := m.lookup(name)
      if !ok {
          return false
      }
      c.mu.Lock()
      defer c.mu.Unlock()
      if c.closed {
          return false // the conn was evicted/closed; the /data handler answers 404 and closes the stream
      }
      w, ok := c.pending[streamID]
      if !ok {
          return false
      }
      delete(c.pending, streamID)
      w <- ds
      return true
  }
  ```
  (`conn.close` already sets `c.closed` under `c.mu`, so this read is race-free — reconcile and keep it so.)

**Definition of Done:**
- [x] The post-`trackStream` ban re-check closes the client and returns; `deliverStream` returns false on a
      closed conn; no new data race is introduced (`-race` clean).

### [x] Task 3.6 — Tests

- [x] **create** `internal/ban/watch_test.go` (no watcher test file exists today).
- [x] **modify** `internal/ban/engine_test.go` — the existing watcher tests live here and construct
      `&watcher{… onReload: …}` literals and call `w.initial()` / `w.tick()` (no arg); MIGRATE all of
      them to the new `NewWatcher`/`Initial`/`Run`/`tick(onReload)` API, preserving every BEHAVIORAL
      assertion (vanish refusal, older-mtime detection, failed-load retry, CSV-vanish refusal,
      absent-file benign skip, torn-read stability) while RE-BASELINING every reload-count expectation to
      the new contract. None currently call the top-level `Watch(...)`.
  - [x] The new contract is: `Initial()` fires ZERO reload callbacks (no live connections yet); each
        change-driven `tick` fires ONE. This shifts EVERY reload-count assertion DOWN by one across the
        SEVEN affected tests — the four that assert the initial load fires `onReload` once
        (`TestWatchFiresOnReloadOnMtimeChange`, `TestWatcher_DetectsDeletionAndEqualMtime`,
        `TestWatchLoadErrorKeepsPreviousSnapshot`, `TestWatcher_FirstDeployAbsenceStillSkips`) AND the
        three whose reload-count expectations embed the initial +1 (`TestWatcher_RetriesAfterFailedLoad`,
        `TestWatcher_VanishedFileKeepsSnapshot`, `TestWatcher_VanishedCSVKeepsSnapshot`). Only
        `TestWatcher_TornReadRetries` (which seeds `w.last` directly) is unaffected. (This is a
        deliberate contract change, mirroring Task 11.4's `TestReadPumpPongStampsLiveness` flip.)
- [x] **modify** `internal/attest/signers_test.go`, `internal/edge/*_test.go`,
      `internal/phoneconn/manager_test.go`.

| Test | Verifies | Setup notes |
|---|---|---|
| `TestWatcher_SingleLoadNoDoubleExpansion` | `Initial()` loads once; `Run` does not re-load until a change | count loads via a stat/parse seam |
| `TestWatcher_VanishAfterInitialIsRefused` | a file present at `Initial()` then removed is refused on tick (bans kept, Error logged) | scripted `stat` seam |
| `TestWatcher_TornReadNeverGoesLive` | a mid-write (changing fingerprint) file never swaps into the live engine; previous bans still match through the unstable window | scripted `stat` returning changing sizes |
| `TestWatcher_InitialDoesNotFireOnReload` | `Initial()` fires no reload callback; the first change-driven `tick` does | onReload counter |
| `TestSigners_VanishedFileKeepsSet` | a deleted allowlist file keeps the previous digests and logs Error | temp file + delete |
| `TestBridge_BanDuringDialbackEvictsStream` | a tunnel banned after admission but before splice is refused post-`trackStream`, and the client socket is closed | fake router + ban seam |
| `TestDeliverStream_RefusesClosedConn` | `deliverStream` returns false once `conn.close` ran | close then deliver |

**Definition of Done:**
- [x] `internal/ban` compiles and passes with the migrated tests (including the updated initial-`onReload`
      expectations); all rows above are green.

---

## [x] US4 — Startup fail-fast & listener correctness (W-A2, W-A8, A-002, A-003, A-004, A-005, A-009)

**Why:** the internal listener binds lazily and a bind failure is swallowed; several address/name
misconfigurations surface late; a failed mesh-cert mint leaves an accepting-but-dead `:9443`; the
errgroup's fail-fast is unused because serve errors are swallowed.

**Acceptance criteria:**
- [x] `--listen`, `--mesh-listen`, `--internal-listen` are validated at startup and their binds are all
      fatal at construction (before serving).
- [x] `--name-prefix` is lowercased everywhere and charset-validated; an uppercase/invalid prefix cannot
      silently `no-route` every tunnel.
- [x] `--enroll-host` == `--control-host` is rejected at startup.
- [x] A non-shutdown `Serve` error cancels the errgroup (process exits for the orchestrator to restart);
      `ErrServerClosed`/`net.ErrClosed` remain non-fatal.
- [x] The internal server drains gracefully (no hard `Close` racing `Shutdown`).
- [x] A failed initial mesh-cert mint is fatal; a failed rotation retries on a short backoff.

### [x] Task 4.1 — Validate listen addresses; lowercase+validate name prefix; reject host collision (W-A2, W-A8, A-009)

- [x] **modify** `internal/config/config.go` `Validate()`:
  - Add address parseability for the three listeners (accept `host:port` or `:port`):
    ```go
    for _, a := range []struct{ name, v string }{
        {"--listen", c.Listen}, {"--mesh-listen", c.MeshListen}, {"--internal-listen", c.InternalListen},
    } {
        if _, _, err := net.SplitHostPort(a.v); err != nil {
            return fmt.Errorf("%s must be host:port or :port, got %q: %w", a.name, a.v, err)
        }
    }
    ```
  - Reject an enroll/control host collision (case-insensitive; the hosts are lowercased in `server.Run`):
    ```go
    if strings.EqualFold(c.EnrollHost, c.ControlHost) {
        return fmt.Errorf("--enroll-host and --control-host must differ (SNI dispatch would hide the control plane), both %q", c.EnrollHost)
    }
    ```
  - Validate the name-prefix charset (DNS label chars, no leading `-`), case-insensitively since it is
    lowercased at runtime:
    ```go
    for _, r := range strings.ToLower(c.NamePrefix) {
        if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
            return fmt.Errorf("--name-prefix must be [a-z0-9-] only, got %q", c.NamePrefix)
        }
    }
    if strings.HasPrefix(c.NamePrefix, "-") {
        return fmt.Errorf("--name-prefix must not start with '-', got %q", c.NamePrefix)
    }
    ```
- [x] **modify** `internal/server/server.go` — lowercase the prefix alongside the hosts (after line 50):
  ```go
  cfg.NamePrefix = strings.ToLower(cfg.NamePrefix)
  ```

**Definition of Done:**
- [x] `Validate()` rejects a bad listen address, an enroll/control collision, and an out-of-charset prefix;
      `server.Run` lowercases `cfg.NamePrefix` so name generation AND `validNameFunc` both see lowercase.

### [x] Task 4.2 — Bind the internal listener at construction; propagate serve errors; graceful drain (W-A2, A-002, A-003, A-004)

- [x] **modify** `internal/server/server.go`:
  - Bind the internal listener alongside `rawLn`/`meshLn` (after the mesh bind, ~line 207), fatal on
    error, closing the already-bound listeners on failure:
    ```go
    internalLn, err := net.Listen("tcp", cfg.InternalListen)
    if err != nil {
        _ = rawLn.Close()
        _ = meshLn.Close()
        return fmt.Errorf("internal listen %s: %w", cfg.InternalListen, err)
    }
    ```
  - Serve the internal server through `serveTLS` on the pre-bound plain listener (it is plain HTTP — pass
    `internalLn` directly, no TLS wrapper), replacing the `serveInternal` goroutine:
    ```go
    g.Go(func() error { return serveTLS(gctx, internalSrv, internalLn, logger, "internal") })
    ```
- [x] **modify** `internal/server/serve.go`:
  - `serveTLS` returns the non-shutdown error so the errgroup cancels (A-003), keeping the shutdown
    sentinels non-fatal:
    ```go
    func serveTLS(ctx context.Context, srv *http.Server, ln net.Listener, logger *slog.Logger, which string) error {
        go func() { <-ctx.Done(); _ = ln.Close() }()
        err := srv.Serve(ln)
        if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
            logger.Warn("listener exited", "which", which, "err", err)
            return err
        }
        return nil
    }
    ```
  - Delete `serveInternal` (the hard `srv.Close()` watcher — A-004 — is gone; the drain's
    `internalSrv.Shutdown(sctx)` already bounds it, and the listener-close-on-ctx pattern above matches
    the other servers so the internal server now drains gracefully).
  - Update `serveTLS`'s doc comment (`serve.go:24-25`, currently "The listener is already a tls.Listener
    …") to reflect that `ln` is a `tls.Listener` for the TLS servers OR the plain internal listener
    (agent.md: comments must not misstate the code).

**Definition of Done:**
- [x] The internal listener binds at construction (fatal on failure); `serveInternal` is gone; `serveTLS`
      propagates non-shutdown errors and keeps `ErrServerClosed`/`net.ErrClosed` non-fatal; the shutdown
      order in `Run` still drains the internal server via `Shutdown`; `serveTLS`'s comment is accurate.

### [x] Task 4.3 — Mesh-cert mint: fatal initial, retried rotation (A-005)

- [x] **modify** `internal/server/schedulers.go` — make `mint` return an error, make the INITIAL mint
      fatal via `newMeshCertHolder`, and make a failed rotation retry on a short backoff. Add an
      injectable timer seam (`after`, default `time.After`) so the rotation-retry test needs no wall-clock
      wait:
  ```go
  // meshRotateRetry is the short backoff between a FAILED mesh-cert rotation and the next attempt (so a
  // transient CA-signing blip does not leave a dead :9443 until the next 2/3-TTL tick).
  const meshRotateRetry = 5 * time.Minute

  type meshCertHolder struct {
      nodeID string
      ttl    time.Duration
      logger *slog.Logger
      cur    atomic.Pointer[tls.Certificate]
      after  func(time.Duration) <-chan time.Time // seam: default time.After; overridden in tests
  }

  // newMeshCertHolder mints the first mesh cert; a failure is FATAL (the caller must not bind :9443 with
  // no servable cert, per docs/ARCHITECTURE.md §1).
  func newMeshCertHolder(caObj *ca.CA, nodeID string, ttl time.Duration, logger *slog.Logger) (*meshCertHolder, error) {
      h := &meshCertHolder{nodeID: nodeID, ttl: ttl, logger: logger, after: time.After}
      if err := h.mint(caObj); err != nil {
          return nil, fmt.Errorf("mesh cert initial mint: %w", err)
      }
      return h, nil
  }

  func (h *meshCertHolder) mint(caObj *ca.CA) error {
      certPEM, keyPEM, err := caObj.SignMesh(h.nodeID, h.ttl)
      if err != nil {
          return err
      }
      cert, err := tls.X509KeyPair(certPEM, keyPEM)
      if err != nil {
          return err
      }
      h.cur.Store(&cert)
      return nil
  }

  // rotateLoop re-mints at 2/3 TTL; a failed rotation retries after meshRotateRetry instead of waiting a
  // full interval.
  func (h *meshCertHolder) rotateLoop(ctx context.Context, caObj *ca.CA) {
      interval := h.ttl * 2 / 3
      if interval <= 0 {
          interval = time.Hour
      }
      d := interval
      for {
          select {
          case <-ctx.Done():
              return
          case <-h.after(d):
          }
          if err := h.mint(caObj); err != nil {
              h.logger.Warn("mesh cert rotation failed (retrying on backoff)", "err", err)
              d = meshRotateRetry
          } else {
              d = interval
          }
      }
  }
  ```
- [x] **modify** `internal/server/server.go` — `newMeshCertHolder` now returns an error (call site
      ~line 144): handle it and `return` it fatally from `Run` BEFORE `:9443` binds (consistent with the
      other fatal construction steps).
  - Context: mirror the fatal treatment `buildVerifier` gives a failed signer-allowlist load.

**Definition of Done:**
- [x] A failed initial mint aborts `Run` before `:9443` binds; a failed rotation waits `meshRotateRetry`
      (5m) then a successful one returns to the 2/3-TTL interval; the `after` seam lets the test drive
      rotations without wall-clock waits.

### [x] Task 4.4 — Tests

- [x] **modify** `internal/config/config_test.go`, `internal/server/serve_test.go` /
      `server_test.go` / `schedulers_test.go`.

| Test | Verifies | Setup notes |
|---|---|---|
| `TestValidate_ListenAddressesRejectGarbage` | non-`host:port` `--listen`/`--mesh-listen`/`--internal-listen` fail | table |
| `TestValidate_EnrollControlHostCollision` | equal enroll/control hosts fail (case-insensitive) | table |
| `TestValidate_NamePrefixCharset` | uppercase/`_`/leading-`-` prefixes fail; `ab-1` passes | table |
| `TestRun_InternalBindFailureIsFatal` | an unusable `--internal-listen` returns from `Run` (not a warn) | occupy the port first |
| `TestServeTLS_PropagatesNonShutdownError` | a serve error returns (cancels the group); `ErrServerClosed`/`net.ErrClosed` return nil | fake listener |
| `TestServeInternal_DrainsGracefully` | an in-flight request is drained by `Shutdown` at ctx-cancel, not hard-aborted | serve harness + in-flight request |
| `TestMeshCert_InitialMintFatal` | a failing initial mint aborts construction before bind | inject a signer that errors |
| `TestMeshCert_RotationRetriesOnBackoff` | a failed rotation requests `meshRotateRetry`, then a success returns to the 2/3-TTL interval | inject the `after` seam to capture requested durations + a signer that fails once |
| `TestRun_NamePrefixLowercased` (integration) | an uppercase `--name-prefix` yields lowercase generated/validated tunnel names (the runtime `server.Run` normalization, not just `Validate()`) | integration tier drives `server.Run`; enroll a tunnel, assert the name uses the lowercase prefix |

**Definition of Done:**
- [x] Every AC of US4 maps to a green test above (validation, fatal binds, serve-error propagation, graceful
      drain, mesh-mint fatal + rotation retry, runtime prefix lowercasing).

---

## [x] US5 — Eliminate silent failures & error swallowing (W-S2, W-A6, E-005, S-006, A-010, A-011)

**Why:** several error paths `continue`/discard with no signal, so real outages (Valkey, renewal,
heartbeat) are diagnosable only by their downstream symptom.

**Acceptance criteria:**
- [x] The issuance-slot heartbeat error is LOGGED (30s TTL kept — user decision; no timeout change).
- [x] The reserved-host `shouldRenew` error and a persistent phone `Heartbeat` error are logged with
      identifiers.
- [x] Every remaining intentional `_` discard in scope carries a go.md justification comment.
- [x] `reservedCerts.ensure` uses the injected clock in both branches.
- [x] `NewPromRecorder` no longer panics on a nil admin store, and its comment matches reality.

### [x] Task 5.1 — Log discarded errors (W-S2, W-A6, E-005)

- [x] **modify** `internal/limit/issuance.go` — `IssuanceHeartbeatLoop`: log the heartbeat error at Warn
      with `name` + `orderID`. KEEP the 30s TTL (**user decision:** a Valkey blip is a real problem; fail
      fast and let the client retry via the documented 503/`retry_after` path — NO TTL/timeout change):
  ```go
  if err := issuanceHeartbeatScript.Run(ctx, l.rdb, []string{inflightKey(name)},
      orderID, now, issuanceSlotTTL.Milliseconds(),
      (issuanceSlotTTL+issuanceKeyTTLMargin).Milliseconds()).Err(); err != nil {
      l.logger.Warn("issuance slot heartbeat failed (slot may expire; a concurrent order could then start)", "tunnel", name, "order", orderID, "err", err)
  }
  ```
  Reconcile: if `Limiter` has no logger field, add one (constructor/functional-option, per go.md DI); wire
  it in `server.Run`'s `limit.NewLimiter(...)`. No package global.
- [x] **modify** `internal/server/reserved.go` — `maybeRenew`: log the `shouldRenew` error, mirroring
      `renewalWatcher.tick`:
  ```go
  due, _, err := rc.shouldRenew(ctx, rh.currentInfo())
  if err != nil {
      rc.logger.Warn("reserved-host renewal check failed (will retry next scan)", "host", rh.host, "err", err)
      return
  }
  if !due {
      return
  }
  ```
- [x] **modify** `internal/phoneconn/manager.go` — the heartbeat loop (~lines 212-215): Warn-log a
      persistent `Heartbeat` error with tunnel + connID (dedup/rate-limit if per-tick volume is a concern)
      instead of a bare `continue`.

**Definition of Done:**
- [x] The three error paths log at Warn with identifiers; the 30s issuance-slot TTL is unchanged;
      `Limiter` receives its logger via DI (no package global).

### [x] Task 5.2 — Documented discards, injected clock & nil-guard (S-006, A-010, A-011)

- [x] **modify** `internal/admin/tunnels.go` — `atoi64` (~lines 89-92): add the one-line justification
      comment for the intentional `_` discard (absent hash field → 0), mirroring `store/rejected.go`.
- [x] **modify** `internal/server/reserved.go` — `ensure` (~lines 92/95): use `rc.now()` in BOTH the
      renew-margin and still-valid branches (`notAfter.Sub(rc.now()) > rc.renewMargin`).
- [x] **modify** `internal/metrics/recorder.go` — `NewPromRecorder`: nil-guard the `*admin.Store` (treat
      nil as a no-op admin sink in `flush`); fix the constructor comment (it currently claims "never
      carries nil collaborators" while accepting a nil store). No-op guard keeps the existing
      `deploy_test`/`e2e_test` nil callers valid without a panic if they ever flush.

**Definition of Done:**
- [x] `atoi64` carries the justification comment; `ensure` uses `rc.now()` in both branches;
      `NewPromRecorder` no-ops the admin sink on nil and its comment is accurate.

### [x] Task 5.3 — Tests

| Test | Verifies | Setup notes |
|---|---|---|
| `TestIssuanceHeartbeat_LogsOnError` | a failing heartbeat script logs Warn with identifiers | inject an rdb that errors; capture slog |
| `TestReservedMaybeRenew_LogsShouldRenewError` | a `shouldRenew` error logs and returns | fake `shouldRenewFunc` returning err |
| `TestHeartbeatLoop_LogsPersistentError` | a persistent phone `Heartbeat` error logs Warn with tunnel + connID (not a bare `continue`) | inject a failing `Router.Heartbeat` seam; capture slog |
| `TestReservedEnsure_UsesInjectedClock` | the expiring-cache branch compares against `rc.now()` | fake clock past the margin |
| `TestPromRecorder_NilAdminStoreFlushNoPanic` | `flush` with a nil admin store does not panic | construct with nil, force a flush |

**Definition of Done:**
- [x] All five tests present and green.

---

## [x] US6 — ACME cancellation & bounded external I/O (W-I3, W-I4)

**Why:** the caller `context` is dropped across the lego seam (no cancellation into ACME orders; account
registration runs under the `lazyCA` mutex, blocking concurrent obtains and the renewal scheduler), and
the custom DNS provider is called with an unbounded `context.Background()`.

**Acceptance criteria:**
- [x] A cancelled/shutdown caller stops waiting on an in-flight ACME obtain AND on in-flight first-use
      registration.
- [x] The renewal scheduler (`shouldRenew`) is NEVER pinned by a hung registration (it uses the cached
      client or the configured fixed floor, never triggering registration); a build error is still
      retried on the next call.
- [x] The custom DNS provider `Present`/`CleanUp` calls carry a bounded deadline.

### [x] Task 6.1 — Propagate ctx into obtain + registration; keep the renewal scheduler off the registration path (W-I3)

- [x] **modify** `internal/acme/lego_client.go` — `obtain`: run the (ctx-less) `ObtainForCSR` in a
      goroutine and select on `ctx.Done()` so a cancelled/shutdown caller stops waiting (the abandoned
      call completes under lego's internal per-request timeout):
  ```go
  func (l *legoClient) obtain(ctx context.Context, csr *x509.CertificateRequest, _ string) ([]byte, store.CertInfo, error) {
      req := certificate.ObtainForCSRRequest{CSR: csr, Bundle: true, Profile: l.cfg.Profile}
      if l.cfg.Validity > 0 {
          req.NotAfter = time.Now().Add(l.cfg.Validity)
      }
      type result struct {
          res *certificate.Resource
          err error
      }
      ch := make(chan result, 1)
      go func() {
          res, err := l.client.Certificate.ObtainForCSR(req)
          ch <- result{res, err}
      }()
      select {
      case <-ctx.Done():
          return nil, store.CertInfo{}, transient(ctx.Err())
      case r := <-ch:
          if r.err != nil {
              return nil, store.CertInfo{}, classifyLego(r.err)
          }
          info, err := certInfoFromPEM(l.cfg.CAID, r.res.Certificate)
          if err != nil {
              return nil, store.CertInfo{}, permanent(err)
          }
          return r.res.Certificate, info, nil
      }
  }
  ```
- [x] **modify** `internal/acme/lazy.go` — make first-use registration ctx-aware and keep the renewal
      scheduler entirely off the registration path:
  - `resolve(ctx)` uses `singleflight.Group.DoChan("build", …)` + `select` on `ctx.Done()` so a
    cancelled/shutdown caller returns promptly (the in-flight build completes+caches in the background;
    a build error is surfaced to that caller and retried on the next call).
  - `obtain` threads the caller ctx into `resolve`.
  - `shouldRenew` uses a NON-blocking `cached()` check and otherwise the CONFIGURED fixed floor (as
    today), so a hung registration NEVER pins the renewal scheduler — it never triggers a build.
  ```go
  type lazyCA struct {
      // ... existing config fields (caID, shortlived, renewMargin, build) ...
      group singleflight.Group
      inner atomic.Pointer[caIssuer] // fast-path read; nil until first successful build
  }

  // cached returns the built client only if already constructed (never triggers a network build).
  func (l *lazyCA) cached() (caIssuer, bool) {
      if c := l.inner.Load(); c != nil {
          return *c, true
      }
      return nil, false
  }

  // resolve returns the built client, performing first-use registration once (deduped). It is ctx-aware:
  // a cancelled/shutdown caller returns promptly while the build completes+caches in the background.
  func (l *lazyCA) resolve(ctx context.Context) (caIssuer, error) {
      if c, ok := l.cached(); ok {
          return c, nil
      }
      ch := l.group.DoChan("build", func() (any, error) {
          if c, ok := l.cached(); ok {
              return c, nil
          }
          c, err := l.build()
          if err != nil {
              return nil, err // not cached → retried on the next call
          }
          l.inner.Store(&c)
          return c, nil
      })
      select {
      case <-ctx.Done():
          return nil, ctx.Err()
      case r := <-ch:
          if r.Err != nil {
              return nil, r.Err
          }
          return r.Val.(caIssuer), nil
      }
  }

  func (l *lazyCA) obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
      c, err := l.resolve(ctx)
      if err != nil {
          return nil, store.CertInfo{}, transient(err)
      }
      return c.obtain(ctx, csr, name)
  }

  func (l *lazyCA) shouldRenew(ctx context.Context, cur store.CertInfo, now time.Time) (bool, time.Time, error) {
      c, ok := l.cached()
      if !ok {
          // Degraded fixed floor: do NOT trigger registration from the renewal path so a hung CA never
          // pins the scheduler. (Defaults guard a zero config in tests — same values as today.)
          shortlived, margin := l.shortlived, l.renewMargin
          if shortlived <= 0 {
              shortlived = 160 * time.Hour
          }
          if margin <= 0 {
              margin = 48 * time.Hour
          }
          at := cur.NotBefore.Add(shortlived - margin)
          return !now.Before(at), at, nil
      }
      return c.shouldRenew(ctx, cur, now)
  }
  ```
  Replace the `mu sync.Mutex; inner caIssuer` pair with the atomic pointer + singleflight group
  (`golang.org/x/sync/singleflight` — already in the required `golang.org/x/sync` module used by
  `errgroup`, so `go.mod` does not change). The degraded-fixed-floor behavior is the SAME as today's
  `resolve`-error fallback — it now triggers on cached-miss instead, so `shouldRenew` never blocks on
  registration.

**Definition of Done:**
- [x] `obtain` and `resolve` are ctx-aware (a cancelled caller returns promptly); `shouldRenew` never
      calls `build()`; a build error is retried on the next `resolve`; the old mutex is gone.

### [x] Task 6.2 — Bound the DNS provider call (W-I4)

- [x] **modify** `internal/acme/lego_client.go` — `legoDNSAdapter.Present`/`CleanUp`: derive a bounded
      deadline instead of a bare `context.Background()`:
  ```go
  // dnsProviderTimeout bounds one TXT publish/cleanup against our neutral DNSProvider seam. lego's
  // challenge.Provider interface is ctx-less, so this is the only place a deadline can be imposed; the
  // record publish/remove is a quick API call (propagation waiting is lego's own concern).
  const dnsProviderTimeout = 2 * time.Minute

  func (a *legoDNSAdapter) Present(domain, _, keyAuth string) error {
      ctx, cancel := context.WithTimeout(context.Background(), dnsProviderTimeout)
      defer cancel()
      info := dns01.GetChallengeInfo(domain, keyAuth)
      return a.p.Present(ctx, info.EffectiveFQDN, info.Value)
  }
  // ... same for CleanUp ...
  ```

**Definition of Done:**
- [x] `Present`/`CleanUp` pass a bounded-deadline ctx to the DNSProvider seam.

### [x] Task 6.3 — Tests

| Test | Verifies | Setup notes |
|---|---|---|
| `TestLegoClient_ObtainRespectsCtxCancel` | a cancelled ctx returns promptly with a transient error | blocking obtain stub |
| `TestLazyCA_ConcurrentResolveSingleBuild` | N concurrent `resolve(ctx)` calls build once; a build error is retried on the next call | counting build func |
| `TestLazyCA_ResolveCancelWhileBuildHangs` | a cancelled ctx returns from `resolve` while the build blocks (the build still caches in the background) | build func that blocks on a release channel |
| `TestLazyCA_ShouldRenewNeverTriggersBuild` | `shouldRenew` with no cached client uses the fixed floor and does NOT call `build` | build counter asserted 0 |
| `TestLegoDNSAdapter_PresentUsesDeadline` | the adapter passes a ctx with a deadline to the DNSProvider | fake DNSProvider asserting `ctx.Deadline()` ok |

**Definition of Done:**
- [x] All five tests present and green (`-race` clean), including the cancel-while-hanging and
      no-build-from-shouldRenew guarantees.

---

## [x] US7 — Enrollment/issuance conformance & taxonomy (W-I2, W-I6, I-007, I-008, I-009, I-010)

**Why:** the P-256-only invariant is not enforced on the Phase-2 TLS CSR; several enroll-HTTP error
mappings diverge from PROTOCOL.md and the ban gate fails open on an unparseable IP; Issue-path rejection
labels drop the known tunnel name.

**Acceptance criteria:**
- [x] `recordRejection` records the mTLS-CN name on the Issue path (Phase 1 stays `""`).
- [x] A non-P-256 Phase-2 TLS CSR is refused (user reason `unsupported_key_type`, metric label
      `csr-mismatch` — an existing registered label, so no ARCHITECTURE §8 change).
- [x] `GET /enroll/nonce` maps `bad_source_ip`→400 and `enroll_rate`→429 (frozen PROTOCOL §2 contract);
      an unparseable peer IP is rejected before dispatch; a Valkey nonce-consume error is `internal`
      (retryable), not `invalid_nonce`.
- [x] A FAILED `/issue` consumes its nonce (replay → `invalid_nonce`).

### [x] Task 7.1 — Thread the tunnel name into Issue-path rejections (I-010) — FIRST (7.2 depends on it)

- [x] **modify** `internal/enroll/enroll.go` — give `recordRejection` (and `attestAndBind`, which calls
      it) a `name` parameter: pass the mTLS-CN name in `Issue` (its `attest-*`/`csr-mismatch` rejections),
      pass `""` in `Enroll` (Phase 1, no name yet). `recordRejection` then calls `s.rec.Reject(reason,
      name, ip)` so the metric + caplog dedup key on `(tunnel, reason)` per ARCHITECTURE §8. Phase-1
      behavior (empty name) is unchanged.

**Definition of Done:**
- [x] `recordRejection` takes a `name`; Issue-path callers pass the CN name; Phase-1 callers pass `""`.

### [x] Task 7.2 — Enforce ECDSA P-256 on the Phase-2 TLS CSR (W-I2)

- [x] **modify** `internal/enroll/enroll.go` — in `Issue`, after `TLSCSR.CheckSignature()` and
      `csrMatchesTunnel(...)` pass and before forwarding to the ACME chain, require the TLS CSR public key
      to be `*ecdsa.PublicKey` on P-256. On failure, record the rejection with the EXISTING registered
      `csr-mismatch` label via `recordRejection(ctx, ip, name, "csr-mismatch", req)` (persists evidence,
      like the other csr-mismatch sites) and return `&Error{Reason: "unsupported_key_type"}` (non-retryable
      → 400, matching `signError`'s identity-key wording).
  - Context: project.md "Enrollment accepts ECDSA P-256 keys ONLY"; PROTOCOL §2 scopes Phase 2 as part of
    enrollment. No new metric label is introduced, so ARCHITECTURE §8 is unchanged.

**Definition of Done:**
- [x] A non-P-256 TLS CSR is rejected with `unsupported_key_type` (400) and a `csr-mismatch` metric +
      evidence; the identity-CSR path is unchanged; no new rejection label is introduced.

### [x] Task 7.3 — Enroll-HTTP status mapping, taxonomy & fail-closed ban gate (I-007, I-008, I-009)

- [x] **modify** `internal/enroll/http.go`:
  - `handleNonce`: map `enrollLimit` errors explicitly — `enroll_rate` (Retryable) → **429** (frozen
    PROTOCOL §2 nonce-route contract), everything else (e.g. `bad_source_ip`) → `statusForError(e)` (→
    400). Do NOT route `enroll_rate` through the blanket `statusForError` (which would yield 503).
  - `ServeHTTP` ban gate: when `netip.ParseAddr(ip)` FAILS, reject (`400 bad_source_ip`) BEFORE dispatch
    instead of proceeding — the ban check must be the first effective gate (fail closed).
- [x] **modify** `internal/enroll/enroll.go` — `consumeNonce` handling in `Enroll`/`Issue`: distinguish a
      Valkey/script ERROR (→ `{Reason:"internal", Retryable:true}`) from a genuinely absent/replayed nonce
      (→ `{Reason:"invalid_nonce"}`), instead of mapping both to `invalid_nonce`.

**Definition of Done:**
- [x] Nonce route: `enroll_rate`→429, `bad_source_ip`→400; unparseable peer IP → 400 before dispatch;
      a Valkey nonce-consume error → `internal`+retryable, a real absent/replayed nonce → `invalid_nonce`.

### [x] Task 7.4 — Tests

| Test | Verifies | Setup notes |
|---|---|---|
| `TestIssueReject_CarriesTunnelName` | Issue-path `attest-*`/`csr-mismatch` reject with the CN name | fake recorder capturing name |
| `TestIssue_RejectsNonP256TLSCSR` | an RSA/P-384 `tls_csr` is refused `unsupported_key_type` (400) with a `csr-mismatch` metric; the identity CSR path is unchanged | build an RSA CSR |
| `TestIssue_NonceConsumedOnFailure` | a FAILED `Issue` (e.g. issuance-cap) consumes the nonce; replay → `invalid_nonce` (W-I6) | miniredis; drive a failing Issue then replay |
| `TestHandleNonce_BadSourceIPIs400` | `bad_source_ip` maps to 400 | `RemoteAddr` without host:port |
| `TestHandleNonce_EnrollRateIs429` | `enroll_rate` on the nonce route maps to 429 (not 503) | exhaust the per-IP minute window |
| `TestServeHTTP_UnparseableIPRejected` | an unparseable peer IP is refused before dispatch | malformed `RemoteAddr` |
| `TestConsumeNonce_ValkeyErrorIsInternal` | a script error yields `internal`+retryable, not `invalid_nonce` | rdb stub returning error |

**Definition of Done:**
- [x] All seven tests present and green.

---

## [x] US8 — Client library & protocol retry path (W-C1, W-C2, W-C3, I-005, I-006)

**Why:** the client panics on a bad enroll host, discards the Phase-1 bootstrap identity on a retryable
Phase-2 failure (orphaning a name in the registry), and its retry API is untested; several response
reads discard errors.

**Acceptance criteria:**
- [x] `fetchNonce` returns an error instead of nil-panicking on a bad host.
- [x] On a Phase-2 failure, `Enroll` returns the Phase-1 bootstrap identity so the caller can run the
      documented retry path WITHOUT re-enrolling (which would orphan the first name).
- [x] Response read errors are surfaced (not misreported as decode/empty-reason errors).
- [x] The `FetchIssueNonce` → `Renew` retry path is tested end to end.

### [x] Task 8.1 — Robust request construction & response reads (W-C1, I-005, I-006)

- [x] **modify** `client/enroll.go`:
  - `fetchNonce`: check the `http.NewRequestWithContext` error (return it) instead of `req, _ :=`.
  - The three `io.ReadAll(io.LimitReader(...))` sites (Phase-1 `Enroll`, `issueCerts`, `fetchNonce`):
    check the read error and wrap it (`fmt.Errorf("read response: %w", err)`).
  - The `json.Marshal(...)` discards: handle, or add the go.md justification comment (string-only marshal
    cannot fail — a one-line comment is acceptable).

**Definition of Done:**
- [x] No `req, _ :=` or unjustified `_` discard remains in `client/enroll.go`; read errors are wrapped.

### [x] Task 8.2 — Preserve the bootstrap identity for the documented retry path (W-C2)

- [x] **modify** `client/enroll.go` — `Enroll`: on a Phase-2 (`issueCerts`) failure, return the Phase-1
      bootstrap `*Identity` (name + bootstrap identity cert + `bootKey`) ALONGSIDE the error, so the
      caller can execute PROTOCOL §3's retry path (fresh nonce → wait `retry_after_seconds` → `Renew` over
      the same mTLS identity) without re-enrolling (which would orphan the first name — PROTOCOL §2: the
      name is never rolled back).
  - Concretely: `return bootIdent, err` on the Phase-2 error branch (the bootstrap identity has no public
    cert yet — exactly the state `Renew`/`FetchIssueNonce` expect); document the two-value contract. A
    successful enroll still returns the fully-issued identity + nil error (unchanged). Reconcile all
    `Enroll` callers (client tests, e2e) — existing `if err != nil { return … }` callers are unaffected.

**Definition of Done:**
- [x] A Phase-2 failure returns the bootstrap identity + the error; a successful enroll is unchanged; the
      contract is documented and all callers compile.

### [x] Task 8.3 — Tests (W-C3 + the above)

| Test | Verifies | Setup notes |
|---|---|---|
| `TestFetchNonce_BadHostReturnsError` | a malformed enroll host returns an error (no panic) | invalid host string |
| `TestEnroll_Phase2FailureReturnsBootstrapIdentity` | a retryable `/issue` failure returns the bootstrap identity + error; the name is not re-claimed | httptest server 503 on `/issue` |
| `TestFetchIssueNonce_RetryPathCompletes` | the documented retry path (fresh nonce → `Renew`) completes after a failed `/issue` using the preserved bootstrap identity | httptest enroll+issue handlers |
| `TestReadResponse_TruncatedBodyErrors` | a truncated response body surfaces a read error, not a decode error | server closing mid-body |

**Definition of Done:**
- [x] All four tests present and green.

---

## [x] US9 — e2e / test-harness robustness (W-C4, I-007c, I-008c, I-009c, I-010c, I-011)

**Why:** several e2e tests pass without exercising what they claim, leak a client connection, or fail
nondeterministically.

**Acceptance criteria:**
- [x] `TestE2E_Eviction` asserts the evicted victim's socket is closed (an unenforced concurrency cap
      cannot pass silently).
- [x] `echoPhone` joins `Run`'s return before `Close` (honors the `Close` contract; no leaked transport).
- [x] `TestE2E_CrossNodeAndFastPath`'s comment matches the actual scenario.
- [x] Test-code `pem.Decode`/parse/marshal/generate discards are nil-checked or `t.Fatal`'d.
- [x] `freeAddr` no longer races (deterministic bind).
- [x] `chalPost` uses a bounded-timeout HTTP client.

### [x] Task 9.1 — Strengthen and correct e2e tests

- [x] **modify** `e2e/e2e_test.go`:
  - `TestE2E_Eviction` (W-C4): after `c3` succeeds, assert exactly one of `c1`/`c2` observes EOF/error
    within a deadline (the evicted victim's socket is closed).
  - `echoPhone` (I-007c): capture a `runDone` channel and make cleanup `cancel(); <-runDone; c.Close()`.
  - `TestE2E_CrossNodeAndFastPath` comment (I-008c): correct it to "the same-node fast path entering at
    the owner replica" (no rebinding occurs).
  - `freeAddr` TOCTOU (I-010c): hold the probe listeners and pass bound listeners/addresses into the
    server where feasible, OR retry `startReplica` on a bind failure with fresh ports (deterministic).
- [x] **modify** `internal/tunneltest/containers.go` — `chalPost` (I-011): use an `http.Client` with a
      short timeout (or a ctx-bound request), matching the other helpers.
- [x] **modify** `client/harness_test.go`, `client/enroll_test.go`, `e2e/e2e_test.go` (I-009c): nil-check
      `pem.Decode` blocks before using `.Bytes` (reuse `parseCSR`'s pattern), and handle/`t.Fatal` the
      `_`-discarded `x509.ParseCertificate` / `MarshalECPrivateKey` / `ecdsa.GenerateKey` /
      `json.Marshal` / body-`Decode` results.

**Definition of Done:**
- [x] `TestE2E_Eviction` asserts a closed victim; `echoPhone` joins `Run` before `Close`; the CrossNode
      comment is accurate; `freeAddr` is deterministic; `chalPost` is time-bounded; the flagged test
      discards are handled. The e2e tier passes (`-tags=e2e`).

---

## [x] US10 — Ban geo-source attribution (S-007)

**Why:** per-country `Source` data is collected then discarded, so a matched geo-ban cannot tell the
operator which country/line fired.

**Acceptance criteria:**
- [x] A matched geo-ban's `Source` names the country code and the requesting ban-file line.
- [x] The absent/corrupt/zero-row CSV semantics are preserved EXACTLY.

### [x] Task 10.1 — Carry the country/source through expansion

- [x] **modify** `internal/ban/dbip.go` — `ExpandCountries` returns per-country prefixes:
      `func ExpandCountries(csvPath string, wanted map[string]struct{}) (map[string][]netip.Prefix, error)`
      (key = country code). Preserve the absent/corrupt/zero-row semantics EXACTLY (still `(nil, err)` on
      present-but-zero-rows and on absent — the caller distinguishes).
- [x] **modify** `internal/ban/engine.go` — `build`/`Load`: insert each country's prefixes with the
      parsed entry's `Source` (from `p.countries[cc]`, i.e. the file/line/`Detail=cc`), not the generic
      `country-expansion` source.
- [x] **modify** `internal/ban/dbip_test.go`, `internal/ban/engine_test.go` for the new return shape.

**Definition of Done:**
- [x] A geo-ban `Source` carries the country + file/line; the absent/zero-row `(nil,err)` semantics are
      unchanged; dbip/engine tests updated to the new shape.

### [x] Task 10.2 — Test

| Test | Verifies | Setup notes |
|---|---|---|
| `TestLoad_GeoBanCarriesCountrySource` | a matched geo-ban's `Source` names the country + the requesting ban-file line | CSV with `XX`/`YY` rows (placeholders only) |
| `TestExpandCountries_SemanticsPreserved` | absent CSV, zero-row CSV, and absent-wanted-code still return the documented `(nil,err)`/empty results | reuse the existing dbip cases against the new signature |

**Definition of Done:**
- [x] Both tests present and green.

---

## [x] US11 — Protocol method enforcement & close-reason accuracy (E-004, E-006, E-003)

**Why:** `/control`, `/data`, `/mesh` accept any method though PROTOCOL specifies POST; an oversize
control frame is misattributed as `phone-close`; a `NewConnID` discard carries a factually wrong comment.

**Acceptance criteria:**
- [x] `GET /control`, `GET /data`, `GET /mesh` → 405 (PROTOCOL §3–§5 already specify POST).
- [x] An oversize control frame records the `protocol-error` close reason (reviving that dead branch);
      genuine EOF stays `phone-close`.
- [x] The `NewConnID` failure fallback is a deterministic non-empty id (never a 400-refused dial-back),
      and its comment is accurate.

### [x] Task 11.1 — Enforce POST (E-006)

- [x] **modify** `internal/phoneconn/listener.go` — dispatch: require `http.MethodPost` on `/control` and
      `/data` (405, mirroring the existing `/issue` handling).
- [x] **modify** `internal/mesh/listener.go` — require `http.MethodPost` on `/mesh` (405).
  - Context: aligns the code with docs/PROTOCOL.md §3–§5 (already POST); no doc change needed.

**Definition of Done:**
- [x] Non-POST `/control`, `/data`, `/mesh` return 405; POST behavior is unchanged.

### [x] Task 11.2 — Distinct protocol-error close reason (E-004)

- [x] **modify** `internal/phoneconn/stream.go` — `readControlFrame`: return the EXISTING
      `wire.ErrControlTooLarge` for the oversize length-prefix case (instead of `io.ErrUnexpectedEOF`).
      (The `wire.ErrControlTooLarge` sentinel already exists in `internal/wire` — returned today by
      `EncodeControl`; `wire.DecodeControl` returns `ErrControlMalformed` for oversize, and `readPump`
      already maps any `wire.DecodeControl` failure to `protocol-error` — so no `internal/wire` change is
      required.)
- [x] **modify** `internal/phoneconn/listener.go` — `readPump`: map `wire.ErrControlTooLarge` (and any
      `wire.DecodeControl` failure) to the `protocol-error` close reason; a genuine EOF stays
      `phone-close`.

**Definition of Done:**
- [x] An oversize control frame records `protocol-error`; a graceful EOF still records `phone-close`; no
      `internal/wire` change was made.

### [x] Task 11.3 — Fix the NewConnID discard comment/fallback (E-003)

- [x] **modify** `internal/edge/bridge.go` — the `store.NewConnID()` discards (~lines 141-143, 181, 192):
      use a deterministic non-empty fallback on the (practically impossible) `crypto/rand` failure so a
      dial-back is never 400-refused, mirroring phoneconn's `mustConnID` (`"00000000"`), and correct the
      comment to describe the true behavior. Prefer hoisting `mustConnID` into `store` and reusing it at
      both sites (single source of truth).

**Definition of Done:**
- [x] The edge uses a non-empty fallback id on rand failure; the comment is accurate; `mustConnID` has a
      single source of truth if hoisted.

### [x] Task 11.4 — Tests

| Test | Verifies | Setup notes |
|---|---|---|
| `TestControlData_NonPostIs405` | `GET /control`, `GET /data` → 405 | httptest with a valid identity cert |
| `TestMesh_NonPostIs405` | `GET /mesh` → 405 | mesh handler test |
| `TestReadPump_OversizeFrameIsProtocolError` | an oversize length prefix records `protocol-error`, not `phone-close` | craft `0x01,0xff,0xff,0xff,0xff` |
| `TestNewConnIDFallback_NonEmpty` | the fallback id is non-empty and accepted by the dial-back match | force the rand-failure path via the hoisted helper |

- [x] Update the existing `TestReadPumpPongStampsLiveness` expectation (currently asserts the oversize
      frame → `phone-close`) to expect `protocol-error` (same file as Task 11.2's caller).

**Definition of Done:**
- [x] All four rows green, plus the `TestReadPumpPongStampsLiveness` expectation updated.

---

## [x] US12 — Correct the false-pass & redundant tests (W-E2, W-A12, W-A13, W-S3, A-014, A-015, S-005, S-004, S-008)

**Why:** several tests can pass while the behavior they name is broken, or are duplicates/dead; two
package globals block clean testing.

**Acceptance criteria:**
- [x] No test in scope can pass while the behavior it names is broken (unbanned-IP assertion, lifecycle
      readiness, legacy-flag rejection, all-8-key TTL sweep are made real).
- [x] Duplicate/dead tests are removed; the reserved-label branch gains real coverage.
- [x] `internal/limit/window.go` uses an injected clock (no package global); the async backoff base is
      injectable so the retry test runs in milliseconds.

### [x] Task 12.1 — Make weak assertions real

- [x] **modify** `internal/phoneconn/listener_test.go` (W-E2) — `TestServeHTTPIPBanFirst`: assert via the
      `Reject` recorder that the unbanned request records ZERO `ban` rejections (or decode the JSON body
      and assert `reason != "banned"`); the current `Body.String() == "banned\n"` compare can never fire.
- [x] **modify** `internal/server/server_test.go` (W-A12) — `waitUntil`: `t.Fatal` on timeout.
- [x] **modify** `internal/config/config_test.go` (W-A13) — `TestRemovedLegacyFlagsRejected`: assert the
      error identifies an UNKNOWN FLAG (message contains `unknown flag`) or supply an otherwise-valid
      config (env twins) so the only possible failure is the unknown flag.
- [x] **modify** `internal/limit/window_test.go` (W-S3) — extend `TestEveryKeyHasTTLAfterFirstOp` (or add
      a sibling) to invoke `ClaimBandwidth`, `ClaimTraffic`, `IssuanceBegin`, `IssuanceRecord`,
      `BumpCAFailures` before the all-keys TTL sweep, so `bw:`, `traf:day/week`, `iss:`, `iss_inflight:`,
      `acme-fail:` are pinned as TTL'd.

**Definition of Done:**
- [x] Each of the four tests now fails if its named behavior regresses (verified by construction, not a
      dead/always-true assertion).

### [x] Task 12.2 — Remove dead/duplicate tests; fix missed coverage

- [x] **modify** `internal/config/config_test.go` (A-014) — delete the copy-paste duplicate second case
      of `TestValidateMeshPoolSizeRange`.
- [x] **modify** `internal/server/schedulers_test.go` (A-015) — `TestValidNameFunc`: add a case whose
      length matches the generator shape so the reserved-label rejection is actually exercised.
- [x] **modify** `internal/router/nodes_test.go` (S-005) — delete the three route-registry duplicates
      (`TestBindLookupRouteRoundTrip`, `TestBindRouteFingerprintGuard`, `TestSelfHealRouteConnIDOwner` —
      kept in `registry_test.go`) and the dead `_ = mr` statement.

**Definition of Done:**
- [x] The duplicate/dead items are gone; the reserved-label branch is exercised; the kept coverage
      (registry_test.go) still passes.

### [x] Task 12.3 — Testability seams (S-004, S-008)

- [x] **modify** `internal/limit/window.go` (S-004) — replace the package-global `nowFunc` with an
      injected clock: move `Allow`/`Over` onto `Limiter` (which already has an injected `now` + `SetClock`)
      or pass the clock in. No package-level mutable global.
- [x] **modify** the call sites this changes: `internal/enroll/enroll.go` (`limit.Allow` ×2 /
      `limit.Over` ×2), `internal/edge/edge.go` (`limit.Allow`), and their tests
      (`internal/enroll/*_test.go`, `internal/edge/*_test.go`, `internal/limit/window_test.go`, AND
      `internal/limit/helpers_test.go` — `freezeClock` writes the `nowFunc` global directly and MUST be
      migrated to the injected-clock seam, or it will not compile).
- [x] **modify** `internal/store/async.go` (S-008) — make the retry backoff base injectable (functional
      option, per go.md), defaulting to the current 1s; `internal/store/async_test.go` uses a tiny base so
      the retry-exhaustion test runs in milliseconds. Reconcile the `NewAsyncConnLog` call in `server.Run`
      (default option).

**Definition of Done:**
- [x] No package-global `nowFunc` remains; all call sites compile against the injected clock; the async
      retry test runs in milliseconds with the injected backoff; production defaults unchanged.

---

## [x] US13 — Deployment fixups (D-008, D-009, D-010)

**Why:** the README ntfy step is not literally executable and leaves alerting silently broken; the pinned
compose images get no update PRs; missing required-variable guards let an empty-credential stack start.

**Acceptance criteria:**
- [x] The README ntfy step runs inside the ntfy container and restarts the bridge after setting the token.
- [x] Dependabot covers the compose images.
- [x] Every REQUIRED compose variable is `:?`-guarded (fail fast); optional ones are not.

### [x] Task 13.1 — README ntfy step (D-008)

- [x] **modify** `README.md` step 7 — prefix the `ntfy user add`/`ntfy token add` commands with
      `docker compose -f deploy/docker-compose.yml exec ntfy …`, and add
      `docker compose -f deploy/docker-compose.yml restart ntfy-alertmanager` after setting the token.
      Do NOT change ntfy exposure (D-006 deferred).

**Definition of Done:**
- [x] The README step is literally executable (exec context + bridge restart); ntfy exposure is unchanged.

### [x] Task 13.2 — Dependabot for compose images (D-009)

- [x] **modify** `.github/dependabot.yml` — add a `package-ecosystem: "docker-compose"` entry with
      `directory: "/deploy"` (verified upstream: Docker Compose is a distinct ecosystem from `docker`).

**Definition of Done:**
- [x] `.github/dependabot.yml` has a valid `docker-compose` entry for `/deploy`.

### [x] Task 13.3 — Fail-fast compose variables (D-010)

- [x] **modify** `deploy/docker-compose.yml` — guard every REQUIRED interpolated variable with `:?`,
      matching the existing `${DEPLOY_UID:?…}`: `TUNNEL_DOMAIN`, `ENROLL_HOST`, `CONTROL_HOST`, `S3_BUCKET`,
      `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `GRAFANA_ADMIN_PASSWORD` (and any other currently-unguarded
      required var). Do NOT add `:?` to genuinely optional variables. The fetcher service and its
      variables (D-005) MUST NOT be touched.

**Definition of Done:**
- [x] Every required variable is `:?`-guarded; the fetcher service is untouched; `make compose-config`
      (run at US14) passes with `deploy/.env.example`.

---

## [x] US14 — Documentation sync + ground-up verification (final)

**Why:** keep the canonical docs and `project.md` accurate for the behavior changes, and double-check
EVERYTHING from the ground up.

**Acceptance criteria:**
- [x] The canonical docs reflect the P-256-on-TLS-CSR invariant, the single-load/build-verify-commit ban
      behavior, and the signer-allowlist vanished-file refusal.
- [x] D-005 and D-006 were NOT touched; no finding/plan ID leaked into any code/commit/artifact.
- [x] ALL quality gates pass on the final code.

### [x] Task 14.1 — Documentation

- [x] **modify** `docs/PROTOCOL.md` §2 — state explicitly that Phase 2 enforces ECDSA P-256 on the TLS
      CSR (matching the identity-CSR rule) so the "ECDSA P-256 keys ONLY" invariant covers both keys.
- [x] **modify** `docs/ARCHITECTURE.md` §7 — note the single startup ban load + build-verify-commit
      reload (no double load; a torn read never goes live) and the signer-allowlist vanished-file refusal.
- [x] **modify** `.claude/rules/project.md` ONLY if a Standard Command / behavior summary changed (e.g.
      the P-256 invariant wording). Keep it CONCISE (reference the canonical docs; no duplication).
- [x] Do NOT create new doc files. Do NOT touch the DB-IP CC BY 4.0 attribution. No AI attribution
      anywhere. No real country codes/domains (placeholders `XX`/`YY`, `example.test`, `free.example.com`
      only). These doc edits touch NO Mermaid chart (prose only).

**Definition of Done:**
- [x] PROTOCOL §2 and ARCHITECTURE §7 reflect the new behavior; no Mermaid chart changed; attribution and
      placeholder rules honored.

### [x] Task 14.2 — Ground-up double-check of EVERYTHING (last task)

- [x] Re-read this plan top to bottom; confirm every acceptance criterion and every `[ ]` is satisfied and
      checked, and that D-005 and D-006 were NOT touched.
- [x] Confirm no code comment, commit message, or artifact references a finding/plan ID (agent.md).
- [x] Confirm no secret/real value entered the repo; `git status` shows the intended tracked/untracked set
      (secrets untracked & gitignored; `config.scfg` git-`rm --cached`).
- [x] Run ALL quality gates (ONCE, here): `make build`, `make lint`, `make vet`, `make govulncheck`,
      `make test-unit`, `make test-integration`, `make test-e2e`, `make test-scripts`,
      `make compose-config`, `make tidy` (assert no drift). Pipe each through `tee` to
      `/tmp/tunneld-plan5-<gate>.log`. Fix every failure (root cause) and re-run.
- [x] Confirm the `## Deviations` section records every reconciliation made against the current code.

**Definition of Done:**
- [x] Every checkbox in the plan is `[x]`; all quality gates pass on the FINAL code; `## Deviations` is
      complete; D-005/D-006 untouched.

---

## Deviations

- **Task 4.3 (mesh cert) — added a signer seam for testability.** `meshCertHolder` gained a `sign
  meshSigner` field (defaulting to `caObj.SignMesh`), and `mint()`/`rotateLoop()` dropped their `caObj`
  parameter. A real CA cannot be made to fail `SignMesh` deterministically, so the seam is required to
  test the fatal-initial-mint and rotation-retry paths. `server.Run`'s `rotateLoop(gctx)` call and
  `TestMeshCertHolderHotSwap` were updated accordingly.
- **Task 6.1 (ACME obtain) — added an obtain seam for testability.** `legoClient` gained an `obtainCSR`
  field (defaulting to `client.Certificate.ObtainForCSR`) so the ctx-cancel path can be driven with a
  blocking stub (`TestLegoClient_ObtainRespectsCtxCancel`); the real lego client is otherwise unstubbable.
- **Task 12.3 (S-004) — removed the now-dead edge `rdb` field/param.** Moving `Allow`/`Over` onto
  `Limiter` left `Edge.rdb` (and the `rdb` parameter of `edge.New`) unused; both were removed (updating
  `server.Run` and the edge test harness) to keep the build lint-clean. `StreamLimiter` gained `Allow`.
- **Task 12.3 (S-004) — integration test needed a Limiter.** `TestIntegration_Registry` built a bare
  `enroll.Service` with no `Limiter` (it previously relied on the package-level `limit.Allow(s.rdb, …)`).
  Both sub-tests now pass a `limit.NewLimiter(rdb, …)`.
- **Task 4.4 test (W-A8) — corrected the name-prefix expectation.** Per decision 5 the prefix is
  lowercased at runtime, so an UPPERCASE prefix is normalized-and-accepted (not rejected). The planned
  "uppercase fails" test row was corrected to "uppercase normalized ok"; the charset guard rejects only
  non-`[a-z0-9-]` characters and a leading `-`.
- **Task 7.4 test — `TestHandleNonce_EnrollRateIs429` folded.** The `enroll_rate`→429 nonce-route mapping
  is already covered by the pre-existing `TestHandlerNonceRouteRateLimited` (it exhausts the per-IP minute
  window and asserts 429), so a separate identically-named test would duplicate it (US12 forbids duplicate
  tests). No new test was added under that name.
- **Task 11.4 test — `TestReadPump_OversizeFrameIsProtocolError` folded.** The oversize-frame →
  `protocol-error` case is exercised by the (plan-required) update to `TestReadPumpPongStampsLiveness`; a
  separate identically-named test would duplicate the same oversize-frame assertion, so it was not added.
- **Task 4.3 test — signer seam reachable through the constructor.** `newMeshCertHolder` gained an
  optional `signOverride ...meshSigner` param (production passes none) so `TestMeshCert_InitialMintFatal`
  drives the FATAL initial-mint path through the constructor (not just `mint()`), verifying the error
  actually propagates out of `newMeshCertHolder`.
- **US11 test — `store.MustConnID` rand-failure seam.** `internal/store/event.go` gained an unexported
  `connIDRand` package var (defaulting to `crypto/rand.Read`) so a white-box test
  (`event_internal_test.go`) can force the rand-failure path and assert the non-empty `"00000000"`
  fallback — the planned `TestNewConnIDFallback_NonEmpty` alone could not reach that branch.
