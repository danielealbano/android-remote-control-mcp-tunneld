<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 2 — Full-Audit Remediation

Remediation of every finding from the full-codebase audit (95 findings: 4 CRITICAL, ~40 WARNING,
~51 INFO). One comprehensive plan (operator decision). Two behavior forks were resolved by the
operator: **over-cap response drain = pace + account** (never tear down the tunnel); **/connect
pre-auth ordering = acquire the semaphore BEFORE the per-IP connect rate-limit Redis call**. Two
further forks collapse to the documented contract and are decided here without assumption:
**config validation = fail-fast** (per `docs/ARCHITECTURE.md` §9) and **ban-CSV failure =
skip-and-warn when the CSV is absent, keep-previous-snapshot when a present CSV fails to parse**
(per `docs/ARCHITECTURE.md` §6).

Finding IDs (AUTH-/ING-/DP-/OPS-/DEP-/DOC-/TEST-) are traceability tags for this plan only; they
MUST NOT appear in any code comment (see US15).

## Finding coverage

All 95 audit findings are addressed. Several findings were reported by more than one investigation
agent under different IDs; those duplicates are covered once: ING-012 ≡ TEST-004 (total-header cap
test); OPS-006 ≡ TEST-003 (parser overflow); DEP-010 ≡ TEST-022 (`scripts_test.sh` cleanup, US16.7);
AUTH-009 ⊇ TEST-021 (IPv6 in the abuse path). Findings with no dedicated production change are
covered by test-only actions in US18: ING-013 (`TestSanitize_MTLSAndForwarded`), TEST-025
(`TestGenerateName_ReservedSkipAndExhaustion`), TEST-026 (`TestCaplog_WindowExpiryRelog`), TEST-027
(`TestEnrollBodyReadTimeout`).

## Conventions for the implementer

- Reconcile every code block with the CURRENT code before applying — the audit already changed
  nothing, but preserve any incidental bugfix and log it in `## Deviations`.
- NO code comment may reference a plan number, user story, task, action, or finding ID. Comments
  cite ONLY `docs/` sections. This applies to every block below.
- Quality gates run ONCE at the end (US19), never per task.

---

## US1 — [x] Fail-fast config validation & overflow-safe size/bitrate parsing

**Why:** Several documented-critical config values pass `Validate()` today and then either panic the
replica at runtime or silently break the whole service; the size/bitrate parsers wrap on overflow and
return a negative value with no error. `docs/ARCHITECTURE.md` §9 promises `Validate()` "fail-fasts on
every cross-field invariant."

**Acceptance criteria:**
- [x] `--ping-interval`, `--limit-request-timeout`, `--ban-poll`, `--cert-validity` each reject `≤ 0` in `Validate()` (OPS-001..004).
- [x] Every parsed byte-size limit and the bandwidth floor reject `0` / degenerate values (OPS-005).
- [x] `ParseByteSize`/`ParseBitrate` reject inputs whose multiplication overflows `int64` instead of returning a wrapped value (OPS-006).
- [x] All new rejections are covered by unit tests (added in US18).

### Task 1.1 — [x] Duration lower bounds in `Validate()`
- [x] **Action** — modify `internal/config/config.go`, in `Validate()`, add lower-bound checks (place the ping-interval check next to the existing `> 90s` upper bound; add the others beside the existing `RouteTTL`/`ConnectAuthTimeout`/`ShutdownGrace` block):
```go
if c.PingInterval <= 0 {
	return fmt.Errorf("--ping-interval must be > 0, got %s", c.PingInterval)
}
if c.LimitRequestTimeout <= 0 {
	return fmt.Errorf("--limit-request-timeout must be > 0, got %s", c.LimitRequestTimeout)
}
if c.BanPoll <= 0 {
	return fmt.Errorf("--ban-poll must be > 0, got %s", c.BanPoll)
}
if c.CertValidity <= 0 {
	return fmt.Errorf("--cert-validity must be > 0, got %s", c.CertValidity)
}
```
- [x] **DoD:** the four checks are present; the existing `PingInterval > 90s` and `LimitRequestTimeout >= 100s` upper bounds are unchanged.

### Task 1.2 — [x] Reject degenerate byte-size limits
- [x] **Action** — modify `internal/config/config.go`, in the size-parse loop in `Validate()`, require each parsed size `≥ 1`:
```go
for _, sz := range []struct {
	name string
	v    string
}{
	{"--limit-body", c.LimitBody},
	{"--limit-response", c.LimitResponse},
	{"--limit-headers", c.LimitHeaders},
	{"--limit-header-single", c.LimitHeaderSingle},
	{"--limit-enroll-body", c.LimitEnrollBody},
} {
	n, err := ParseByteSize(sz.v)
	if err != nil {
		return fmt.Errorf("%s: %w", sz.name, err)
	}
	if n < 1 {
		return fmt.Errorf("%s must be ≥ 1 byte, got %q", sz.name, sz.v)
	}
}
```
- [x] **DoD:** `--limit-response 0`, `--limit-headers 0b`, etc. fail `Validate()`.

### Task 1.3 — [x] Overflow-safe parsers
- [x] **Action** — modify `internal/config/size.go`, `ParseByteSize`: before `return n * mult`, guard the multiply:
```go
if mult > 1 && n > math.MaxInt64/mult {
	return 0, fmt.Errorf("byte size %q overflows int64", s)
}
return n * mult, nil
```
- [x] **Action** — modify `internal/config/size.go`, `ParseBitrate`: before `return (n * bitsMult) / 8`, guard:
```go
if bitsMult > 1 && n > math.MaxInt64/bitsMult {
	return 0, fmt.Errorf("bitrate %q overflows int64", s)
}
return (n * bitsMult) / 8, nil
```
- [x] **Action** — add `"math"` to the `internal/config/size.go` import block.
- [x] **DoD:** an input like `9223372036854775807kb` returns an error (not a negative value); in-range values are unchanged.

---

## US2 — [x] Trusted-IP normalization (IPv4-mapped IPv6 + IPv6 robustness)

**Why:** `clientip.TrustedIP` is the ONLY derivation of the abuse-control IP. It does not normalize
IPv4-mapped IPv6 (`::ffff:a.b.c.d`) or strip zones, so the same client can present two distinct forms
that bypass bans and split rate-limit counters (ING-005). Fixing it here (the single choke point)
covers `ban.Match` and every `rl:` key derived from it.

**Acceptance criteria:**
- [x] `TrustedIP` returns an `Unmap()`ed, zone-stripped `netip.Addr` (ING-005 lookup side).
- [x] The right-most-token, fail-closed semantics are otherwise unchanged.

### Task 2.1 — [x] Unmap + de-zone in `TrustedIP`
- [x] **Action** — modify `internal/clientip/clientip.go`, `TrustedIP`: after a successful parse, normalize:
```go
addr, err := netip.ParseAddr(last)
if err != nil {
	return netip.Addr{}, false
}
return addr.Unmap().WithZone(""), true
```
- [x] **DoD:** `::ffff:9.9.9.9` and `9.9.9.9` yield the identical `netip.Addr`; a zoned literal loses its zone.

---

## US3 — [x] Ban engine & watcher correctness

**Why:** The ban engine (the ONLY revocation mechanism) has five defects that make it silently
stale/open: mapped-IPv6 entries never match (ING-005 insert side); the watcher tracks only the max
mtime so an equal/older-mtime replacement or a file deletion never reloads (ING-002); a failed load
consumes the mtime so recovery never retries (ING-003); one malformed CSV row aborts the entire
country expansion (ING-008); a present-but-unreadable CSV silently drops all country bans from the new
snapshot (ING-009); and `ParseLine` silently accepts extra tokens (ING-010).

**Acceptance criteria:**
- [x] `ip`/`cidr` entries are `Unmap()`ed at insert so mapped-form entries match unmapped lookups (ING-005).
- [x] The watcher reloads on ANY per-file change including deletion and equal/older mtime replacement (ING-002).
- [x] A failed load is retried on the next tick (mtime not consumed on failure) (ING-003).
- [x] A malformed CSV row is skipped, not fatal to the whole expansion (ING-008).
- [x] A present CSV that yields ZERO parseable rows (corrupt/empty) is a HARD load error that keeps the previous snapshot; a valid CSV whose wanted country code is simply absent stays legal (empty result, no error); an ABSENT CSV still skip-and-warns (ING-009).
- [x] A ban line with extra tokens is rejected (warn-and-skip), not silently truncated (ING-010).

### Task 3.1 — [x] Unmap ip/cidr at insert
- [x] **Action** — modify `internal/ban/parse.go`, in `parseFile` `case "ip"`: `addr = addr.Unmap()` before building the prefix:
```go
addr, e := netip.ParseAddr(value)
if e != nil {
	log.Warn("skipping invalid ip", "file", path, "line", lineNo, "value", value)
	continue
}
addr = addr.Unmap()
src.Reason, src.Detail = ReasonIP, value
p.prefixes = append(p.prefixes, prefixSource{netip.PrefixFrom(addr, addr.BitLen()), src})
```
- [x] **Action** — modify `internal/ban/parse.go`, `case "cidr"`: unmap the prefix address when it is 4-in-6:
```go
pfx, e := netip.ParsePrefix(value)
if e != nil {
	log.Warn("skipping invalid cidr", "file", path, "line", lineNo, "value", value)
	continue
}
if a := pfx.Addr(); a.Is4In6() {
	pfx = netip.PrefixFrom(a.Unmap(), pfx.Bits()-96)
}
src.Reason, src.Detail = ReasonCIDR, value
p.prefixes = append(p.prefixes, prefixSource{pfx.Masked(), src})
```
- [x] **DoD:** a ban `ip ::ffff:9.9.9.9` matches a lookup of `9.9.9.9` and vice-versa.

### Task 3.2 — [x] Reject extra tokens in `ParseLine`
- [x] **Action** — modify `internal/ban/parse.go`, `ParseLine`: after comment-stripping and `strings.Fields`, reject `len(fields) != 2`:
```go
fields := strings.Fields(line)
if len(fields) != 2 {
	return "", "", fmt.Errorf("malformed ban line %q (want exactly '<kind> <value>')", line)
}
```
- [x] **Action** — modify `internal/ban/parse.go`, the `ParseLine` doc comment: state that a line with anything other than exactly `<kind> <value>` — INCLUDING extra tokens — yields a non-nil error (the caller warns-and-skips).
- [x] **DoD:** `country XX YY` is warned-and-skipped (not silently reduced to `XX`); the `ParseLine` doc comment matches the new behavior.

### Task 3.3 — [x] Per-file fingerprint watcher (detect any change incl. deletion)
- [x] **Action** — modify `internal/ban/watch.go`: replace the single `last time.Time` and `maxMtime` with a per-path fingerprint map, reloading when ANY path's `(mtime, size, exists)` differs, and advancing the recorded fingerprint ONLY on a successful load.
```go
type fileState struct {
	exists  bool
	modTime time.Time
	size    int64
}

type watcher struct {
	e        *Engine
	files    []string
	csv      string
	onReload func(*Engine)
	log      *slog.Logger
	last     map[string]fileState
}

func (w *watcher) initial() {
	cur := w.fingerprint()
	if err := w.e.Load(w.files, w.csv, w.log); err != nil {
		w.log.Warn("initial ban load error; engine stays at empty/previous snapshot until next successful load", "err", err)
		return // do NOT record cur — retry on the next tick
	}
	w.last = cur
	if w.onReload != nil {
		w.onReload(w.e)
	}
}

func (w *watcher) tick() {
	cur := w.fingerprint()
	if w.last != nil && sameStates(w.last, cur) {
		return
	}
	if err := w.e.Load(w.files, w.csv, w.log); err != nil {
		w.log.Warn("ban reload error; keeping previous snapshot (will retry)", "err", err)
		return // do NOT advance w.last — retry on the next tick
	}
	w.last = cur
	if w.onReload != nil {
		w.onReload(w.e)
	}
}

// fingerprint records (exists, mtime, size) for every configured path so a change of ANY kind —
// including deletion or a replacement with an equal/older mtime — is detected.
func (w *watcher) fingerprint() map[string]fileState {
	states := map[string]fileState{}
	paths := w.files
	if w.csv != "" {
		paths = append(append([]string{}, w.files...), w.csv)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			states[p] = fileState{exists: false}
			continue
		}
		states[p] = fileState{exists: true, modTime: fi.ModTime(), size: fi.Size()}
	}
	return states
}

func sameStates(a, b map[string]fileState) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || av != bv {
			return false
		}
	}
	return true
}
```
- [x] **Action** — update the `Watch` constructor call to initialise `last` as `nil` (so the first `tick` after a failed `initial` still fires): `w := &watcher{e: e, files: files, csv: csvPath, onReload: onReload, log: log}` (leave `last` zero/nil).
- [x] **Action** — delete the now-unused `maxMtime` function.
- [x] **Action** — modify `internal/ban/watch.go`, the `Watch` function doc comment: rewrite it to state it polls a per-path `(exists, mtime, size)` fingerprint every `poll` and reloads on ANY change — including deletion and equal/older-mtime replacement — dropping the stale "max mtime" wording.
- [x] **DoD:** deleting a ban file, or replacing one with an equal/older mtime, triggers a reload on the next tick; a failed load retries until it succeeds.

### Task 3.4 — [x] CSV row-skip + present-CSV-failure is fail-closed
- [x] **Action** — modify `internal/ban/dbip.go`, `ExpandCountries`: tolerate a malformed row instead of aborting the whole file (ING-008), AND treat a present-but-garbage CSV (zero parseable rows) as an error so the caller keeps the previous snapshot (ING-009). Set `r.FieldsPerRecord = -1`, skip bad/short rows, count validly-parsed rows, and error when none parsed. Parse the addresses BEFORE the wanted-code check so `validRows` counts every parseable row (this is what distinguishes "valid CSV, wanted code absent" — `validRows>0`, empty result, no error — from "garbage CSV" — `validRows==0`, error):
```go
r := csv.NewReader(f)
r.FieldsPerRecord = -1 // tolerate stray rows; validate width per-row below
r.ReuseRecord = true

var out []netip.Prefix
validRows := 0
for {
	rec, err := r.Read()
	if errors.Is(err, io.EOF) {
		break
	}
	if err != nil || len(rec) < 3 {
		continue // skip a malformed/short row, keep going (matches the address-parse skip policy)
	}
	start, e1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
	end, e2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
	if e1 != nil || e2 != nil {
		continue
	}
	validRows++
	cc := strings.ToUpper(strings.TrimSpace(rec[2]))
	if _, ok := wanted[cc]; !ok {
		continue
	}
	rng := netipx.IPRangeFrom(start, end)
	if !rng.IsValid() {
		continue
	}
	out = append(out, rng.Prefixes()...)
}
if validRows == 0 {
	// A present CSV that produced no parseable rows is corrupt/empty — error so the caller keeps the
	// previous snapshot rather than silently dropping every country ban (docs/ARCHITECTURE.md §6).
	return nil, fmt.Errorf("dbip csv %q produced no valid rows", csvPath)
}
return out, nil
```
Add `"fmt"` to the `internal/ban/dbip.go` import block.
- [x] **Action** — modify `internal/ban/engine.go`, `Load`: distinguish an ABSENT CSV (skip-and-warn, first deploy) from a PRESENT-but-unreadable CSV (HARD error → keep previous snapshot). Replace the `ExpandCountries` error branch:
```go
if len(wanted) > 0 {
	prefixes, err := ExpandCountries(csvPath, wanted)
	switch {
	case err == nil:
		for _, pfx := range prefixes {
			table.Insert(pfx, Source{Reason: ReasonCountry, File: csvPath, Detail: "country-expansion"})
		}
	case csvPath == "" || errors.Is(err, fs.ErrNotExist):
		// First-deploy / geo-off: the CSV does not exist yet — skip country entries, keep ip/cidr.
		log.Warn("country ban expansion skipped (CSV absent); ip/cidr bans still enforced", "csv", csvPath, "err", err)
	default:
		// A configured CSV is present but failed to parse: do NOT silently drop active geo bans.
		log.Warn("country ban expansion failed on a present CSV; keeping previous snapshot", "csv", csvPath, "err", err)
		return err // preserve the previous snapshot (never swap in one missing the country layer)
	}
}
```
- [x] **Action** — confirm `internal/ban/engine.go` imports `io/fs` (already imported) and `errors` (already imported).
- [x] **Action** — modify `internal/ban/engine.go`, the `Load` doc comment: rewrite it to state — absent files/CSV skip-and-warn; a PRESENT CSV that yields zero parseable rows returns an error and keeps the previous snapshot; a valid CSV whose wanted country code is absent is legal (empty result, no error). (Removes the now-inaccurate "a missing/unreadable CSV skips only the country entries" wording.)
- [x] **Action** — modify `internal/ban/dbip.go`, the `ExpandCountries` doc comment: rewrite it to state it returns an error when `csvPath == ""`, the file is unreadable, OR it yields zero parseable rows (corrupt/empty); the caller keeps the previous snapshot on the present-but-unusable case and skip-and-warns ONLY when the CSV is absent. (Removes the now-inaccurate "the caller then warns and skips country entries" wording.)
- [x] **DoD:** one bad CSV row no longer drops all country bans; a present CSV with zero parseable rows keeps the previous snapshot; an absent CSV still skip-and-warns; the `Load`/`ExpandCountries` doc comments match the new behavior.

---

## US4 — [x] Bandwidth-bucket lifecycle & bounded cap-hit accounting

**Why:** The bucket registry evicts a connected-but-quiet tunnel's entry after the idle window; the
live `Conn` keeps the old pointers while ingress mints a fresh pair, so uploads can drain two budgets
(up to 2× the cap) — breaking the documented "ONE budget" invariant (ING-001). Separately, caplog's
per-key distinct-IP set grows unbounded within a window under a distributed flood (ING-011).

**Acceptance criteria:**
- [x] A live WS connection's bucket pair is never evicted while the connection is held (ING-001).
- [x] caplog's per-key IP set is bounded; overflow is reported as a capped count (ING-011).

### Task 4.1 — [x] Pin buckets for the lifetime of a connection
- [x] **Action** — modify `internal/limit/registry.go`: add a pin refcount to `bucketEntry` and skip eviction of pinned entries; add `Pin`/`Unpin`.
```go
type bucketEntry struct {
	up, down   *TokenBucket
	lastAccess time.Time
	pins       int
}

// Pair returns the SAME (up, down) instances for name, creating them on demand, and lazily evicts
// UNPINNED entries idle past the idle window. A live WS connection pins its pair (see Pin) so it is
// never evicted mid-connection — the ingress paced reader and the WS leg keep sharing ONE budget
// (docs/ARCHITECTURE.md §4).
func (r *BucketRegistry) Pair(name string) (up, down *TokenBucket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for k, e := range r.m {
		if e.pins == 0 && now.Sub(e.lastAccess) > r.idle {
			delete(r.m, k)
		}
	}
	e := r.ensure(name)
	e.lastAccess = now
	return e.up, e.down
}

// Pin returns name's pair and increments its pin count so the entry survives idle eviction until the
// matching Unpin. Called by the WS manager at bind.
func (r *BucketRegistry) Pin(name string) (up, down *TokenBucket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.ensure(name)
	e.pins++
	e.lastAccess = r.now()
	return e.up, e.down
}

// Unpin drops one pin previously taken by Pin. Called by the WS manager at teardown.
func (r *BucketRegistry) Unpin(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.m[name]; ok && e.pins > 0 {
		e.pins--
	}
}

func (r *BucketRegistry) ensure(name string) *bucketEntry {
	e, ok := r.m[name]
	if !ok {
		u, d := NewTunnelBandwidth(r.bps)
		e = &bucketEntry{up: u, down: d}
		r.m[name] = e
	}
	return e
}
```
- [x] **Action** — modify `internal/wsconn/manager.go`, `HandleConnect`: replace `up, down := m.buckets.Pair(name)` with `up, down := m.buckets.Pin(name)`.
- [x] **Action** — modify `internal/wsconn/conn.go`, `teardown` (inside the `closeOnce.Do`): after `c.cancel()`, add `c.mgr.buckets.Unpin(c.name)`.
- [x] **DoD:** a connection idle >10 min keeps its bucket pair; ingress and the WS leg resolve the SAME pair for that name throughout.

### Task 4.2 — [x] Bound caplog's per-key IP set
- [x] **Action** — modify `internal/caplog/caplog.go`: cap the distinct-IP set per `(tunnel, reason)` key at a constant (e.g. `maxTrackedIPs = 1024`); once reached, stop inserting and mark the entry so the summary reports `ips=<cap>+`. Add a `const maxTrackedIPs = 1024`; where the code does `ips[clientIP] = struct{}{}`, guard with `if len(ips) < maxTrackedIPs { ips[clientIP] = struct{}{} } else { entry.ipsCapped = true }`; where it formats `len(ips)`, append `"+"` when `ipsCapped` (add `"strconv"` to the `internal/caplog/caplog.go` imports for formatting `<cap>+`).
- [x] **DoD:** a flood from >1024 distinct IPs allocates at most `maxTrackedIPs` map entries per key per window; the summary line reports the capped count.

---

## US5 — [x] Ingress pipeline hardening

**Why:** The public hot path has the same unjoined-goroutine ResponseWriter race as enroll — a fatal,
remotely-triggerable crash (AUTH-001); Redis errors on the rate-limit/concurrency path return a bare
500 with no log or metric (ING-004); `Connection`-nominated hop-by-hop headers are not stripped
(ING-007); Host matching is case-sensitive so an uppercased Host 404s a live tunnel (ING-014); a
client abort mid-body is mislabeled `body_read_timeout` (ING-015).

**Acceptance criteria:**
- [x] The body read never touches the `ResponseWriter` from the unjoined goroutine — no `MaxBytesReader` in the goroutine (AUTH-001).
- [x] Redis errors on the rps/rpm/concurrency path are logged with identifiers before the 500 (ING-004).
- [x] Headers named by the `Connection` header value are stripped in BOTH directions (ING-007).
- [x] Host→name resolution is case-insensitive (ING-014).
- [x] A client disconnect mid-body is not counted as a cap-hit `body_read_timeout` (ING-015).

### Task 5.1 — [x] Race-free paced body read
- [x] **Action** — modify `internal/ingress/handler.go`: change `bodyResult` to `{data []byte; tooBig bool; err error}`; replace `readPacedBody` with `readPacedBodyLimited` that enforces the limit itself (NO `MaxBytesReader`, never touching `w`):
```go
type bodyResult struct {
	data   []byte
	tooBig bool
	err    error
}

// readPacedBodyLimited reads body in ≤ChunkSize slices, pacing each slice against the up-bucket, and
// enforces the byte limit ITSELF (returning tooBig) so the caller never wraps w in a MaxBytesReader
// from this goroutine — a timeout path that abandons the goroutine must not race the ResponseWriter.
func readPacedBodyLimited(ctx context.Context, body io.Reader, bucket *limit.TokenBucket, limit int64) (data []byte, tooBig bool, err error) {
	var buf bytes.Buffer
	tmp := make([]byte, wire.ChunkSize)
	for {
		n, rerr := body.Read(tmp)
		if n > 0 {
			if werr := bucket.WaitN(ctx, n); werr != nil {
				return nil, false, werr
			}
			if int64(buf.Len())+int64(n) > limit {
				return nil, true, nil
			}
			buf.Write(tmp[:n])
		}
		if errors.Is(rerr, io.EOF) {
			return buf.Bytes(), false, nil
		}
		if rerr != nil {
			return nil, false, rerr
		}
	}
}
```
- [x] **Action** — modify `internal/ingress/handler.go`, `ServeHTTP` body-read section: drop the `MaxBytesReader`, launch the limited reader, and on the timeout branch close the body (which unblocks the goroutine — it writes to the buffered channel and exits, never touching `w`), then map `tooBig`/errors:
```go
up, _ := h.buckets.Pair(name)
bodyCh := make(chan bodyResult, 1)
go func() {
	data, tooBig, rerr := readPacedBodyLimited(reqCtx, r.Body, up, h.bodyLimit)
	bodyCh <- bodyResult{data: data, tooBig: tooBig, err: rerr}
}()

var body []byte
select {
case <-reqCtx.Done():
	_ = r.Body.Close()
	if errors.Is(context.Cause(reqCtx), context.Canceled) || errors.Is(r.Context().Err(), context.Canceled) {
		// Client aborted (parent request context cancelled) — not a cap-hit; no Reject.
		return
	}
	h.rec.Reject("body_read_timeout", name, ipStr)
	h.writeStatus(w, http.StatusRequestTimeout)
	return
case res := <-bodyCh:
	if res.err != nil {
		switch {
		case errors.Is(res.err, context.Canceled):
			return // client abort during a paced read — not a cap-hit
		case errors.Is(res.err, context.DeadlineExceeded):
			h.rec.Reject("body_read_timeout", name, ipStr)
			h.writeStatus(w, http.StatusRequestTimeout)
		default:
			h.writeStatus(w, http.StatusBadRequest)
		}
		return
	}
	if res.tooBig {
		h.rec.Reject("body_too_large", name, ipStr)
		h.writeStatus(w, http.StatusRequestEntityTooLarge)
		return
	}
	body = res.data
}
```
- [x] **Context (ING-015):** `reqCtx` derives from `r.Context()`. Distinguishing `context.Canceled` (client gone) from `context.DeadlineExceeded` (real timeout) removes the mislabelled `body_read_timeout` cap-hit. If `context.Cause` is not convenient, gate on `r.Context().Err() == context.Canceled` for the parent-cancel case and `errors.Is(res.err, context.Canceled)` for the read-side case.
- [x] **DoD:** an over-limit or timed-out body never triggers a concurrent write to `w`; a client abort is not recorded as a cap-hit; `race` detector is clean under a slow/over-limit body test (US18).

### Task 5.2 — [x] Log Redis errors on the limiter path
- [x] **Action** — modify `internal/ingress/handler.go`: in each of the three `err != nil → h.serverError(w)` branches (rps, rpm, `Acquire`), log first with identifiers. Change `h.serverError` to accept context, or add logging inline:
```go
if allowed, retry, err := limit.Allow(r.Context(), h.rdb, "rps", ip, h.cfg.LimitRPS, time.Second); err != nil {
	h.log.Warn("rps limit check failed", "name", name, "ip", ipStr, "err", err)
	h.serverError(w)
	return
} else if !allowed {
	h.rateLimited(w, name, ipStr, "rate_rps", retry)
	return
}
```
Apply the same `h.log.Warn(...)` (scope `"rpm"` / `"concurrency"`) to the rpm and `Acquire` branches.
- [x] **DoD:** a Redis outage on the limiter path emits an actionable Warn per branch; the 500 is unchanged.

### Task 5.3 — [x] Strip `Connection`-nominated hop-by-hop headers
- [x] **Action** — modify `internal/ingress/headers.go`: in BOTH `Sanitize` and `SanitizeResponse`, before dropping, collect the set of field names named by the `Connection` header and drop those too.
```go
// connectionNominated returns the canonicalised set of header names listed in the Connection header
// value (RFC 9110 §7.6.1 connection-scoped headers), which MUST NOT be forwarded across the hop.
func connectionNominated(in http.Header) map[string]struct{} {
	named := map[string]struct{}{}
	for _, v := range in.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				named[http.CanonicalHeaderKey(tok)] = struct{}{}
			}
		}
	}
	return named
}
```
In `Sanitize`'s copy loop add, alongside the `hopByHop` check: `if _, nom := nominated[ck]; nom { continue }` (where `nominated := connectionNominated(in)` is computed once before the loop). Mirror the same in `SanitizeResponse`.
- [x] **DoD:** a request with `Connection: X-Custom` + `X-Custom: v` forwards neither `Connection` nor `X-Custom`; same for a phone response.

### Task 5.4 — [x] Case-insensitive Host→name (`firstLabel`)
- [x] **Action** — modify `internal/ingress/handler.go`, `firstLabel`: lowercase the extracted label. After stripping port and trailing dot, `host = strings.ToLower(host)` before extracting the first label (so `NAME.tunnel-domain` resolves to the lowercase route key). Return `strings.ToLower(host[:i])` / `strings.ToLower(host)`.
- [x] **DoD:** an uppercased Host resolves to the same `route:{name}` as the lowercase form.

---

## US6 — [x] Enroll handler race fix

**Why:** The enroll CSR read has the identical unjoined-goroutine `MaxBytesReader` race as the public
path — a fatal concurrent-map-write crash triggerable by a dribbled over-limit body (AUTH-001).

**Acceptance criteria:**
- [x] The CSR read never wraps `w` in a `MaxBytesReader` from the unjoined goroutine.
- [x] The `413`/timeout/`400` outcomes are preserved.

### Task 6.1 — [x] Race-free CSR read
- [x] **Action** — add to `internal/ingress` a small helper (place in `enroll.go`):
```go
// readAllLimited reads up to limit+1 bytes and reports tooBig if the source exceeds limit. It never
// touches the ResponseWriter, so a caller that abandons this read on timeout cannot race w.
func readAllLimited(r io.Reader, limit int64) (data []byte, tooBig bool, err error) {
	data, err = io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return nil, true, nil
	}
	return data, false, nil
}
```
- [x] **Action** — modify `internal/ingress/enroll.go`, `ServeHTTP`: replace the `MaxBytesReader` + goroutine block with the helper-based read (same timeout `select`, closing `r.Body` on timeout):
```go
type readRes struct {
	data   []byte
	tooBig bool
	err    error
}
ch := make(chan readRes, 1)
go func() {
	d, tooBig, e := readAllLimited(r.Body, h.bodyLimit)
	ch <- readRes{d, tooBig, e}
}()
var body []byte
select {
case <-ctx.Done():
	_ = r.Body.Close()
	h.rec.Reject("body_read_timeout", "", ipStr)
	http.Error(w, "request timeout", http.StatusRequestTimeout)
	return
case res := <-ch:
	if res.err != nil {
		if errors.Is(res.err, context.DeadlineExceeded) || errors.Is(res.err, context.Canceled) {
			h.rec.Reject("body_read_timeout", "", ipStr)
			http.Error(w, "request timeout", http.StatusRequestTimeout)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if res.tooBig {
		h.rec.Reject("enroll_body_too_large", "", ipStr)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	body = res.data
}
```
- [x] **Action** — drop the now-unused `*http.MaxBytesError` handling and the `limited := http.MaxBytesReader(...)` line; keep the `"io"` and `"errors"` imports.
- [x] **DoD:** the enroll timeout path never races `w`; `413` (`enroll_body_too_large`) still fires for an over-limit CSR.

---

## US7 — [x] Host-dispatch normalization in the mux

**Why:** `server.NewMux` compares the enroll host case-sensitively and does not strip a trailing dot,
unlike the two sibling parsers on the same path (`ingress.firstLabel`, `wsconn.hostLabel`) — a valid
`Host: Enroll.example.test` or `enroll.example.test.` is mis-dispatched (OPS-007).

**Acceptance criteria:**
- [x] `hostOnly` strips the trailing dot and folds case, matching the sibling parsers (OPS-007).

### Task 7.1 — [x] Normalise `hostOnly`
- [x] **Action** — modify `internal/server/routes.go`, `hostOnly`:
```go
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
```
- [x] **Action** — add `"strings"` to the `internal/server/routes.go` imports; ensure the `EnrollHost` comparison remains `hostOnly(r.Host) == cfg.EnrollHost` (default enroll host is already lowercase).
- [x] **DoD:** `Enroll.example.test`, `enroll.example.test.`, and `enroll.example.test:443` all dispatch to the enroll branch.

---

## US8 — [x] `/connect` handshake hardening

**Why:** Bind uses the request context rather than the connection lifetime (AUTH-002); the CN check
runs on an under-validated Host label with no tunnel-domain suffix check (AUTH-003); the per-IP
connect rate-limit Redis call runs unbounded ahead of the pre-auth semaphore (AUTH-004, operator
decision: semaphore first); the AUTH cert has no size cap distinct from the WS read limit (AUTH-005).

**Acceptance criteria:**
- [x] `Bind` uses a connection-lifetime context, consistent with `Unbind`/`Heartbeat` (AUTH-002).
- [x] The Host's suffix is verified to equal `.<tunnel-domain>` before/at authentication (AUTH-003).
- [x] The pre-auth semaphore is acquired BEFORE the per-IP connect rate-limit Redis call; ban stays FIRST; a 429 releases the slot (AUTH-004).
- [x] The decoded AUTH cert DER is bounded to a small cap before `x509.ParseCertificate` (AUTH-005).

### Task 8.1 — [x] Reorder: semaphore before connect rate-limit (ban stays first)
- [x] **Action** — modify `internal/wsconn/manager.go`, `HandleConnect`: move the pre-auth semaphore acquisition to immediately AFTER the ban check and BEFORE `limit.Allow("connect", …)`; ensure `releaseSlot`/`defer releaseSlot()` are established before the rate check so the 429 return releases the slot.
```go
if src, banned := m.ban.Match(ip); banned {
	m.rec.Reject(src.Reason.String(), "", ip.String())
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}
// Pre-auth semaphore FIRST (after the SACRED ban check): bound ALL unauthenticated /connect work —
// including the per-IP rate-limit Redis round trip below — to --limit-connect-pending concurrent
// (docs/PROTOCOL.md §2).
select {
case m.connectSem <- struct{}{}:
default:
	m.rec.Reject("connect_pending", "", ip.String())
	http.Error(w, "server busy", http.StatusServiceUnavailable)
	return
}
slotReleased := false
releaseSlot := func() {
	if !slotReleased {
		slotReleased = true
		<-m.connectSem
	}
}
defer releaseSlot()

allowed, _, err := limit.Allow(r.Context(), m.rdb, "connect", ip, m.cfg.LimitRPM, time.Minute)
if err != nil {
	m.log.Warn("connect rate check failed", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
	return
}
if !allowed {
	m.rec.Reject("rate_connect", "", ip.String())
	http.Error(w, "too many requests", http.StatusTooManyRequests)
	return
}
```
Everything from `if !isWebSocketUpgrade(r)` onward is unchanged (the existing `releaseSlot()` after `authenticate` still applies).
- [x] **DoD:** the ban check is still the first handler-level check; the semaphore bounds concurrent connect work including the Redis call; a `429`/`503`/`400` all release the slot.

### Task 8.2 — [x] Bind on the connection lifetime
- [x] **Action** — modify `internal/wsconn/manager.go`, `HandleConnect`: allocate `connCtx` BEFORE `Bind`, and bind on `connCtx` (not `r.Context()`), matching `Unbind`/`Heartbeat`.
```go
connID := randID()
connCtx, cancel := context.WithCancel(m.baseCtx)
if err := m.registry.Bind(connCtx, name, m.nodeID, fp, connID); err != nil {
	cancel()
	if errors.Is(err, router.ErrNameHeldByOther) {
		m.rec.Reject("fingerprint_conflict", name, ip.String())
		m.log.Warn("fingerprint conflict on /connect", "name", name)
		_ = c.Close(closeConflict, "fingerprint conflict")
		return
	}
	m.log.Warn("bind failed", "name", name, "err", err)
	_ = c.Close(websocket.StatusInternalError, "bind failed")
	return
}

up, down := m.buckets.Pin(name)
conn := &Conn{
	name: name, fp: fp, connID: connID,
	ws: c, mgr: m, up: up, down: down,
	ctx: connCtx, cancel: cancel,
}
```
(The `connCtx, cancel := context.WithCancel(m.baseCtx)` line that previously sat after `Pair` is now moved above `Bind`; remove the duplicate.)
- [x] **DoD:** the route's Redis lifetime is tied to the WS connection, not the HTTP request; a request-context cancel after a successful bind does not orphan the route.

### Task 8.3 — [x] Host-suffix validation for the CN check
- [x] **Action** — modify `internal/wsconn/manager.go`: add a Host-suffix check in `HandleConnect` (BEFORE `websocket.Accept`) verifying the Host's suffix equals `.<tunnel-domain>` (case-folded, port/dot-stripped), rejecting `404` otherwise. Add a helper and the check:
```go
func hostSuffixOK(host, tunnelDomain string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == tunnelDomain || strings.HasSuffix(host, "."+tunnelDomain)
}
```
In `HandleConnect`, after `isWebSocketUpgrade` and before/after `hostLabel`, reject a Host whose suffix is not the tunnel domain:
```go
if !hostSuffixOK(r.Host, m.cfg.TunnelDomain) {
	http.Error(w, "unknown host", http.StatusNotFound)
	return
}
```
(Place this before `websocket.Accept`; it is fail-closed and needs no WS.)
- [x] **DoD:** `Host: name.attacker.example` is rejected `404` before the upgrade even if `name` would match a CN; `name.<tunnel-domain>` proceeds.

### Task 8.4 — [x] Bound the AUTH cert DER
- [x] **Action** — modify `internal/wsconn/manager.go`, `authenticate`: reject an oversized decoded cert before parsing. Add `const maxAuthCertDER = 4096` (a P-256 leaf is well under 1 KiB) at package scope, and after decoding `auth.Cert`:
```go
der, err := base64.StdEncoding.DecodeString(auth.Cert)
if err != nil {
	return "", "", err
}
if len(der) > maxAuthCertDER {
	return "", "", errors.New("auth cert too large")
}
cert, err := x509.ParseCertificate(der)
if err != nil {
	return "", "", err
}
```
Replace the current `ca.ParseCertB64DER(auth.Cert)` call with the explicit decode+size-check+parse (or add a `ca.ParseCertB64DERLimited(b64 string, max int)` variant and call it). Prefer adding the variant to `internal/ca/verify.go` to keep the decode in one place:
```go
// ParseCertB64DERLimited decodes and parses a base64-DER certificate, rejecting a decoded length
// above maxDER before parsing (bounds per-handshake x509 parse cost).
func ParseCertB64DERLimited(b64 string, maxDER int) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64 cert: %w", err)
	}
	if len(der) > maxDER {
		return nil, fmt.Errorf("certificate DER too large: %d > %d", len(der), maxDER)
	}
	return x509.ParseCertificate(der)
}
```
and call `ca.ParseCertB64DERLimited(auth.Cert, maxAuthCertDER)` from `authenticate`.
- [x] **DoD:** an AUTH frame with a >4 KiB cert blob is rejected before `x509.ParseCertificate`.

---

## US9 — [x] WS data-plane correctness

**Why:** Over-cap response chunks are drained unpaced/unaccounted after the request resolves —
bandwidth-cap bypass (DP-003, operator decision: pace + account the drain); a ban reload firing
between the auth-time ban check and `conns.Store` never evicts the new conn (DP-002); a mid-send
deadline is misreported as `502 tunnel_offline` instead of `504` (DP-004); the self-heal `Bind` on
`missing` is fingerprint-only and can clobber a newer live connection (DP-006); an oversized chunk
(`ErrBurstExceeded`) is mislabelled `shutdown` (DP-010); `teardown`'s `Unbind` runs with no timeout
and swallows errors, and `serveOne`/heartbeat swallow errors silently (DP-011).

**Acceptance criteria:**
- [x] Every RESPONSE_BODY_CHUNK is paced + byte-accounted, including chunks after the response is resolved over-cap or for an unknown reqid (DP-003).
- [x] A ban that lands during connect is re-checked after `conns.Store`; a now-banned conn is torn down (DP-002).
- [x] A per-message deadline expiry mid-send yields `504` (nil), not `502 tunnel_gone` (DP-004).
- [x] The self-heal `Bind` on `missing` is connID/absence-conditional in one Lua script (DP-006).
- [x] An oversized-chunk `ErrBurstExceeded` tears down with a distinct reason + Warn log (DP-010).
- [x] `teardown`'s `Unbind` is time-bounded and logs failures; heartbeat/serveOne decode errors are logged (DP-011).

### Task 9.1 — [x] Pace + account all response chunks (over-cap drain)
- [x] **Action** — modify `internal/wsconn/conn.go`, `readPump` `case wire.RESPONSE_BODY_CHUNK`: move the pace + accounting ABOVE the `inf == nil` check so every chunk is paced/accounted; distinguish the WaitN error class:
```go
case wire.RESPONSE_BODY_CHUNK:
	rid := wire.FrameReqID(hdr)
	// Pace + account EVERY response chunk before dispatch/drop, so the per-tunnel bandwidth cap and
	// byte accounting hold even while draining bytes the client will never receive (an over-cap or
	// aborted response) — docs/ARCHITECTURE.md §4.
	if err := c.down.WaitN(c.ctx, len(body)); err != nil {
		if errors.Is(err, limit.ErrBurstExceeded) {
			c.mgr.log.Warn("oversized response chunk exceeds bandwidth burst; tearing down", "tunnel", c.name, "bytes", len(body))
			return "oversized_frame"
		}
		return "shutdown"
	}
	c.mgr.rec.Bytes(c.name, "in", int64(len(body)))
	inf := c.get(rid)
	if inf == nil {
		continue // unknown/aborted/over-cap reqid: bytes already paced+accounted; drop the payload
	}
	if int64(inf.body.Len())+int64(len(body)) > c.mgr.responseLimit {
		c.mgr.rec.Reject("response_too_large", c.name, "")
		c.resolve(rid, &wire.RespEnvelope{ReqID: rid, Status: http.StatusBadGateway, Err: "response too large", ErrCode: "response_too_large"})
		continue
	}
	inf.body.Write(body)
```
- [x] **Action** — add `"errors"` and the `limit` import (`.../internal/limit`) to `internal/ingress`… no — to `internal/wsconn/conn.go`. `limit` is already imported there; add `"errors"`.
- [x] **DoD:** with `--limit-response` small, a large response is fully paced (not drained at wire speed) and every received byte is accounted; an oversized single chunk tears down with reason `oversized_frame` + a Warn.

### Task 9.2 — [x] Re-check bans after `conns.Store`
- [x] **Action** — modify `internal/wsconn/manager.go`, `HandleConnect`: after `m.conns.Store(name, conn)` and the existing `m.closed.Load()` shutdown re-check, add a ban re-check mirroring the shutdown pattern:
```go
m.conns.Store(name, conn)
m.rec.WSConnect()
if m.closed.Load() {
	conn.teardown("shutdown")
	return
}
// Close the ban-reload race: a reload firing between the auth-time MatchTunnel and this Store could
// have missed this conn in EvictBanned's Range; re-check against the CURRENT snapshot and drop it
// here so a newly-banned tunnel never stays connected (docs/ARCHITECTURE.md §3).
if src, banned := m.ban.MatchTunnel(name, fp); banned {
	conn.teardown(src.Reason.String())
	return
}
conn.serve()
```
- [x] **DoD:** a ban applied during the connect window evicts the conn immediately after Store rather than waiting for the next reload.

### Task 9.3 — [x] Correct 504-vs-502 on a mid-send deadline
- [x] **Action** — modify `internal/wsconn/conn.go`, `Do`: on the send legs (`REQUEST_HEAD`, chunk `WaitN`, chunk `write`, `REQUEST_END`), when the failure is the per-message ctx expiring/cancelling, return `nil` (→ frontend 504) rather than `synthErr(..., "tunnel_gone")` (→ 502). Introduce a helper and use it at each send failure:
```go
// sendResult maps a send-leg error to the response the frontend should see: a per-message ctx
// deadline/cancel is a timeout (nil → 504), any other write failure is a dead tunnel (502).
func (c *Conn) sendFailure(ctx context.Context, reqid string) *wire.RespEnvelope {
	if ctx.Err() != nil {
		return nil // deadline/cancel → frontend maps to 504 (matches the post-END select arm)
	}
	return synthErr(reqid, "tunnel_gone")
}
```
Replace each `return synthErr(req.ReqID, "tunnel_gone")` inside `Do`'s send path with `return c.sendFailure(ctx, req.ReqID)`.
- [x] **DoD:** a large paced upload that exceeds the request timeout mid-send yields `504` (not `502 tunnel_offline`); a genuine write failure on a live-ctx still yields `502 tunnel_gone`.

### Task 9.4 — [x] connID/absence-conditional self-heal bind
- [x] **Action** — modify `internal/router/registry.go`: add a Lua script + method `BindIfAbsentOrOwner(ctx, name, node, fp, connID)` that sets `route:{name}` only if the key is absent OR its stored `connID` matches, returning a three-state result (bound / not-owner / conflict-fingerprint). Model it on the existing `bindScript`/`heartbeatScript`, setting the TTL in the same script.
```go
// selfHealScript binds route:{name} ONLY if the key is absent, or is still owned by this connID
// (same-fingerprint). A key owned by a DIFFERENT connID/fingerprint is left untouched (not-owner),
// so a stale conn's self-heal can never clobber a newer connection's route. TTL is set in-script.
var selfHealScript = redis.NewScript(`
local v = redis.call('HMGET', KEYS[1], 'node', 'fingerprint', 'connID')
if v[1] == false then
  redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3])
  redis.call('PEXPIRE', KEYS[1], ARGV[4])
  return 'bound'
end
if v[2] ~= ARGV[2] then
  return 'conflict'
end
if v[3] ~= ARGV[3] then
  return 'not-owner'
end
redis.call('HSET', KEYS[1], 'node', ARGV[1], 'fingerprint', ARGV[2], 'connID', ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return 'bound'
`)
```
Add a NEW result enum `SelfHealResult` with constants `SelfHealBound` / `SelfHealNotOwner` / `SelfHealConflict`, and the method `BindIfAbsentOrOwner(ctx, name, node, fp, connID) (SelfHealResult, error)` that runs `selfHealScript` and maps `'bound'`→`SelfHealBound`, `'not-owner'`→`SelfHealNotOwner`, `'conflict'`→`(SelfHealConflict, ErrNameHeldByOther)`. The `heartbeat.go` code below references `router.SelfHealNotOwner` and `router.ErrNameHeldByOther`, so BOTH MUST be defined (do NOT reuse the `Heartbeat*` enum).
- [x] **Action** — modify `internal/wsconn/heartbeat.go`, `heartbeatOnce` `case router.HeartbeatMissing`: call the new conditional bind instead of the unconditional `Bind`:
```go
case router.HeartbeatMissing:
	res, err := c.mgr.registry.BindIfAbsentOrOwner(c.ctx, c.name, c.mgr.nodeID, c.fp, c.connID)
	switch {
	case res == router.SelfHealNotOwner || errors.Is(err, router.ErrNameHeldByOther):
		c.teardown("superseded")
		return true
	case err != nil:
		c.mgr.log.Warn("heartbeat self-heal bind failed", "tunnel", c.name, "err", err)
		return false
	default:
		return false
	}
```
- [x] **DoD:** a stale conn's `missing` self-heal cannot overwrite a route now owned by a different connID; it tears itself down as `superseded` instead.

### Task 9.5 — [x] Time-bound + log lifecycle Redis calls
- [x] **Action** — modify `internal/wsconn/conn.go`, `teardown`: bound `Unbind` with a short timeout and log a failure:
```go
uctx, ucancel := context.WithTimeout(context.Background(), 5*time.Second)
if err := c.mgr.registry.Unbind(uctx, c.name, c.connID); err != nil {
	c.mgr.log.Warn("route unbind on teardown failed", "tunnel", c.name, "err", err)
}
ucancel()
```
(Add `"time"` to `conn.go` imports.)
- [x] **Action** — the heartbeat self-heal generic-error Warn (`c.mgr.log.Warn("heartbeat self-heal bind failed", "tunnel", c.name, "err", err)`) is already folded into Task 9.4's `heartbeatOnce` switch block — no separate edit here; ensure it is present.
- [x] **Action** — modify `internal/transport/transport.go`, `serveOne`: log an undecodable request envelope: `rec` has no logger; add a `log *slog.Logger` parameter to `ServeNode`/`serveOne` (thread it from `server.Run`) and `log.Warn("dropping undecodable request envelope", "err", err)`. (This parameter addition also serves US11's readiness callback — do both in one signature change.) Add `"log/slog"` to the `internal/transport/transport.go` imports.
- [x] **DoD:** teardown `Unbind` cannot block indefinitely and logs failures; envelope-decode drops and heartbeat bind errors are visible in logs.

---

## US10 — [x] Wire codec error handling

**Why:** The `wire` decode helpers discard `json.Unmarshal` errors with no documented justification,
and phone-side `DecodeReqHeader` silently converts a corrupt header into a `GET /` request (DP-012).

**Acceptance criteria:**
- [x] The decode helpers return the decode error (callers apply the documented drop rule explicitly), or the `_ =` discard is justified with a `docs/PROTOCOL.md` citation (DP-012).

### Task 10.1 — [x] Surface the harmful decode error; justify the benign zero-value drops
- [x] **Action** — modify `internal/wire/frame.go`, `DecodeReqHeader`: return an `error` instead of fabricating a `GET /` request on a bad header (this is the one genuinely harmful silent path — a corrupt header would otherwise be forwarded to the phone backend as `GET /`):
```go
func DecodeReqHeader(header, body []byte) (reqid string, req *http.Request, err error) {
	var h reqHeaderJSON
	if uerr := json.Unmarshal(header, &h); uerr != nil {
		return "", nil, uerr
	}
	u := &url.URL{Path: h.Path, RawQuery: h.RawQuery}
	req, err = http.NewRequest(h.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Host = h.Host
	if h.Header != nil {
		req.Header = h.Header
	}
	req.ContentLength = int64(len(body))
	return h.ReqID, req, nil
}
```
- [x] **Action** — update the phone-side `DecodeReqHeader` call site `internal/tunneltest/fakephone.go` to the 3-return form and drop the frame when `err != nil`. (The `client/client.go` call site is created fresh in its 3-return form by US14.1's `handleOne` rewrite — no separate change is made here, avoiding a forward reference.)
- [x] **Action** — modify `internal/wire/frame.go`: keep `FrameReqID`, `DecodeRespHeader`, and `DecodeErrorHeader` at their CURRENT signatures (unchanged — they are used across the read-pump/demux as single-/multi-value returns; changing them would ripple through US9.1 and US14.1 call sites for no behavioral gain). Replace each bare `_ = json.Unmarshal(...)` with a justification comment citing the drop rule, e.g. `// A malformed header yields a zero-value reqid/status; per docs/PROTOCOL.md §3 an unknown/stale reqid frame is dropped by the read-pump and an out-of-range status is clamped to 502 — the zero value IS the documented drop, not a silent failure.`
- [x] **Context:** on-wire bytes are unchanged (decode-side only) — the golden fixtures do NOT change. `FrameReqID` stays single-return, so US9.1's `rid := wire.FrameReqID(hdr)` and US14.1's `wire.FrameReqID(hdr)` call sites need no change.
- [x] **DoD:** phone-side `DecodeReqHeader` drops a corrupt request header instead of forwarding a fabricated `GET /`; every remaining `_ = json.Unmarshal` in `internal/wire` carries a `docs/PROTOCOL.md`-citing justification; the golden-fixture tests are untouched.

---

## US11 — [x] Transport readiness & client-abort discrimination

**Why:** `ServeNode` never confirms its `req:{nodeID}` subscription and the public listener starts
accepting concurrently, so a request published in the startup window is silently lost → user-visible
504s on every deploy (DP-005). `RoundTrip` maps a client-abort (parent-ctx cancel) to `ErrTimeout`,
inflating the timeout metric (DP-015).

**Acceptance criteria:**
- [x] The public listener does not accept until `req:{nodeID}` is confirmed subscribed (DP-005).
- [x] A public-client abort during the round trip is not counted as a timeout (DP-015).

### Task 11.1 — [x] Confirm subscription before accepting public traffic
- [x] **Action** — modify `internal/transport/transport.go`, `ServeNode`: confirm the subscription with `pubsub.Receive(ctx)` before the loop and signal readiness via a callback param:
```go
func ServeNode(ctx context.Context, rdb redis.UniversalClient, nodeID string, timeout time.Duration, rec observ.Recorder, log *slog.Logger, ready func(), handle func(context.Context, *wire.ReqEnvelope) *wire.RespEnvelope) error {
	pubsub := rdb.Subscribe(ctx, "req:"+nodeID)
	defer func() { _ = pubsub.Close() }()
	if _, err := pubsub.Receive(ctx); err != nil {
		return err // subscription not confirmed — fail startup rather than silently drop requests
	}
	if ready != nil {
		ready()
	}
	ch := pubsub.Channel()
	for {
		...
		go serveOne(ctx, rdb, timeout, rec, log, handle, payload)
	}
}
```
(Thread `log` through `serveOne` per US9.5.)
- [x] **Action** — modify `internal/server/server.go`, `Run`: gate the public listener on node readiness.
```go
nodeReady := make(chan struct{})
var readyOnce sync.Once
ready := func() { readyOnce.Do(func() { close(nodeReady) }) }

g.Go(func() error {
	return transport.ServeNode(drainCtx, rdb, nodeID, cfg.LimitRequestTimeout, rec, logger, ready, manager.RouteLocal)
})
g.Go(func() error {
	select {
	case <-nodeReady:
	case <-gctx.Done():
		return nil // shutting down before the node was ready
	}
	return serveHTTP(publicSrv)
})
g.Go(func() error { return serveHTTP(internalSrv) })
```
(Add `"sync"` to `server.go` imports. The internal listener — `/healthz`, `/metrics` — may start immediately; only the public listener, which hosts `/connect` and public ingress, gates on readiness.)
- [x] **Action** — modify `internal/transport/transport_test.go`: update the direct `serveOne(...)` call in `TestServeNodeRecordsPublishError` to pass a logger argument matching the new `serveOne` signature (US9.5 + this task), so the `transport` test package compiles.
- [x] **DoD:** a request routed to a freshly-started replica is never dropped in the subscription window; startup fails fast if the subscription cannot be confirmed.

### Task 11.2 — [x] Client-abort ≠ timeout in `RoundTrip`
- [x] **Action** — modify `internal/transport/transport.go`, `RoundTrip`: on `deadline.Done()`, distinguish a parent-ctx cancel (client gone) from a real deadline:
```go
case <-deadline.Done():
	// reqCtx (ctx) is itself a WithTimeout of the same budget, so a genuine end-to-end timeout
	// surfaces here with ctx.Err() == DeadlineExceeded — that MUST still be ErrTimeout → 504. Only a
	// parent-context CANCEL (client gone) is reclassified.
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, context.Canceled // client aborted — caller skips the timeout metric
	}
	return nil, ErrTimeout
```
- [x] **Action** — modify `internal/ingress/handler.go`, the `RoundTrip` error handling: treat `context.Canceled` as a client abort (no `rec.Timeout()`, no `Reject("timeout")`, no body write):
```go
resp, err := transport.RoundTrip(reqCtx, h.rdb, node, env, h.cfg.LimitRequestTimeout)
if err != nil {
	switch {
	case errors.Is(err, context.Canceled):
		return // client aborted mid-round-trip — not a timeout
	case errors.Is(err, transport.ErrTimeout):
		h.rec.Timeout()
		h.rec.Reject("timeout", name, ipStr)
		h.writeStatus(w, http.StatusGatewayTimeout)
		return
	default:
		h.rec.PublishError()
		h.writeStatus(w, http.StatusBadGateway)
		return
	}
}
```
- [x] **DoD:** a public client that disconnects during the round trip does not increment `tunneld_request_timeouts_total` or the `timeout` rejection counter.

---

## US12 — [x] Metrics, admin & logging robustness

**Why:** `PromRecorder.flush` discards Redis errors AND the drained deltas with no log (OPS-008); the
final shutdown flush runs on `context.Background()` with no deadline (OPS-009); a misconfigured `--log`
file path is never opened at startup and write failures vanish (OPS-010); `/admin/tunnels` `TopN` has
no key dedup and no empty-hash filtering (OPS-011).

**Acceptance criteria:**
- [x] `flush` logs each failed `Incr` with identifiers (OPS-008).
- [x] The final shutdown flush is time-bounded (OPS-009).
- [x] A file log sink is probed at startup and a failure fails fast (OPS-010).
- [x] `TopN` de-duplicates keys and skips empty hashes (OPS-011).

### Task 12.1 — [x] Log flush errors; give the recorder a logger
- [x] **Action** — modify `internal/metrics/recorder.go`: add a `log *slog.Logger` field to `PromRecorder` and `NewPromRecorder`; in `flush`, log each failed `Incr`:
```go
if e.requests != 0 {
	if err := p.admin.Incr(ctx, name, "requests", e.requests); err != nil {
		p.log.Warn("admin counter flush failed", "tunnel", name, "field", "requests", "err", err)
	}
}
```
(mirror for `bytes_in`/`bytes_out`.) Add `"log/slog"` to the `internal/metrics/recorder.go` imports.
- [x] **Action** — modify `internal/server/server.go`, `Run`: pass `logger` to `NewPromRecorder`.
- [x] **Action** — modify `internal/metrics/metrics_test.go`: update the `setup()` helper's `NewPromRecorder(...)` call to pass a discard/no-op logger, so the `metrics` test package compiles against the new 4-arg signature.
- [x] **DoD:** a Redis failure during flush emits an actionable Warn per field.

### Task 12.2 — [x] Bound the shutdown flush
- [x] **Action** — modify `internal/metrics/recorder.go`, `RunFlusher`: replace `p.flush(context.Background())` with a bounded context:
```go
case <-ctx.Done():
	fctx, cancel := context.WithTimeout(context.Background(), flushShutdownTimeout)
	p.flush(fctx)
	cancel()
	return ctx.Err()
```
Add `const flushShutdownTimeout = 5 * time.Second` at package scope.
- [x] **DoD:** the final flush cannot block shutdown indefinitely.

### Task 12.3 — [x] Probe file log sinks at startup
- [x] **Action** — modify `internal/logging/logging.go`, `newLogger`: after constructing each lumberjack sink, perform a zero-length `Write` (lumberjack opens lazily) and return an error if it fails, so a bad path fails fast:
```go
lj := &lumberjack.Logger{Filename: s.path, MaxSize: s.maxSizeMB, MaxBackups: s.maxFiles, Compress: false}
if _, werr := lj.Write(nil); werr != nil {
	_ = lj.Close()
	return nil, noopClose, fmt.Errorf("log sink %q not writable: %w", s.path, werr)
}
closers = append(closers, lj)
children = append(children, newLeaf(lj, s))
```
- [x] **Context:** `ParseSpecs` (used by `config.Validate()`) MUST remain side-effect-free — the probe lives only in `New`/`newLogger`, which runs at process start in `main`. A zero-length write creates/opens the file without emitting a log line.
- [x] **DoD:** starting with `--log output=/nonexistent/dir/x.log` fails fast with a clear error instead of silently dropping all logs.

### Task 12.4 — [x] Dedup + filter in `TopN`
- [x] **Action** — modify `internal/admin/tunnels.go`, `TopN`: track seen keys across SCAN pages and skip an empty `HGETALL`:
```go
seen := map[string]struct{}{}
...
for _, k := range keys {
	if _, dup := seen[k]; dup {
		continue
	}
	seen[k] = struct{}{}
	h, err := s.rdb.HGetAll(ctx, k).Result()
	if err != nil {
		return nil, err
	}
	if len(h) == 0 {
		continue // key expired between SCAN and HGETALL — skip the phantom
	}
	stats = append(stats, TunnelStat{...})
}
```
- [x] **DoD:** `/admin/tunnels` never double-counts a key delivered twice by SCAN, nor lists an all-zero phantom.

---

## US13 — [x] CA defense-in-depth & enroll-host reservation

**Why:** `VerifyEnrolledCert` accepts `ExtKeyUsageAny` and does not assert `!IsCA` / digital-signature
key usage (AUTH-007); the reserved-label guard is not fed the configured enroll host and
`--enroll-host`/`--tunnel-domain` are unvalidated (OPS-012); the reserved-label skip is silently dead
when `--name-prefix` is set (AUTH-006).

**Acceptance criteria:**
- [x] `VerifyEnrolledCert` asserts the leaf is non-CA and carries digital-signature key usage (AUTH-007).
- [x] `--enroll-host` and `--tunnel-domain` are validated non-empty/well-formed; the enroll host's first label is reserved from name generation (OPS-012).
- [x] The reserved-label semantics with a non-empty prefix are documented (AUTH-006).

### Task 13.1 — [x] Assert leaf constraints at verify
- [x] **Action** — modify `internal/ca/verify.go`, `VerifyEnrolledCert`: after `cert.Verify`, assert non-CA + digital signature:
```go
if cert.IsCA {
	return "", "", errors.New("ca: enrolled cert must not be a CA")
}
if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
	return "", "", errors.New("ca: enrolled cert lacks digitalSignature key usage")
}
```
- [x] **DoD:** a CA-flagged cert minted by the same key is rejected at `/connect`.

### Task 13.2 — [x] Validate enroll host / tunnel domain; reserve the enroll label
- [x] **Action** — modify `internal/config/config.go`, `Validate()`: reject empty/degenerate `EnrollHost`/`TunnelDomain` (non-empty, must contain a dot / be a valid host):
```go
if c.TunnelDomain == "" || !strings.Contains(c.TunnelDomain, ".") {
	return fmt.Errorf("--tunnel-domain must be a dotted domain, got %q", c.TunnelDomain)
}
if c.EnrollHost == "" || !strings.Contains(c.EnrollHost, ".") {
	return fmt.Errorf("--enroll-host must be a dotted host, got %q", c.EnrollHost)
}
```
(Add `"strings"` to the `internal/config/config.go` import block.)
- [x] **Action** — modify `internal/ca/name.go`, `GenerateName`: accept an extra reserved label (the enroll host's first label) so a generated name can never shadow the enroll host. Add a variadic `extraReserved ...string` parameter (or a `GenerateNameReserving(prefix string, length int, extra ...string)`), and have `ingress.EnrollHandler` pass `firstLabel(cfg.EnrollHost)`. Skip a candidate whose `prefix+enc[:length]` equals any extra-reserved label, case-folded.
- [x] **Action** — modify `internal/ca/name.go`: make the random source injectable via an unexported seam so tests can force a reserved-label collision and the 8-attempt exhaustion path — keep `GenerateName` delegating to `generateName(prefix string, length int, rnd io.Reader, extra ...string)` with `rnd` defaulting to `rand.Reader` (enables the reserved-skip/exhaustion test). Add `"io"` to the `internal/ca/name.go` imports.
- [x] **Action** — modify the `GenerateName` call site in `internal/ingress/enroll.go` to pass the enroll host's first label.
- [x] **Action** — modify `internal/ca/name.go`: update the `reserved` comment to state that with a non-empty `--name-prefix` the bare-label reservations only match when the prefix is empty (documenting AUTH-006), citing the enroll-host reservation as the prefix-independent guard.
- [x] **DoD:** with any `--enroll-host`, a generated tunnel name can never equal the enroll host's label; an empty OR dot-less `--tunnel-domain`/`--enroll-host` fails `Validate()`.

---

## US14 — [x] Go reference client rework

**Why:** The client dispatches the backend synchronously on the read loop — no multiplexing and pings
go unanswered, so a slow-but-valid request gets the tunnel killed as `dead_peer` (DP-007); the whole
response is buffered despite a "streams" comment and `httptest` is imported by a library package
(DP-014); `Serve` discards the connect error so permanent failures retry forever invisibly (DP-013);
`Enroll` has no client-side P-256 guard (AUTH-010).

**Acceptance criteria:**
- [x] Each `REQUEST_END` is handled in its own goroutine with a client-side write mutex; the read loop always stays in `Read` so pings are answered (DP-007).
- [x] The response is streamed via a custom `http.ResponseWriter` (no `httptest` in the library) (DP-014).
- [x] `Serve` surfaces the per-attempt connect error via an optional logger/callback (DP-013).
- [x] `Enroll` rejects a non-P-256 key locally with a clear error (AUTH-010).

### Task 14.1 — [x] Concurrent bridge with a write mutex
- [x] **Action** — modify `client/client.go`, `bridge`: keep the read loop always reading; on `REQUEST_END`, dispatch in a goroutine; guard all frame writes with a shared `sync.Mutex`; track a `sync.WaitGroup` so `bridge` returns only after in-flight handlers finish. Replace the synchronous `backend.ServeHTTP` + inline writes with a goroutine that writes RESPONSE_HEAD/chunks/END under the mutex. Add `"sync"` to the `client/client.go` imports.
```go
func bridge(ctx context.Context, ws *websocket.Conn, backend http.Handler) error {
	type partial struct{ hdr, body []byte }
	pending := map[string]*partial{}
	var writeMu sync.Mutex
	var wg sync.WaitGroup
	write := func(t wire.FrameType, header, body []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return ws.Write(ctx, websocket.MessageBinary, wire.EncodeFrame(t, header, body))
	}
	defer wg.Wait()
	for {
		typ, hdr, body, err := readFrame(ctx, ws)
		if err != nil {
			return err
		}
		switch typ {
		case wire.REQUEST_HEAD:
			pending[wire.FrameReqID(hdr)] = &partial{hdr: hdr}
		case wire.REQUEST_BODY_CHUNK:
			if pr := pending[wire.FrameReqID(hdr)]; pr != nil {
				pr.body = append(pr.body, body...)
			}
		case wire.REQUEST_END:
			reqid := wire.FrameReqID(hdr)
			pr := pending[reqid]
			if pr == nil {
				continue
			}
			delete(pending, reqid)
			wg.Add(1)
			go func(reqid string, pr *partial) {
				defer wg.Done()
				handleOne(ctx, write, backend, reqid, pr.hdr, pr.body)
			}(reqid, pr)
		default:
			continue
		}
	}
}
```
- [x] **Action** — add a streaming `handleOne` + a custom `http.ResponseWriter` (`wsResponseWriter`) that emits RESPONSE_HEAD on first write and RESPONSE_BODY_CHUNK per ≤ChunkSize slice, then RESPONSE_END — removing the `net/http/httptest` import.
```go
func handleOne(ctx context.Context, write func(wire.FrameType, []byte, []byte) error, backend http.Handler, reqid string, hdr, body []byte) {
	_, req, err := wire.DecodeReqHeader(hdr, body)
	if err != nil {
		return // drop a corrupt request header rather than forwarding a fabricated request
	}
	w := &wsResponseWriter{ctx: ctx, write: write, reqid: reqid, header: http.Header{}, status: http.StatusOK}
	backend.ServeHTTP(w, req)
	w.finish()
}
```
(`wsResponseWriter` implements `Header()`, `WriteHeader`, `Write` (emitting HEAD lazily then chunked bodies), and `finish()` emitting RESPONSE_END; it drops write errors — the read loop surfaces the drop.)
- [x] **Context (DP-007):** writes are already frame-atomic; the mutex mirrors the server's `writeMu`. The read loop never blocks on a handler, so `coder/websocket` control pings are answered within the server's 10 s pong window. If `DecodeReqHeader` now returns an error (US10), handle the drop.
- [x] **DoD:** two concurrent backend requests multiplex; a 15 s handler does not cause a `dead_peer` teardown; `net/http/httptest` is no longer imported by `client`.

### Task 14.2 — [x] Surface connect errors from `Serve`
- [x] **Action** — modify `client/client.go`: add an optional `OnConnectError func(error)` field on `Client` (nil-safe); in `Serve`, capture `err := c.Connect(...)` and, when non-nil and `ctx.Err() == nil`, invoke `c.OnConnectError(err)` (or log via an injected logger). Keep the bounded-backoff loop unchanged.
- [x] **DoD:** a permanent refusal (expired cert, `4403`, `4409`) is observable to the caller rather than silently retried forever.

### Task 14.3 — [x] Client-side P-256 guard in `Enroll`
- [x] **Action** — modify `client/client.go`, `Enroll`: assert the key curve before building the CSR:
```go
if key.Curve != elliptic.P256() {
	return nil, "", errors.New("client: enrollment key must be ECDSA P-256")
}
```
(Add `"crypto/elliptic"` to the imports.)
- [x] **DoD:** a non-P-256 key returns a clear local error before any network call.

---

## US15 — [x] Remove plan-artifact references from all code comments

**Why:** 32 comments across 17 Go files plus `deploy/docker-compose.yml` reference user-story IDs
(`US1`, `US6.2`, `US7 step 8`, …). `agent.md` §1 forbids this absolutely (comments cite ONLY `docs/`).

**Acceptance criteria:**
- [x] No source comment (Go, YAML, shell) contains a `US<n>` / plan / task / action reference (DOC-005/DP-001/DEP-002).
- [x] Where a comment carried load-bearing rationale, it cites the relevant `docs/` section instead.

### Task 15.1 — [x] Sweep and rewrite US-referencing comments
- [x] **Action** — enumerate every occurrence with `grep -rnE 'US[0-9]' --include='*.go' --include='*.yml' --include='*.sh' .` and rewrite each comment to drop the `US<n>` token, substituting a `docs/` citation where the rationale is load-bearing. Known sites (non-exhaustive — the grep is authoritative): `internal/config/config.go` (15-18, 147, 153), `internal/wire/envelope.go` (1-3, 18, 31), `internal/wire/frame.go` (30-31, 98), `internal/ingress/handler.go` (219, 307), `internal/limit/*` (bucket.go 15/19, concurrency.go 13, registry.go 11), `internal/router/registry.go` (111), `internal/wsconn/conn.go` (53), `internal/server/server.go` (71-72, 92), `internal/metrics/recorder.go` (15-16), `internal/observ/recorder.go` (1-4, 9), `internal/admin/tunnels.go` (36, 42), `internal/ban/watch.go` (15), `internal/ca/ca.go` (23), `internal/tunneltest/fakephone.go`, `internal/tunneltest/recorder.go`, `deploy/docker-compose.yml` (125).
- [x] **Action** — modify `deploy/docker-compose.yml:125`: `- ./scripts:/scripts:ro           # droplist/DB-IP fetch scripts (see docs/PROJECT.md §4)`.
- [x] **DoD:** `grep -rnE 'US[0-9]' --include='*.go' --include='*.yml' --include='*.sh' .` returns nothing (excluding this plan and other `docs/plans/` files).

---

## US16 — [x] Deployment & CI hardening (resource protection first)

**Why:** `gen-ca.sh` silently destroys an existing CA on re-run — permanent loss of the only
persistent identity (DEP-001); no `.gitignore` protection for the CA key/secrets (DEP-003); the CA
output dir isn't created (DEP-004); the ops-auth `.env` value is `$`-mangled by Compose interpolation
(DEP-012, verified); `NodeDown` can't fire under `dns_sd` (DEP-006); the release dispatch doesn't
check out its tag (DEP-005); unpinned images/actions/mermaid-cli (DEP-007/008/009); ntfy/bridge ports
implicit (DEP-013); the production Traefik template is validated by no gate (DEP-011); `scripts_test.sh`
leaks temp dirs (DEP-010).

**Acceptance criteria:**
- [x] `gen-ca.sh` refuses to overwrite an existing CA and creates its output dir (DEP-001, DEP-004).
- [x] `.gitignore` protects `deploy/ca/`, `deploy/.env`, `deploy/tunneld.env`, `deploy/logs/` (DEP-003).
- [x] Operator env examples use escaping that survives Compose interpolation; the misleading comment is corrected (DEP-012).
- [x] `NodeDown` uses `static_configs` so a fully-down replica yields `up==0` (DEP-006).
- [x] The release workflow checks out the dispatched tag (DEP-005).
- [x] Ops-stack images, GitHub Actions, and mermaid-cli are pinned (DEP-009, DEP-008, DEP-007).
- [x] ntfy + bridge ports are explicit (DEP-013); the Traefik template gets a render gate (DEP-011); `scripts_test.sh` cleans up (DEP-010).

### Task 16.1 — [x] `gen-ca.sh`: no-clobber + mkdir
- [x] **Action** — modify `deploy/scripts/gen-ca.sh`: create the dir and refuse to overwrite an existing CA.
```sh
set -eu
OUT_DIR="${1:?usage: gen-ca.sh <out-dir>}"
mkdir -p "$OUT_DIR"
if [ -e "$OUT_DIR/ca-key.pem" ] || [ -e "$OUT_DIR/ca.pem" ]; then
  echo "refusing to overwrite an existing CA in $OUT_DIR (remove it explicitly to regenerate)" >&2
  exit 1
fi
umask 077
```
- [x] **DoD:** a second run against a populated dir exits non-zero without touching the existing key/cert; a first run against a missing dir succeeds.

### Task 16.2 — [x] `.gitignore` protection
- [x] **Action** — modify `.gitignore`, append:
```
/deploy/ca/
/deploy/.env
/deploy/tunneld.env
/deploy/logs/
```
- [x] **DoD:** the CA key, secret env files, and logs cannot be accidentally staged.

### Task 16.3 — [x] Compose env escaping + corrected comments
- [x] **Action** — modify `deploy/.env.example`: single-quote the ops-auth value so Compose does not interpolate its `$`, and correct the comment (verified: unquoted `$` in a `.env` value IS interpolated by Compose; single-quoting disables it). Move the inline comments to their own lines.
```
# Ops access
# htpasswd (apr1/bcrypt) — SINGLE-QUOTE so Compose does not interpolate the `$` in the hash.
OPS_BASIC_AUTH='admin:$apr1$changeme'
GRAFANA_ADMIN_PASSWORD=changeme
```
Also move the `CLOUDFLARE_IP_RANGES` trailing comment to its own line (defensive; the space-preceded inline form is stripped correctly today but the own-line form removes the fragility).
- [x] **Action** — modify `deploy/tunneld.env.example`: move the line-1 inline comment to its own line above the value.
- [x] **DoD:** `docker compose --env-file deploy/.env.example -f deploy/docker-compose.yml config` renders `OPS_BASIC_AUTH` as the literal `admin:$apr1$changeme` (verify by inspecting the rendered value).

### Task 16.4 — [x] `NodeDown` via static targets
- [x] **Action** — modify `deploy/prometheus/prometheus.yml`: replace the `dns_sd_configs` block with static targets so a stopped replica still yields `up==0`:
```yaml
scrape_configs:
  - job_name: tunneld
    static_configs:
      - targets: ["tunneld-1:9090", "tunneld-2:9090"]
```
- [x] **Action** — modify `deploy/docker-compose.yml:32-36`: fix the dangling "the Prometheus dns_sd comment calls out" cross-reference (now that `dns_sd` is gone) — reword to reference the per-URL file-provider requirement without the stale pointer.
- [x] **DoD:** stopping `tunneld-1` produces `up{job="tunneld"} == 0` for that target, so `NodeDown` can fire.

### Task 16.5 — [x] Release checks out the dispatched tag
- [x] **Action** — modify `.github/workflows/release.yml`, the `actions/checkout@v4` step: add `ref: ${{ github.event.inputs.tag || github.ref }}`.
- [x] **DoD:** a `workflow_dispatch` with `tag: v1.0.0` builds that tag's commit, not the branch HEAD.

### Task 16.6 — [x] Pin images, actions, and mermaid-cli
- [x] **Action** — modify `deploy/docker-compose.yml`: pin the five `:latest` images (`prom/prometheus`, `prom/alertmanager`, `grafana/grafana`, `binwiederhier/ntfy`, `xenrox/ntfy-alertmanager`) to explicit current tags (the implementer selects the latest stable tag of each at implementation time and records the chosen versions in `## Deviations`).
- [x] **Action** — modify `.github/workflows/ci.yml` AND `.github/workflows/release.yml`: pin EVERY `uses:` action in BOTH workflows to a full commit SHA with the tag in a trailing comment (`actions/checkout`, `actions/setup-go`, `golangci/golangci-lint-action`, `actions/setup-node`, `docker/setup-qemu-action`, `docker/setup-buildx-action`, `docker/login-action`, `goreleaser/goreleaser-action`).
- [x] **Action** — modify `scripts/mermaid-check.sh` and `Makefile` (mermaid-check target): pin `@mermaid-js/mermaid-cli` to an explicit version (`npx --yes @mermaid-js/mermaid-cli@<version> ...`), consistent with the repo's pinning policy.
- [x] **DoD:** no `:latest` image remains; no mutable-tag action remains in EITHER workflow; mermaid-cli is version-pinned.

### Task 16.7 — [x] Explicit ntfy/bridge ports + Traefik render gate + script cleanup
- [x] **Action** — modify `deploy/ntfy/server.yml`: set `listen-http: ":80"` explicitly; modify `deploy/ntfy-alertmanager/config.scfg`: set the bridge's `http-address` explicitly to `:8080` (matching `alertmanager.yml`'s webhook URL) — so the wiring no longer rests on image defaults.
- [x] **Action** — add a Traefik dynamic-config render gate: extend `make compose-config` (or add a `make traefik-config` target invoked by CI's `static-checks`) that renders/loads `deploy/traefik/dynamic.yml` under a `traefik:v3.3` container with placeholder env and fails on a template/parse error. Wire it into `.github/workflows/ci.yml` `static-checks`.
- [x] **Action** — modify `deploy/scripts/scripts_test.sh`: track every `mktemp -d` under one root and remove them in an `EXIT` trap (`trap 'rm -rf "$tmproot"' EXIT`), matching `scripts/mermaid-check.sh`.
- [x] **Action** — modify `deploy/scripts/scripts_test.sh`: add a `gen-ca refuses to clobber an existing CA` case — run `gen-ca.sh` against a dir twice and assert the second run exits non-zero with the original `ca.pem`/`ca-key.pem` bytes unchanged (regression test for US16.1 / DEP-001).
- [x] **DoD:** ntfy + bridge listen on documented ports; a broken Traefik template is caught by a gate; `make test-scripts` leaves no temp dirs behind.

---

## US17 — [ ] Documentation sync

**Why:** README quickstart step 1 fails on a fresh checkout (DOC-001); the `§2` sequence diagram shows
the wrong order of operations (DOC-002); `project.md` points at a non-existent reason-writer list in
ARCHITECTURE §7 (DOC-003); Plan 1 has unrecorded plan-vs-code deviations (DOC-004); the README prebuilt
-image tag wording is wrong given goreleaser strips the `v` prefix (DEP-014, verified). The US8
reorder and US9 behavior changes must be reflected in `PROTOCOL.md`/`ARCHITECTURE.md`.

**Acceptance criteria:**
- [ ] README step 1 works on a fresh checkout (mkdir handled) (DOC-001).
- [ ] The `§2` diagram matches the code's order (lookup + tunnel-ban before allowlist/caps) and validates with `mmdc` (DOC-002).
- [ ] The reason→writer set is documented where `project.md` claims, or the cross-reference is corrected (DOC-003).
- [ ] Plan 1 gains a `## Deviations` section recording module-path, CI-shape, Makefile, and ban-file-wording divergences (DOC-004).
- [ ] The README image-tag guidance states the tag is the version without the leading `v` (DEP-014).
- [ ] `PROTOCOL.md` §2 / `ARCHITECTURE.md` §3 reflect the semaphore-first `/connect` order (US8).

### Task 17.1 — [ ] README fixes
- [ ] **Action** — modify `README.md` step 1: since `gen-ca.sh` now `mkdir -p`s, the command works as-is; update the comment to note the dir is created. Modify the prebuilt-image paragraph: state the image tag is the version WITHOUT the leading `v` (git tag `v1.0.0` → `ghcr.io/danielealbano/tunneld:1.0.0`).
- [ ] **DoD:** README step 1 succeeds on a bare checkout; the image example uses the `v`-stripped tag.

### Task 17.2 — [ ] Fix the `§2` sequence diagram
- [ ] **Action** — modify `docs/ARCHITECTURE.md` §2 Mermaid sequence diagram: place `Lookup route:{name}` and the `MatchTunnel` tunnel-ban gate BEFORE the allowlist/caps/concurrency step, matching the prose and the code.
- [ ] **DoD:** the diagram order equals the prose order; it validates via `mmdc` (US19 Mermaid step).

### Task 17.3 — [ ] Reason→writer documentation
- [ ] **Action** — modify `docs/ARCHITECTURE.md` §7: add the registered rejection-reason label set and its writers (the set is fixed and enumerated in Plan 1 Task 9.1), OR modify `.claude/rules/project.md` to point at the actual location. Prefer adding the table to `§7` so the `project.md` cross-reference becomes true.
- [ ] **DoD:** the `project.md` "the architecture doc lists" claim resolves to real content.

### Task 17.4 — [ ] Record Plan 1 deviations + reflect US8/US9 in the wire/architecture docs
- [ ] **Action** — modify `docs/plans/1_self_hosted_tunnel_server_20260814130404.md`: add a `## Deviations` section (a permitted plan-file edit) recording: module path is `…-tunneld` not `…/tunneld`; CI is `ci.yml` (unfiltered, e2e always-on) not an opt-in `tunnel-ci.yml`; the Makefile is the tiered/3-pass form; and the ban unreadable-file behavior aborts the whole reload (ARCHITECTURE §6 documents the real behavior).
- [ ] **Action** — modify `docs/PROTOCOL.md` §2 and `docs/ARCHITECTURE.md` §3: update the `/connect` pre-upgrade order to ban → pre-auth semaphore → per-IP connect rate → upgrade (US8 reorder), and note the over-cap response is paced+accounted, not dropped at wire speed (US9.1).
- [ ] **DoD:** Plan 1 records the deviations; the wire/architecture docs match the new `/connect` order and drain behavior.

---

## US18 — [ ] Test coverage additions

**Why:** The suite is broad but has real gaps and a few misleading/nondeterministic tests. Each fix
above needs a regression test; several documented behaviors have no coverage at any tier. Tests are
mandatory (`go.md` §3).

**Acceptance criteria:**
- [ ] Every US1–US17 behavior change has a test at the appropriate tier.
- [ ] The e2e proxy edge is actually exercised (TEST-001); misleading/nondeterministic tests are fixed (TEST-004/005/008/010/011/015/024, ING-006).
- [ ] Documented-but-untested behaviors gain coverage (dead-peer, publish-failure, fingerprint-ban revocation, `/admin/tunnels`, golden fixtures, envelope malformed input, etc.).

### Task 18.1 — [ ] Unit tests (compressed)
- [ ] **Action** — add unit tests (test code derived from the implementation; names + intents below):

| Test | Verifies | Setup notes |
|---|---|---|
| `TestValidate_DurationLowerBounds` | `≤0` ping/request-timeout/ban-poll/cert-validity rejected | table over the four flags (OPS-001..004) |
| `TestValidate_ZeroSizeRejected` | `--limit-response 0` etc. fail | (OPS-005) |
| `TestValidate_HostAndDomain` | empty AND dot-less `--tunnel-domain`/`--enroll-host` rejected | (OPS-012) |
| `TestParseByteSize_Overflow` / `TestParseBitrate_Overflow` | overflowing input errors, not wraps | `9223372036854775807kb` (OPS-006) |
| `TestTrustedIP_MappedAndZoned` | `::ffff:1.2.3.4`→`1.2.3.4`; zone stripped; right-most token; IPv6 bare | (ING-005, AUTH-009) |
| `TestBan_MappedIPv6Matches` | ban `ip ::ffff:9.9.9.9` matches `9.9.9.9` and vice-versa | (ING-005) |
| `TestParseLine_ExtraTokensRejected` | `country XX YY` warned-and-skipped | (ING-010) |
| `TestExpandCountries_SkipsMalformedRow` | one bad row does not drop all country prefixes | (ING-008) |
| `TestBanLoad_PresentCSVFailureKeepsSnapshot` | present-but-corrupt CSV → previous snapshot kept; absent CSV → skip-and-warn | (ING-009) |
| `TestWatcher_DetectsDeletionAndEqualMtime` | deletion / equal-mtime replacement triggers reload | inject a fingerprint via `tick()` (ING-002) |
| `TestWatcher_RetriesAfterFailedLoad` | failed load does not consume the change; next tick retries | (ING-003) |
| `TestBucketRegistry_PinnedNotEvicted` | a pinned entry survives idle eviction; Unpin restores eviction | fake clock (ING-001) |
| `TestCaplog_IPSetBounded` | per-key IP set caps at `maxTrackedIPs`; summary reports `+` | (ING-011) |
| `TestSanitize_ConnectionNominatedStripped` | `Connection: X-Custom` drops `X-Custom` both directions | table over Sanitize/SanitizeResponse (ING-007) |
| `TestFirstLabel_CaseInsensitive` | uppercased Host resolves same route key | (ING-014) |
| `TestHostOnly_DotAndCase` | trailing dot + case folded; port stripped | (OPS-007) |
| `TestHostSuffixOK` | `name.<domain>` ok; `name.attacker` rejected | (AUTH-003) |
| `TestVerifyEnrolledCert_RejectsCAAndNoDigSig` | CA-flagged / wrong-keyusage leaf rejected | mint via test CA (AUTH-007) |
| `TestGenerateName_ReservesEnrollLabel` | generator never emits the enroll host label | inject reserved (OPS-012) |
| `TestAuthCertSizeCap` | >4 KiB AUTH cert rejected pre-parse | (AUTH-005) |
| `TestParseByteSize`/`size` overflow + zero | see above | |
| `TestWire_DecodeErrors` | malformed frame/envelope header → error (not zero-value) | (DP-012, TEST-017) |
| `TestGoldenFrameFixtures_ChallengeAndAuth` | `challenge.frame` (+ add `auth`, `response_body_chunk` fixtures) pinned | (DP-009, TEST-002) |
| `TestEnrollHourLimit` | perHour binding branch denies | (TEST-011) |
| `TestAdminTopN_DedupAndEmptySkip` | duplicate SCAN key counted once; empty hash skipped; N-truncation | (OPS-011, TEST-013.6) |
| `TestClient_EnrollErrors` + `TestClient_EnrollRejectsNonP256` | non-200/bad-PEM/429 surfaced; non-P256 local error | httptest (TEST-016, AUTH-010) |
| `TestClient_ServeSurfacesConnectError` | `Serve` invokes `OnConnectError` on a failed connect attempt; NOT after ctx is done | inject a failing dial (DP-013) |
| `TestLogging_FileSinkProbeFails` | unwritable path → startup error | temp dir perms (OPS-010) |
| `TestSanitize_MTLSAndForwarded` | all 5 mTLS headers → reject; `Forwarded` stripped; XFF/Host/Proto re-added | table over Sanitize (ING-013) |
| `TestGenerateName_ReservedSkipAndExhaustion` | forced reserved collision skipped; 8-attempt exhaustion → error | injected rand seam (TEST-025) |
| `TestCaplog_WindowExpiryRelog` | second immediate log + second summary across a window boundary | injected clock (TEST-026) |
| `TestEnrollBodyReadTimeout` | stalling CSR body → 408 `body_read_timeout` | blocking body, short timeout (TEST-027) |
| `TestBan_IPv6EntriesMatch` | IPv6 `ip`/`cidr` ban entries match IPv6 lookups | (TEST-021) |

### Task 18.2 — [ ] wsconn / dataplane tests (compressed)
- [ ] **Action** — add:

| Test | Verifies | Setup notes |
|---|---|---|
| `TestOverCapResponsePacedAndAccounted` | over-cap drain is paced + `Bytes` recorded; tunnel stays up | fake down-bucket / recorder (DP-003) |
| `TestOversizedChunkTearsDown` | `ErrBurstExceeded` → reason `oversized_frame` + Warn | (DP-010) |
| `TestBanDuringConnectEvicts` | ban applied between auth and Store tears the conn down | (DP-002) |
| `TestMidSendDeadlineIs504` | per-message deadline mid-send → nil (504), not 502 | slow up-bucket (DP-004) |
| `TestSelfHealDoesNotClobberNewerConn` | `missing` self-heal is connID-conditional | two conns, Redis blip (DP-006) |
| `TestBindIfAbsentOrOwner_ThreeState` | absent→bound; same-connID→bound; diff-connID/same-fp→not-owner; diff-fp→conflict (`ErrNameHeldByOther`) | router-tier unit test, miniredis (DP-006) |
| `TestWSDropFailsPendingWith502` | in-flight request on WS drop resolves `tunnel_gone` | real pending request (DP-008/TEST-008) |
| `TestDeadPeerTeardown` | failed ping → `dead_peer` + route removed | sever TCP; short ping (TEST-009) |
| `TestPreAuthSlotReleasedOnAuthFailure` | N+1 failed auths still admit the next connect | (AUTH-008) |
| `TestConnectRateLimit429ReleasesSlot` | N connect-rate-limited 429s do not exhaust the pre-auth semaphore; ban check precedes the semaphore acquire | (AUTH-004) |
| `TestEmptyBodyZeroChunksOnWire` | empty-body request sends zero REQUEST_BODY_CHUNK frames | rawPhone counts frames (TEST-019) |
| `TestStaleErrorFrameIgnored` | ERROR with unknown reqid does not disturb in-flight | (TEST-018) |
| `TestBindDuringShutdownNoRouteSurvives` | connect racing Shutdown leaves no route | (TEST-020) |
| `TestConcurrentClientBridge` | two concurrent requests multiplex; ping answered during a slow handler | client rework (DP-007) |
| `TestBindSurvivesRequestCtxCancel` | route survives a cancelled REQUEST context post-bind (bind on conn ctx) | integration tier (AUTH-002) |
| `TestTeardownUnbindTimeBounded` | teardown returns within the 5s bound when Redis is unresponsive; failure logged | stalled miniredis / capturing logger (DP-011) |

### Task 18.3 — [ ] Ingress / transport / server tests (compressed)
- [ ] **Action** — add:

| Test | Verifies | Setup notes |
|---|---|---|
| `TestBodyTimeoutNoWriterRace` | over-limit/timeout body read never races `w` | run under `-race`; slow+oversize body (AUTH-001) |
| `TestClientAbortNotTimeout` | client abort mid-body/round-trip records no cap-hit/timeout | cancel parent ctx (ING-015, DP-015) |
| `TestTotalHeaderCap431` | many small headers summing over `--limit-headers` → 431 `headers_too_large` | (TEST-004) |
| `TestRateRPM429` | rpm branch → 429 `rate_rpm` | low RPM, high RPS, frozen window (TEST-005, ING-006 determinism) |
| `TestPublishFailure502` / `TestLimiterRedisError500` | publish-fail → 502 `PublishError`; limiter Redis error → logged 500 | close miniredis after bind (TEST-006, ING-004) |
| `TestPacedByNodeStamped` | ingress stamps `PacedByNode = nodeID` | assert on forwarded envelope (TEST-007) |
| `TestNodeReadyBeforeAccept` | first request to a fresh replica succeeds on the FIRST try (no retry) | (DP-005) |
| `TestAdminTunnelsHandler` | 200 JSON shape + 500 on TopN error | httptest against internal mux (TEST-012) |
| `TestRunFlusherCadenceAndFinalFlush` | ticker flush + final flush on cancel; failed Incr logged | fake store (TEST-013.4, OPS-008) |
| `TestMux_MethodAndHostEdges` | `GET /enroll`→404; trailing-dot/case/port hosts dispatch | (TEST-023, OPS-007) |

### Task 18.4 — [ ] e2e: exercise the proxy edge; determinism
- [ ] **Action** — modify `e2e/tunnel_e2e_test.go`: route at least the core lifecycle scenario (enroll → `/connect` WS → public `POST /mcp` → response) through `c.traefikURL` with real `Host` headers and NO client-injected `X-Real-Ip` (Traefik sets the client-IP header per `e2e/testdata/traefik-e2e.yml`); keep one direct-to-replica test for deterministic cross-replica routing (TEST-001).
- [ ] **Action** — modify `e2e/tunnel_e2e_test.go` `TestRateLimit429`: set a low `TUNNELD_LIMIT_RPS` (e.g. `2`) in the replica env (or issue the burst concurrently) so the trip is deterministic (TEST-015).
- [ ] **Action** — add an e2e assertion that a `/connect` with a banned `tunnel-fingerprint` is REFUSED (the missing half of `TestBannedTunnelFingerprintRefusedAndEvicted`) and that a banned fingerprint blocks public ingress on the resolved route (TEST-024).
- [ ] **DoD:** the e2e suite drives Traefik for the core path; rate-limit and fingerprint-ban scenarios are deterministic and complete.

### Task 18.5 — [ ] Test-quality cleanups
- [ ] **Action** — replace `time.Sleep` synchronization in `internal/wsconn/manager_test.go` `TestSameNodeReconnectNotClobbered` with deterministic polling on `conns.Load`/`Lookup` (TEST-010).
- [ ] **Action** — add `t.Parallel()` to the parallel-safe pure-function suites (`wire`, `config/size`, `clientip`, `ingress/allowlist`, `ban/parse`, `ca`) and their subtests (TEST-013).
- [ ] **Action** — convert the table loops in `internal/config/size_test.go`, `internal/ban/parse_test.go`, `internal/ingress/allowlist_test.go` to named `t.Run` subtests using `t.Errorf` (not `t.Fatalf`-in-loop) (TEST-014); add `t.Helper()` to the failing helpers in `internal/ingress/handler_test.go`/`enroll_test.go` (TEST-028).
- [ ] **DoD:** no `time.Sleep`-based synchronization remains in wsconn tests; parallel-safe suites run parallel; table tests are named subtests.

---

## US19 — [ ] Final ground-up verification (MANDATORY LAST)

**Why:** Re-verify the whole change set from the ground up and run every quality gate.

**Acceptance criteria:**
- [ ] Every US1–US18 acceptance criterion is checked and satisfied against the final code.
- [ ] All quality gates pass on the FINAL code.
- [ ] Every touched Mermaid chart validates.

### Task 19.1 — [ ] Ground-up re-review
- [ ] **Action** — re-read every user story's acceptance criteria against the final diff; confirm no `US<n>` reference remains in any comment (re-run the US15 grep); confirm no finding was missed (walk the audit finding IDs US1–US18 map).
- [ ] **DoD:** every acceptance box above is ticked with the code as evidence.

### Task 19.2 — [ ] Mermaid validation (REQUIRED — this plan modifies `docs/ARCHITECTURE.md` diagrams)
- [ ] **Action** — validate every Mermaid block in `docs/ARCHITECTURE.md` (and any other touched Markdown) via the `mmdc` procedure in `development_pipeline.md` §9 / `make mermaid-check`.
- [ ] **DoD:** all Mermaid blocks render clean.

### Task 19.3 — [ ] Quality gates
- [ ] **Action** — run, capturing each to `/tmp/p2-*.log` via `tee`: `make lint` (3-pass), `make vet`, `make govulncheck`, `make build`, `make test-unit`, `make test-integration`, `make test-e2e`, `make test-scripts`, `make compose-config` (+ the new Traefik render gate), `make mermaid-check`, and `go mod tidy` drift check.
- [ ] **DoD:** every gate is green on the final code; any fix made to reach green is re-verified by re-running the affected gate.

---

## Deviations

- **Task 16.6 — pinned ops-stack image versions** (selected as the latest stable tag from each image's
  Docker Hub registry at implementation time): `prom/prometheus:v3.13.2`, `prom/alertmanager:v0.34.0`,
  `grafana/grafana:13.0.6`, `binwiederhier/ntfy:v2.27.0`, `xenrox/ntfy-alertmanager:1.0.0`.
- **Task 16.6 — pinned GitHub Action commit SHAs** (resolved via `gh api repos/<a>/commits/<tag>`):
  `actions/checkout` v4 `11d5960…`, `actions/setup-go` v5 `40f1582…`, `golangci/golangci-lint-action`
  v7 `9fae48a…`, `actions/setup-node` v4 `49933ea…`, `docker/setup-qemu-action` v3 `c7c5346…`,
  `docker/setup-buildx-action` v3 `8d2750c…`, `docker/login-action` v3 `c94ce9f…`,
  `goreleaser/goreleaser-action` v6 `e435ccd…`. mermaid-cli pinned to `@11.16.0` (npm latest).
- **Task 16.7 — ntfy bridge port left at its default** (`:8080`, which `alertmanager.yml`'s webhook
  already targets). ntfy's own `listen-http: ":80"` was set (directive verified against docs.ntfy.sh).
  The `xenrox/ntfy-alertmanager` scfg directive for the HTTP address could NOT be verified against an
  authoritative source, so per the external-claim-verification rule no unverified directive was added
  (a wrong scfg key would break the strict parser); a `config.scfg` comment documents the expectation.
- **Task 16.7 — Traefik render gate is best-effort.** `make traefik-config` runs `traefik:v3.3`
  briefly and fails on the file-provider's template/parse error lines. Traefik keeps running on a bad
  hot-reloadable dynamic config, so the gate greps for `template:` / `error while building the
  configuration` / `error while parsing`; the exact match set is best-effort (Traefik's log strings
  were not verified against a rendered failure) and missing-entrypoint warnings are intentionally not
  matched.
