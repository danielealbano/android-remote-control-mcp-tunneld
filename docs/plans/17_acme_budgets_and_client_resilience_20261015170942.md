<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 17 — ACME issuance budgets, phone liveness + issuance retries, lighter soak app

Decision record (agreed with the user on 2026-10-15; not derivable from the code):

- **Which CAs are in the chain.** A CA without its parameters is simply left out:
  - **LE** is in unless `--acme-dir-le` is set empty.
  - **GTS** is in only for the ids listed in `--acme-gts-account` (default: none).
  - **ZeroSSL** is in only when BOTH `--acme-eab-zerossl-kid` and `--acme-eab-zerossl-hmac` are set (one without the other is a config error).
  - `Validate()` refuses a config with no CA left.
  - Only the enabled CAs' validation methods count (`UsesChallenge`).
- **GTS accounts are never created by tunneld.**
  - Every listed id needs its EXISTING account key at `<acme-account-dir>/accounts/<id>.key`; a missing key fails startup.
  - The account is looked up by key (ACME `onlyReturnExisting`, lego `ResolveAccountByKey`); no EAB, no email.
  - The GTS EAB flags are removed.
  - Production will list `arc-tunnel-acme-gts-1..4` (registered 2026-10-15).
- **ACME issuance budgets in Valkey**, counted the way each CA counts, as token buckets (`capacity` = burst, one token regained every `period / count`):
  - **LE:**
    - per registered domain 50 / 168 h. The key is the registered domain of each certificate's name: eTLD+1 by the Public Suffix List, as LE counts it, via `golang.org/x/net/publicsuffix`.
    - per account 300 new orders / 3 h;
    - per exact name 5 / 168 h.
    - A renewal of a name whose current certificate is from LE is exempt from the first two (LE's own rule). This covers phone names and tunneld's own reserved hosts.
  - **GTS (per account = per Public CA project):**
    - 100 new orders / 1 h;
    - 120 requests / 1 min, of which requests to `/cert/` URLs ≤ 50 / 1 min. `cert` is GTS's quota resource, named in its 429s on `POST …/cert/<id>`; order polls count against the 120.
  - **ZeroSSL (per account):** 200 new orders / 1 h with bursts up to 40, and 240 requests / 1 min.
  - Every value is a flag. The attempt deadlines and the poll timing are flags too (user, 2026-10-15). Renewals and enrollments share the budgets (no priority).
- **Reserve, don't spend.** Each order reserves one slot in every bucket it draws on, in the per-node sorted set `acme:inflight:{bucket}:{node}` (member = the attempt, score = its deadline). Available = tokens − reservations of LIVE nodes (the `nodes` set; node ids are per process). The set's TTL is only ever extended (`EXPIRE NX` + `EXPIRE GT`), so a later, shorter reservation never expires an earlier one.
  - **Settlement:**
    - Success spends.
    - The order buckets are spent once the CA created the order, on all three CAs.
    - An order finalized and then abandoned counts as issued, and its success buckets are spent. "Finalized" means the CA answered the finalize request with a 2xx. "Abandoned" means the attempt then did not succeed for any reason: tunneld's deadline, a 429, lego's own certificate wait, or a network error on a poll or on the download. The CA issues and counts that certificate anyway.
    - Every other failure releases.
  - No cross-checking at the CA.
  - A per-CA `SETNX` lock (2 s TTL; held for milliseconds) guards check + reserve / spend.
- **A 429 is the safety net:**
  - It sets a cluster-wide per-account wait-until from Retry-After. It is never shortened: a pipelined `EXPIRE GT` then `SET NX EX`. An existing key is extended before the `SET NX` runs, so it cannot expire between the two commands.
  - It resyncs ONLY the bucket the 429 names:
    - LE, by the docs anchor in the detail: `#new-certificates-per-registered-domain` → domain, `#new-orders-per-account` → orders, `#new-certificates-per-exact-set-of-identifiers` → name;
    - GTS: `resource "cert"` → cert bucket, anything else → requests bucket. The two GTS 429 details seen in production on 2026-10-15 were `over quota (50 requests in 60 seconds) for the given ACME resource "cert"` and `… (250 requests in 60 seconds) … resource "order"`. The second is an order-URL polling quota, so it counts against requests. No new-order 429 has been seen, and GTS does not publish its format;
    - ZeroSSL: requests bucket (no published limits, no 429 seen).
  - It ends the attempt at once.

  The HTTP layer around lego refuses or holds every request (tracked or not) of an account under a wait-until or without request budget, and spaces the polls.
- **Backoff** (user, 2026-10-15, asked explicitly). Every other unsuccessful attempt counts as a CA failure: a `"fail"` in `tunneld_acme_issue_total`, and the account goes on the existing exponential backoff (`--acme-backoff-initial` doubling up to `--acme-backoff-max`; cluster-wide for a GTS account). "Every other" means anything but a 429, a permanent error or a local error. It includes:
  - an attempt that hits its deadline (the CA is too slow);
  - a request tunneld itself refused because the account had no request budget;
  - a request tunneld held while the account waited out another attempt's 429, until the attempt's deadline.
- **Abandoned attempts** (deadline or 429) clean up their pending TLS-ALPN-01 challenge immediately, so the next account/CA can present its own (only one is pending per domain cluster-wide).
- **Polling:** the first certificate poll after finalize waits the CA's median wait + 2 s (LE 2 s, GTS 5.6 s, ZeroSSL 15.2 s), then every 2 s; lego's own 30 s certificate wait is unchanged.
- **Deadlines:** per attempt LE 20 s, GTS 40 s, ZeroSSL 90 s; a whole chain run is capped at 290 s (derived from the agreed 300 s phone wait minus 10 s for the rest of `/api/v1/issue`; injectable for tests).
- **Chain order:** LE → GTS accounts (most remaining order budget first, random among equals, `crypto/rand`) → ZeroSSL; an account without budget or under a wait-until gets no request.
  - Every account unavailable → retryable `acme_rate_limited` with `retry_after_seconds` = earliest free slot + random 1–10 s.
  - No slot booking.
- **Phone rules (PROTOCOL):**
  - After 90 s without any control frame the phone drops the control CONNECTION and reconnects on a new one; `--control-ping-interval` is capped at 30 s.
  - Issuance retries: at most 3, issuance only (never re-enroll). Each waits `retry_after_seconds` when given, else 5 s / 10 s / 15 s. Network errors, timeouts and `retryable: true` answers are retried; `retryable: false` stops; then give up. A failed fresh-nonce fetch counts as a failed retry and follows the same rules (user, 2026-10-15, asked explicitly).
  - The issuance wait is 300 s.
  - Renewals are single-flight in the Go client and both apps. A `RENEW_NUDGE` that arrives while a renewal (or its retries) is running is ignored, so overlapping nudges never issue twice.
- **Soak app:**
  - It answers on the dial-back connection itself (server-mode TLS with the phone's public cert, minimal HTTP/1.1, `POST /op?resp=<n>`): no Ktor/Netty, no local socket/port.
  - No phone cap.
  - A phone is saved right after Phase 1, so a failed issuance never leads to re-enrollment, not even on a later `start`. A saved phone without a public cert resumes with issuance only (fresh nonce, the retry rule).
- **Kotlin unit tests** use JUnit 4.13.2, the latest 4.x. Android's local-test guide (developer.android.com/training/testing/local-tests) prescribes JUnit 4 ("Required -- JUnit 4 framework") and has no JUnit 5 path.
- **CI:** the GitHub secret `TUNNELD_STAGING_GTS_ACCOUNT_KEY` switches to the `arc-tunnel-acme-gts-staging` account.
- **Not in this plan.** These happen after the PR merges, each step on the user's go:
  - the release;
  - the GTS keys and settings on the nodes;
  - deploying the dashboard to N1;
  - deleting `arc-tunnel-acme`;
  - resuming the soak.

Branch: `feat/plan-17-acme-budgets-client-resilience`.

---

## [x] US1 — Protocol contract: control liveness + issuance retries

Phones must notice a dead control connection and retry issuance in a bounded, uniform way.

- [x] AC1: `wire` exports the liveness and retry constants; `Validate()` refuses `--control-ping-interval` > 30 s.
- [x] AC2: `docs/PROTOCOL.md` §3 states the 90 s rule, the 300 s issuance wait and the retry rule.

### [x] T1.1 — wire constants

- [x] A1.1.1 `internal/wire/frame.go` (modify): add `"time"` to the imports and append:

```go
const (
	MaxControlPingInterval = 30 * time.Second
	ControlSilenceTimeout  = 3 * MaxControlPingInterval
	IssueRetries           = 3
)

func IssueRetryWait(retry int) time.Duration { return time.Duration(retry+1) * 5 * time.Second }
```

DoD:
- [x] Constants and `IssueRetryWait` exported.

### [x] T1.2 — ping-interval cap

- [x] A1.2.1 `internal/config/config.go` (modify): import `github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire`. In `Validate()`, right after the `d.v <= 0` duration loop:

```go
	if c.ControlPingInterval > wire.MaxControlPingInterval {
		return fmt.Errorf("--control-ping-interval must be ≤ %s: phones treat %s without a control frame as a dead connection (docs/PROTOCOL.md §3), got %s", wire.MaxControlPingInterval, wire.ControlSilenceTimeout, c.ControlPingInterval)
	}
```

- [x] A1.2.2 same file: `config` now imports `wire` (A1.2.1), so the duplicated literal loses its only reason, and its comment's last sentence ("The literal is duplicated here with this note rather than importing wire (avoids an import cycle).") becomes false. That sentence is removed, and the constant takes the value from its single source: `const bandwidthFloorBytesPerSec int64 = wire.ChunkSize` (untyped constant, no conversion needed). The rest of the comment stays (still true).

DoD:
- [x] Cap enforced; no comment states something false.

### [x] T1.3 — PROTOCOL.md §3

- [x] A1.3.1 `docs/PROTOCOL.md` (modify), §3, after the first bullet list (ending "the mTLS `POST /api/v1/issue` exchanges (below).") insert:

> **Liveness.** The server sends a `PING` every `--control-ping-interval` (at most 30 s) and drops a phone that
> misses three `PONG`s. The phone MUST treat 90 s without ANY control frame as a dead connection: it closes the
> control CONNECTION — the TCP/TLS connection, not only the stream — and reconnects on a new one. Without this
> rule a half-open TCP connection (a NAT that dropped the mapping, a server that is gone) is never noticed,
> because the phone writes only to answer a `PING`.

- [x] A1.3.2 same file, `/api/v1/issue` **Latency** bullet: `the phone MUST allow at least 60 s for it` → `the phone MUST allow at least 300 s for it`.
- [x] A1.3.3 same file: replace the **Retrying a retryable failure** bullet with:

> - **Retrying a failed issuance**: the phone retries `POST /api/v1/issue` at most 3 times, and only the issuance — it
>   NEVER re-enrolls (a new enrollment assigns a new name and orphans the old one). A network error, a timeout, or
>   an error answer with `retryable: true` is retried; `retryable: false` ends the attempts at once. Retry n
>   (1–3) waits the answer's `retry_after_seconds` when it carries one, otherwise 5 s, 10 s, 15 s. Every attempt
>   CONSUMES its single-use nonce, including a failed one, and the enroll and issue nonces share ONE namespace, so
>   after the wait the phone fetches a fresh challenge from `GET /api/v1/enroll/nonce` (server-TLS, per-IP
>   rate-limited) and repeats `POST /api/v1/issue` with a fresh attestation over it (fresh keys/CSRs, as always);
>   a failed nonce fetch is a failed retry like any other. After the third failed retry the phone gives up. When
>   every CA is out of issuance budget the server answers `503` `acme_rate_limited` with `retry_after_seconds` =
>   the earliest free budget slot plus a random 1–10 s. A phone that is already BOUND on the control stream is
>   also re-nudged: the renewal watcher sees a cert-less or renewal-due tunnel and sends a fresh
>   `RENEW_NUDGE{nonce}` on its next scan.

DoD:
- [x] §3 states the three rules exactly as above.

### [x] T1.4 — tests

| Test | Verifies |
|---|---|
| `TestIssueRetryWait_Schedule` (`internal/wire/frame_test.go`) | retry 0/1/2 → 5 / 10 / 15 s; `IssueRetries == 3`; `ControlSilenceTimeout == 90 s` |
| `TestValidate_ControlPingIntervalCap` (`internal/config`) | 30 s valid; 31 s → error naming `--control-ping-interval` |

**Existing test to adapt:** `TestEnvTwinOverridesFlag` (`internal/config/config_test.go`). kong runs `Validate()` on parse, so `TUNNELD_CONTROL_PING_INTERVAL` `45s` and the asserted `45*time.Second` become `25s` / `25*time.Second`.

DoD:
- [x] Tests added and adapted.

---

## [x] US2 — Shared test proxy (`internal/tunneltest`)

The Go client and the device gates both need a TCP proxy that can black-hole existing connections without closing them.

- [x] AC1: `BlackholeProxy` forwards, freezes existing connections on demand, passes an end of stream from one side to the other while not frozen (like a real TCP path), counts accepted connections, and never hangs cleanup.

### [x] T2.1 — `internal/tunneltest/blackhole.go` (create; shared test infrastructure)

- [x] A2.1.1:

```go
package tunneltest

import (
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

type BlackholeProxy struct {
	t      *testing.T
	ln     *net.TCPListener
	target *net.TCPAddr
	mu     sync.Mutex
	closed bool
	conns  []*proxiedConn
	count  atomic.Int64
	wg     sync.WaitGroup
}

type proxiedConn struct {
	client, upstream *net.TCPConn
	frozen           atomic.Bool
}

func StartBlackholeProxy(t *testing.T, target string) *BlackholeProxy {
	t.Helper()
	raddr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &BlackholeProxy{t: t, ln: ln, target: raddr}
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(func() {
		p.mu.Lock()
		p.closed = true
		conns := slices.Clone(p.conns)
		p.mu.Unlock()
		CloseOrLog(t, ln)
		for _, c := range conns {
			CloseOrLog(t, c.client)
			CloseOrLog(t, c.upstream)
		}
		p.wg.Wait()
	})
	return p
}

func (p *BlackholeProxy) accept() {
	defer p.wg.Done()
	for {
		c, err := p.ln.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.t.Logf("blackhole proxy: accept: %v", err)
			}
			return
		}
		up, err := net.DialTCP("tcp", nil, p.target)
		if err != nil {
			p.t.Logf("blackhole proxy: dial %s: %v", p.target, err)
			CloseOrLog(p.t, c)
			continue
		}
		pc := &proxiedConn{client: c, upstream: up}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			CloseOrLog(p.t, c)
			CloseOrLog(p.t, up)
			return
		}
		p.conns = append(p.conns, pc)
		p.count.Add(1)
		p.wg.Add(1)
		p.mu.Unlock()
		var pair sync.WaitGroup
		pair.Add(2)
		go p.pipe(pc, pc.client, pc.upstream, &pair)
		go p.pipe(pc, pc.upstream, pc.client, &pair)
		go p.reap(pc, &pair)
	}
}

func (p *BlackholeProxy) reap(pc *proxiedConn, pair *sync.WaitGroup) {
	defer p.wg.Done()
	pair.Wait()
	p.mu.Lock()
	p.conns = slices.DeleteFunc(p.conns, func(c *proxiedConn) bool { return c == pc })
	p.mu.Unlock()
	CloseOrLog(p.t, pc.client)
	CloseOrLog(p.t, pc.upstream)
}

func (p *BlackholeProxy) pipe(pc *proxiedConn, src, dst *net.TCPConn, pair *sync.WaitGroup) {
	defer pair.Done()
	buf := make([]byte, 16384)
	for {
		n, err := src.Read(buf)
		if n > 0 && !pc.frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				if !errors.Is(werr, net.ErrClosed) {
					p.t.Logf("blackhole proxy: write: %v", werr)
				}
				return
			}
		}
		if err != nil {
			if pc.frozen.Load() {
				return
			}
			if cerr := dst.CloseWrite(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
				p.t.Logf("blackhole proxy: half-close after %v: %v", err, cerr)
			}
			return
		}
	}
}

func (p *BlackholeProxy) Freeze() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.frozen.Store(true)
	}
}

func (p *BlackholeProxy) Accepted() int64 { return p.count.Load() }

func (p *BlackholeProxy) Addr() string { return p.ln.Addr().String() }
```

DoD:
- [x] Proxy in place (used by US3 and US10).

### [x] T2.2 — tests

| Test | Verifies |
|---|---|
| `TestBlackholeProxy_ForwardsThenFreezes` (`internal/tunneltest`) | echo target: bytes flow; after `Freeze()` an existing connection gets no bytes but is not closed; a new connection still flows; `Accepted()` counts both |
| `TestBlackholeProxy_PropagatesClose` | the target closes a connection → the client side reads EOF; the client half-closes → the target reads EOF; a frozen connection propagates nothing; once both directions of a pair have ended, both sockets are closed and the pair leaves the proxy's list |
| `TestBlackholeProxy_CleanupNeverHangs` | connections opened concurrently with cleanup → cleanup returns |

DoD:
- [x] Tests added.

---

## [ ] US3 — Go client: dead-connection detection + issuance retry rule

The reference Go client implements both phone rules; `New` learns the enroll host so a renewal retry can fetch fresh nonces.

- [ ] AC1: `ControlSilenceTimeout` without a frame, counted from before the request is sent, ends `Run` with `errControlSilence` and closes the TCP connection; the next `Run` dials a new one.
- [ ] AC2: `Enroll` (Phase 2) and `Renew` follow the retry rule; a failed nonce fetch is a failed retry.
- [ ] AC3: Every `client.New` / `newMTLSTransport` call site is updated.
- [ ] AC4: A `RENEW_NUDGE` that arrives while a nudge-driven renewal (or its retries) is running is ignored, with a Debug log.

### [ ] T3.1 — retry helper

- [ ] A3.1.1 `client/issue_retry.go` (create):

```go
package client

import (
	"context"
	"errors"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func issueRetryWait(err error, retry int) (time.Duration, bool) {
	if ee, ok := errors.AsType[*EnrollError](err); ok {
		if !ee.Retryable {
			return 0, false
		}
		if ee.RetryAfter > 0 {
			return ee.RetryAfter, true
		}
		return wire.IssueRetryWait(retry), true
	}
	if _, ok := errors.AsType[*transportError](err); ok {
		return wire.IssueRetryWait(retry), true
	}
	return 0, false
}

func issueWithRetries(ctx context.Context, sleep func(context.Context, time.Duration) error, nonce string,
	issue func(nonce string) (*Identity, error), freshNonce func() (string, error)) (*Identity, error) {
	id, err := issue(nonce)
	for retry := 0; err != nil; retry++ {
		wait, ok := issueRetryWait(err, retry)
		if !ok || retry >= wire.IssueRetries {
			return nil, err
		}
		if serr := sleep(ctx, wait); serr != nil {
			return nil, errors.Join(err, serr)
		}
		var n string
		if n, err = freshNonce(); err == nil {
			id, err = issue(n)
		}
	}
	return id, nil
}
```

DoD:
- [ ] Helper in place.

### [ ] T3.2 — `Client`: enroll host, connection tracking, silence watchdog

- [ ] A3.2.1 `client/control.go` (modify):
  - **Imports:** `sync/atomic`.
  - **`Client` gains:**

```go
	enrollHost     string
	silenceTimeout time.Duration
	sleep          func(context.Context, time.Duration) error
	renewing       atomic.Bool

	connMu sync.Mutex
	conn   net.Conn
```

  - **`New`** becomes `func New(dialAddr, enrollHost, controlHost, tunnelDomain string, caPool *x509.CertPool, ident *Identity, backend Backend, opts ...Option) (*Client, error)`. It initialises `enrollHost: enrollHost, silenceTimeout: wire.ControlSilenceTimeout, sleep: sleepCtx`, and builds the transport with `newMTLSTransport(dialAddr, controlHost, caPool, c.currentCert, c.trackConn)`.
  - **Added:**

```go
var errControlSilence = errors.New("client: no control frame within the silence timeout; connection treated as dead")

func WithControlSilenceTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return errors.New("client: control silence timeout must be positive")
		}
		c.silenceTimeout = d
		return nil
	}
}

func (c *Client) trackConn(conn net.Conn) {
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
}

func (c *Client) dropConn() {
	c.connMu.Lock()
	conn := c.conn
	c.conn = nil
	c.connMu.Unlock()
	if conn != nil {
		c.closeLogged("control connection", conn)
	}
}
```

  - **`newMTLSTransport`** gains a last parameter `onConn func(net.Conn)`; its `DialTLSContext` ends with:

```go
			h2, err := requireH2(conn)
			if err != nil {
				return nil, err
			}
			onConn(h2)
			return h2, nil
```

- [ ] A3.2.2 `client/control.go` (modify) `Run`. The existing comments stay where they are.

```go
func (c *Client) Run(ctx context.Context) error {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	var (
		wdMu         sync.Mutex
		ended, quiet bool
	)
	silent := func() bool {
		wdMu.Lock()
		defer wdMu.Unlock()
		return quiet
	}
	watchdog := time.AfterFunc(c.silenceTimeout, func() {
		wdMu.Lock()
		defer wdMu.Unlock()
		if ended || quiet {
			return
		}
		quiet = true
		c.dropConn()
		cancel()
		pw.CloseWithError(errControlSilence)
	})
	defer func() {
		watchdog.Stop()
		wdMu.Lock()
		ended = true
		wdMu.Unlock()
	}()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, "https://"+c.controlHost+"/api/v1/control", pr)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		pw.CloseWithError(err)
		if silent() {
			return errControlSilence
		}
		return err
	}
	defer c.closeLogged("control response body", resp.Body)
	defer c.closeLogged("control request body", pw)
	if resp.StatusCode != http.StatusOK {
		return errors.New("client: control connect rejected: " + resp.Status)
	}
	// Deterministic cancellation: closing the body/pipe unblocks the frame read and any in-flight
	// control write immediately, without relying on the transport's own ctx propagation timing.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-rctx.Done():
			c.closeLogged("control response body", resp.Body)
			pw.CloseWithError(rctx.Err())
		case <-watchDone:
		}
	}()
	c.setSend(pw)
	watchdog.Reset(c.silenceTimeout)

	for {
		ct, payload, err := readControlFrame(resp.Body)
		if err != nil {
			if silent() {
				return errControlSilence
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		watchdog.Reset(c.silenceTimeout)
		switch ct {
		case wire.CtrlOpen:
			go c.handleOpen(ctx, payload)
		case wire.CtrlPing:
			c.sendControl(wire.CtrlPong, nil)
		case wire.CtrlRenewNudge:
			go c.renew(ctx, payload)
		}
	}
}
```

DoD:
- [ ] Silence before or after the request closes the TCP connection before `Run` returns `errControlSilence`. The watchdog runs under `wdMu` and is disarmed (`ended`) before `Run` returns, so a late firing can never touch the next `Run`'s connection. Dial-back sessions and renewals keep using `ctx` as before.

### [ ] T3.3 — retry rule in Phase 2 and `Renew`

- [ ] A3.3.1 `client/enroll.go` (modify) `issueCerts`: the `post` error and the read/close error become transport errors:

```go
	resp, err := post(ctx, hc, "https://"+controlHost+"/api/v1/issue", body)
	if err != nil {
		return nil, &transportError{err}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		err = fmt.Errorf("issue: read response: %w", err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		err = errors.Join(err, fmt.Errorf("issue: close response: %w", cerr))
	}
	if err != nil {
		return nil, &transportError{err}
	}
```

- [ ] A3.3.2 same file `fetchNonce`: the `hc.Do` error and the read/close error return `&transportError{…}` (same wrapping); a non-200 status returns `errorFromResponse(resp.StatusCode, raw)` instead of `fmt.Errorf("enroll: nonce status %d", …)`.
- [ ] A3.3.3 same file:
  - **`Enroll`** delegates to an unexported `enroll` that takes the sleeper:

```go
func Enroll(ctx context.Context, dialAddr, enrollHost, controlHost, tunnelDomain string, caPool *x509.CertPool) (*Identity, error) {
	return enroll(ctx, sleepCtx, dialAddr, enrollHost, controlHost, tunnelDomain, caPool)
}
```

  - **`enroll(ctx, sleep, …)`** keeps the current body and its comments, with three changes:
    - the Phase-2 transport is `newMTLSTransport(dialAddr, controlHost, caPool, func() *tls.Certificate { return &bootCert }, func(net.Conn) {})`;
    - the Phase-2 call:

```go
	id, err := issueWithRetries(ctx, sleep, er.IssueNonce,
		func(n string) (*Identity, error) { return issueCerts(ctx, mtls, controlHost, er.Name, tunnelDomain, "", n) },
		func() (string, error) { return fetchNonce(ctx, hc, enrollHost) })
```

    - in the comment inside the `if err != nil { … return bootIdent, err }` that follows, only "so the caller can execute the documented retry path (fresh nonce → Renew over the SAME mTLS identity) WITHOUT re-enrolling " is removed. It is made wrong: `enroll` now runs the documented retries itself, and after them the phone gives up. The comment then reads "Preserve the Phase-1 bootstrap identity (name + identity cert + key, no public cert yet) — re-enrolling would orphan this name in the registry (PROTOCOL §2: the name is never rolled back). See docs/PROTOCOL.md §3.".
  - **`FetchIssueNonce` doc:** only ", so this is the documented retry path after a RETRYABLE POST /api/v1/issue failure (which consumed the previous nonce): fetch a fresh nonce, wait retry_after_seconds, then call Client.Renew with it" is removed. It is made wrong: `Renew` now retries internally, and it waits before fetching. The doc then reads "FetchIssueNonce mints a fresh single-use challenge nonce from GET /api/v1/enroll/nonce (per-IP rate-limited). The enroll and issue nonces share one namespace. See docs/PROTOCOL.md §3.".
- [ ] A3.3.4 `client/renew.go` (modify) `renew` (the nudge handler) becomes single-flight:

```go
func (c *Client) renew(ctx context.Context, payload []byte) {
	if !c.renewing.CompareAndSwap(false, true) {
		c.logger.Debug("renewal already in progress; RENEW_NUDGE ignored")
		return
	}
	defer c.renewing.Store(false)
	var nudge wire.RenewNudgePayload
	if err := json.Unmarshal(payload, &nudge); err != nil {
		c.logger.Warn("malformed RENEW_NUDGE payload from the server (ignored)", "err", err)
		return
	}
	if nudge.Nonce == "" {
		c.logger.Warn("RENEW_NUDGE without a nonce from the server (ignored)")
		return
	}
	if err := c.Renew(ctx, nudge.Nonce); err != nil {
		c.logger.Warn("renew after a RENEW_NUDGE failed (keeping the current certs)", "err", err)
	}
}
```

- [ ] A3.3.5 same file, `Renew`:

```go
	next, err := issueWithRetries(ctx, c.sleep, nonceHex,
		func(n string) (*Identity, error) {
			return issueCerts(ctx, c.hc, c.controlHost, name, c.tunnelDomain, caID, n)
		},
		func() (string, error) { return FetchIssueNonce(ctx, c.dialAddr, c.enrollHost, c.caPool) })
	if err != nil {
		return err
	}
```

DoD:
- [ ] Phase 2 and `Renew` retry per the rule; `Enroll` still returns the bootstrap identity on final failure.

### [ ] T3.4 — call sites

- [ ] A3.4.1 (modify) pass the enroll host as the new 2nd argument of `client.New`:
  - `internal/server/integration_test.go`, `challenge_integration_test.go` and `drain_startup_integration_test.go` (both calls): `itEnrollHost`;
  - `e2e/e2e_test.go`: `e2eEnrollHost`;
  - every `New(` in `client/*_test.go`: that test's enroll host.
- [ ] A3.4.2 `client/control_test.go` (modify): the four `newMTLSTransport(…)` calls (lines 100, 111, 149, 177) get `func(net.Conn) {}` as the new last argument.

DoD:
- [ ] All call sites updated.

### [ ] T3.5 — tests (`client/`)

| Test | Verifies |
|---|---|
| `TestIssueWithRetries_Rule` (table, fake sleeper) | success first try (no sleep); retryable `EnrollError` with `RetryAfter` waits it; retryable without → 5/10/15 s; `transportError` retried; non-retryable stops; 4 attempts then the last error; a sleep error is joined; each retry issues with the fresh nonce; a retryable fresh-nonce failure consumes a retry and is retried; a non-retryable one ends |
| `TestEnroll_Phase2RetriesWithFreshNonce` | `startEnrollServer` with `issueFail` failing the first `/api/v1/issue` with no `retry_after` (retryable 503) → `enroll` (fake sleeper) sleeps 5 s once and succeeds on retry 1; `opts.nonces()` shows the second issue used a newly fetched nonce |
| `TestRenew_RetriesWithFreshNonce` | same through `Client.Renew` (`c.sleep` replaced), fresh nonce via `c.enrollHost` |
| `TestIssueCerts_TransportErrorIsRetryable` | a dropped issue connection yields `*transportError` |
| `TestRun_SilenceBeforeHeaders` | server accepts `/api/v1/control` and never answers headers; silence 200 ms → `errControlSilence` |
| `TestRun_SilenceAfterBind` | server answers 200 then sends nothing → `errControlSilence` |
| `TestRun_FramesResetSilence` | silence 1 s, server PINGs every 100 ms for 3 s → still serving; ctx cancel → `nil` |
| `TestRun_DeadConnectionIsReplaced` | client → `tunneltest.BlackholeProxy` → h2 control server; after bind `Freeze()`; silence 300 ms → `errControlSilence`; the next `Run` makes `Accepted()` grow by one and binds again |
| `TestWithControlSilenceTimeout_NonPositive` | 0 and −1 rejected |
| `TestRenew_NudgeSingleFlight` | the issue server blocks the first `/api/v1/issue`. `go c.renew(ctx, nudge1)` waits until the server holds that request. Then `c.renew(ctx, nudge2)` returns at once, with no second request and a Debug line. After the server is released, `c.renew(ctx, nudge3)` issues again |

**Shared client test infrastructure** (`client/enroll_test.go`, modify; in full). `startEnrollServer` can now return a non-retryable failure, hands out distinct nonces, and records the nonce of every issue request. Its variadic `issueFail ...func() bool` becomes `opts ...*enrollServerOpts`:

```go
type enrollServerOpts struct {
	issueFail func() *errorResponse

	mu          sync.Mutex
	issueNonces []string
}

func (o *enrollServerOpts) nonces() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.issueNonces)
}
```

- **Options:** `startEnrollServer` uses `o := &enrollServerOpts{}`, or `opts[0]` when one is given.
- **`/api/v1/enroll/nonce`:** keeps a `var nonceSeq atomic.Int64` and answers `nonceResponse{Nonce: fmt.Sprintf("%02x", nonceSeq.Add(1))}`, so every fetch is distinct (still hex).
- **`/api/v1/issue`:** checks mTLS and decodes the body first (unchanged code), then records the nonce and applies the injected failure before signing:

```go
		o.mu.Lock()
		o.issueNonces = append(o.issueNonces, body.Nonce)
		o.mu.Unlock()
		if o.issueFail != nil {
			if e := o.issueFail(); e != nil {
				status := http.StatusBadRequest
				if e.Retryable {
					status = http.StatusServiceUnavailable
				}
				w.WriteHeader(status)
				writeJSON(w, *e)
				return
			}
		}
```

- **Imports gained:** `fmt` and `slices`.

**Existing tests to adapt:**

| Test | Change |
|---|---|
| `TestClient_Renew_LogsFailures` | construct the `Client` with a fake `sleep` and `enrollHost`; assert the failure after the retries |
| `TestFetchIssueNonce_RetryPathCompletes` | `&enrollServerOpts{issueFail: …}` fails only the first issue (`acme_rate_limited`, retryable, `RetryAfter: 1`). `enroll` with a fake sleeper retries internally: `opts.nonces()` has two distinct entries (the Phase-1 `IssueNonce`, then a freshly fetched one), and no external retry is needed |
| `TestEnroll_Phase2FailureReturnsBootstrapIdentity` | `&enrollServerOpts{issueFail: …}` answers `&errorResponse{Reason: "acme_failed"}` (non-retryable, `400`). `enroll` with a fake sleeper returns the bootstrap identity and the error at once, with no sleep and exactly one issue request |
| `TestEnroll_ClosesTransports` | `startEnrollServer(t, ca)` unchanged |
| Any test asserting `"enroll: nonce status"` | now an `*EnrollError` |
| Every `New(` / `newMTLSTransport(` | new signatures |

DoD:
- [ ] Tests added and adapted.

---

## [ ] US4 — Budget primitives in Valkey (`internal/limit`)

Token buckets, per-node in-flight reservations and the per-CA lock, with the same TTL-on-every-write discipline as every other key; plus a wait-until that is never shortened.

- [ ] AC1: Reserve/commit/release/take/resync/level behave per the decision record.
- [ ] AC2: Every key written carries a TTL in the same round-trip.
- [ ] AC3: `SetCACooldown` never shortens an existing wait-until. The value is rounded up to whole seconds (at least 1 s), and `EXPIRE GT` runs before `SET NX EX` in one pipeline. So an existing key is extended, or already outlives the new value, before `SET NX` checks for it.
- [ ] AC4: A reservation never shortens the TTL of its node's in-flight set.

### [ ] T4.1 — wait-until never shortened

- [ ] A4.1.1 `internal/limit/acme_cooldown.go` (modify):
  - **Imports:** `math`.
  - **`SetCACooldown`:** `d` is rounded UP to whole seconds. go-redis v9.23.0 has no `PExpireGT`: `ExpireGT` sends whole seconds, while `SetNX` switches to `PX` for a fractional duration. Rounding first makes both commands carry the same value.

```go
func (l *Limiter) SetCACooldown(ctx context.Context, ca string, d time.Duration) error {
	d = max(time.Duration(math.Ceil(d.Seconds()))*time.Second, time.Second)
	pipe := l.rdb.Pipeline()
	pipe.ExpireGT(ctx, cooldownKey(ca), d)
	pipe.SetNX(ctx, cooldownKey(ca), "1", d)
	_, err := pipe.Exec(ctx)
	return err
}
```

  - **Comments made wrong.** Only the wrong words go, unless the whole comment is wrong:
    - `SetCACooldown` doc: "SET EX — " → "SetCACooldown marks ca as cooling for d (the TTL IS the cooldown).";
    - the block "The ACME rate-limit protection is REACTIVE (no proactive order counter, no budget): a CA answering rate-limited gets a per-CA cooldown … the spillover skips a cooling CA." is removed whole. Every statement in it is made wrong: protection is no longer reactive only, there is a budget, and the cooldown, the backoff and the skipping are per account;
    - the package doc: "per-CA " goes ("…, and the ACME cooldown/backoff.").

DoD:
- [ ] A longer existing wait-until survives a shorter write.

### [ ] T4.2 — `internal/limit/acme_budget.go` (create)

- [ ] A4.2.1:

```go
package limit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type Rate struct {
	Count  int
	Period time.Duration
	Burst  int
}

type Bucket struct {
	Key      string
	Capacity float64
	Refill   time.Duration
}

func (r Rate) Bucket(key string) Bucket {
	refill := r.Period
	if r.Count > 0 {
		refill = r.Period / time.Duration(r.Count)
	}
	return Bucket{Key: key, Capacity: float64(r.Burst), Refill: refill}
}

const (
	budgetLockTTL     = 2 * time.Second
	budgetLockTries   = 100
	budgetLockBackoff = 10 * time.Millisecond
	budgetKeyMargin   = time.Hour
	inflightKeyMargin = time.Minute
)

var ErrBudgetLockContended = errors.New("limit: acme budget lock contended")

func budgetKey(b Bucket) string                { return "acme-budget:" + b.Key }
func inflightKey(b Bucket, node string) string { return "acme:inflight:" + b.Key + ":" + node }
func budgetLockKey(ca string) string           { return "lock:acme-budget:" + ca }

type bucketState struct {
	tokens float64
	at     time.Time
}

func (b Bucket) tokensAt(s bucketState, now time.Time) float64 {
	if now.Before(s.at) || b.Refill <= 0 {
		return s.tokens
	}
	return min(b.Capacity, s.tokens+float64(now.Sub(s.at))/float64(b.Refill))
}

func (b Bucket) waitFor(s bucketState, now time.Time, need float64) time.Duration {
	if need > b.Capacity {
		return b.Refill
	}
	if now.Before(s.at) {
		return s.at.Sub(now) + time.Duration((need-s.tokens)*float64(b.Refill))
	}
	return time.Duration((need - b.tokensAt(s, now)) * float64(b.Refill))
}

func (b Bucket) spend(s bucketState, now time.Time) bucketState {
	if now.Before(s.at) {
		return bucketState{tokens: s.tokens - 1, at: s.at}
	}
	return bucketState{tokens: b.tokensAt(s, now) - 1, at: now}
}

func (l *Limiter) withBudgetLock(ctx context.Context, ca string, fn func() error) error {
	token := mintToken()
	for range budgetLockTries {
		ok, err := l.rdb.SetNX(ctx, budgetLockKey(ca), token, budgetLockTTL).Result()
		if err != nil {
			return fmt.Errorf("acme budget lock %s: %w", ca, err)
		}
		if ok {
			defer l.releaseBudgetLock(ctx, ca, token)
			return fn()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(budgetLockBackoff):
		}
	}
	return ErrBudgetLockContended
}

func (l *Limiter) releaseBudgetLock(ctx context.Context, ca, token string) {
	v, err := l.rdb.Get(ctx, budgetLockKey(ca)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) && ctx.Err() == nil {
			l.logger.Warn("acme budget lock release check failed (lock expires by TTL)", "ca", ca, "err", err)
		}
		return
	}
	if v != token {
		return
	}
	if err := l.rdb.Del(ctx, budgetLockKey(ca)).Err(); err != nil && ctx.Err() == nil {
		l.logger.Warn("acme budget lock release failed (lock expires by TTL)", "ca", ca, "err", err)
	}
}

func (l *Limiter) parseBucket(b Bucket, vals []any, now time.Time) bucketState {
	if len(vals) != 2 || vals[0] == nil || vals[1] == nil {
		return bucketState{tokens: b.Capacity, at: now}
	}
	ts, okT := vals[0].(string)
	as, okA := vals[1].(string)
	t, errT := strconv.ParseFloat(ts, 64)
	at, errA := strconv.ParseInt(as, 10, 64)
	if !okT || !okA || errT != nil || errA != nil {
		l.logger.Warn("unparseable acme budget (treated as full)", "bucket", b.Key, "err", errors.Join(errT, errA))
		return bucketState{tokens: b.Capacity, at: now}
	}
	return bucketState{tokens: t, at: time.UnixMilli(at)}
}

func (l *Limiter) readBuckets(ctx context.Context, bs []Bucket, now time.Time) ([]bucketState, error) {
	pipe := l.rdb.Pipeline()
	cmds := make([]*redis.SliceCmd, len(bs))
	for i, b := range bs {
		cmds[i] = pipe.HMGet(ctx, budgetKey(b), "t", "at")
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("read acme budgets: %w", err)
	}
	out := make([]bucketState, len(bs))
	for i, b := range bs {
		out[i] = l.parseBucket(b, cmds[i].Val(), now)
	}
	return out, nil
}

func writeBucket(ctx context.Context, pipe redis.Pipeliner, b Bucket, s bucketState, now time.Time) {
	key := budgetKey(b)
	pipe.HSet(ctx, key, "t", strconv.FormatFloat(s.tokens, 'f', -1, 64), "at", strconv.FormatInt(s.at.UnixMilli(), 10))
	ttl := time.Duration((b.Capacity-min(s.tokens, b.Capacity))*float64(b.Refill)) + budgetKeyMargin
	if s.at.After(now) {
		ttl += s.at.Sub(now)
	}
	pipe.PExpire(ctx, key, ttl)
}

func (l *Limiter) inflightCounts(ctx context.Context, bs []Bucket, live []string, now time.Time) ([]int64, error) {
	out := make([]int64, len(bs))
	if len(live) == 0 {
		return out, nil
	}
	pipe := l.rdb.Pipeline()
	floor := strconv.FormatInt(now.UnixMilli(), 10)
	cmds := make([][]*redis.IntCmd, len(bs))
	for i, b := range bs {
		for _, node := range live {
			key := inflightKey(b, node)
			pipe.ZRemRangeByScore(ctx, key, "-inf", floor)
			cmds[i] = append(cmds[i], pipe.ZCard(ctx, key))
		}
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("count in-flight acme orders: %w", err)
	}
	for i := range bs {
		for _, c := range cmds[i] {
			out[i] += c.Val()
		}
	}
	return out, nil
}

func (l *Limiter) ReserveACME(ctx context.Context, ca string, bs []Bucket, node, member string, deadline time.Time, live []string) (bool, time.Duration, error) {
	if len(bs) == 0 {
		return true, 0, nil
	}
	var (
		ok   bool
		wait time.Duration
	)
	err := l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		states, err := l.readBuckets(ctx, bs, now)
		if err != nil {
			return err
		}
		held, err := l.inflightCounts(ctx, bs, live, now)
		if err != nil {
			return err
		}
		for i, b := range bs {
			if b.tokensAt(states[i], now)-float64(held[i]) < 1 {
				wait = max(wait, b.waitFor(states[i], now, float64(held[i])+1), time.Second)
			}
		}
		if wait > 0 {
			return nil
		}
		pipe := l.rdb.Pipeline()
		for _, b := range bs {
			key := inflightKey(b, node)
			pipe.ZAdd(ctx, key, redis.Z{Score: float64(deadline.UnixMilli()), Member: member})
			pipe.ExpireNX(ctx, key, deadline.Sub(now)+inflightKeyMargin)
			pipe.ExpireGT(ctx, key, deadline.Sub(now)+inflightKeyMargin)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("reserve acme budget: %w", err)
		}
		ok = true
		return nil
	})
	return ok, wait, err
}

func (l *Limiter) CommitACME(ctx context.Context, ca string, b Bucket, node, member string) error {
	return l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		states, err := l.readBuckets(ctx, []Bucket{b}, now)
		if err != nil {
			return err
		}
		pipe := l.rdb.Pipeline()
		writeBucket(ctx, pipe, b, b.spend(states[0], now), now)
		pipe.ZRem(ctx, inflightKey(b, node), member)
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("spend acme budget %s: %w", b.Key, err)
		}
		return nil
	})
}

func (l *Limiter) ReleaseACME(ctx context.Context, bs []Bucket, node, member string) error {
	if len(bs) == 0 {
		return nil
	}
	pipe := l.rdb.Pipeline()
	for _, b := range bs {
		pipe.ZRem(ctx, inflightKey(b, node), member)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("release acme budget: %w", err)
	}
	return nil
}

func (l *Limiter) TakeACME(ctx context.Context, ca string, bs []Bucket) (time.Duration, error) {
	if len(bs) == 0 {
		return 0, nil
	}
	var wait time.Duration
	err := l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		states, err := l.readBuckets(ctx, bs, now)
		if err != nil {
			return err
		}
		for i, b := range bs {
			if b.tokensAt(states[i], now) < 1 {
				wait = max(wait, b.waitFor(states[i], now, 1), time.Millisecond)
			}
		}
		if wait > 0 {
			return nil
		}
		pipe := l.rdb.Pipeline()
		for i, b := range bs {
			writeBucket(ctx, pipe, b, b.spend(states[i], now), now)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("take acme request budget: %w", err)
		}
		return nil
	})
	return wait, err
}

func (l *Limiter) ResyncACME(ctx context.Context, ca string, bs []Bucket, retryAfter time.Duration) error {
	if len(bs) == 0 {
		return nil
	}
	return l.withBudgetLock(ctx, ca, func() error {
		now := l.now()
		pipe := l.rdb.Pipeline()
		for _, b := range bs {
			writeBucket(ctx, pipe, b, bucketState{tokens: 0, at: now.Add(retryAfter - b.Refill)}, now)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("resync acme budgets: %w", err)
		}
		return nil
	})
}

func (l *Limiter) ACMEBudgetLevel(ctx context.Context, b Bucket, live []string) (float64, error) {
	if b.Capacity <= 0 {
		return 0, nil
	}
	now := l.now()
	states, err := l.readBuckets(ctx, []Bucket{b}, now)
	if err != nil {
		return 0, err
	}
	held, err := l.inflightCounts(ctx, []Bucket{b}, live, now)
	if err != nil {
		return 0, err
	}
	return max(0, min(1, (b.tokensAt(states[0], now)-float64(held[0]))/b.Capacity)), nil
}
```

DoD:
- [ ] No Lua/WATCH/MULTI; every write pipelines its TTL.

### [ ] T4.3 — tests (`internal/limit`, miniredis + `SetClock`)

| Test | Verifies |
|---|---|
| `TestSetCACooldown_NeverShortens` | existing 10 s + new 2 s → 10 s; existing 2 s + new 10 s → 10 s; absent → set; sub-second → 1 s; a fractional 7.4 s over an existing 7.2 s → 8 s (rounded up to whole seconds, so `EXPIRE GT` and `SET NX EX` carry the same value) |
| `TestRate_Bucket` | 50/168h → capacity 50, refill 201.6 min; burst overrides capacity; count 0 → refill = period |
| `TestReserveACME_Reserves` | full bucket → ok, member in `acme:inflight:{key}:{node}` with score = deadline and a TTL |
| `TestReserveACME_InflightCounts` | capacity 2: two reservations ok, third refused with wait > 0 |
| `TestReserveACME_DeadNodeNotCounted` | reservation of a node not in `live` does not reduce the budget |
| `TestReserveACME_ExpiredNotCounted` | a member past its deadline is pruned and not counted |
| `TestReserveACME_WaitUntilNextToken` | empty bucket, refill 10 s, 4 s elapsed → wait 6 s; capacity 1 + 1 in flight → wait = refill |
| `TestCommitACME_SpendsAndDrops` | tokens −1, member removed, key TTL set; works without a prior reservation |
| `TestReleaseACME_NoSpend` | member removed, tokens unchanged |
| `TestTakeACME_TakeOrWait` | takes while ≥ 1 token; then returns the wait to the next token without spending |
| `TestResyncACME_NextTokenAtRetryAfter` | retryAfter < refill and > refill: fewer than 1 token now, and `TakeACME` waits exactly `retryAfter` (1 token at now + retryAfter) |
| `TestACMEBudgetLevel_Ratio` | (tokens − in-flight) / capacity clamped to [0,1]; capacity 0 → 0 |
| `TestACMEBudget_UnparseableTreatedFull` | garbage hash → full bucket + Warn logged |
| `TestBudgetLock_Contended` | lock held by another token → `ErrBudgetLockContended`; cancelled ctx → ctx error |
| `TestBudgetKeys_AllHaveTTL` | after reserve/commit/take/resync, every `acme-budget:*` / `acme:inflight:*` key has a TTL |
| `TestReserveACME_InflightTTLNeverShortened` | a reservation with a 10 min deadline, then one with 30 s on the same node → the in-flight key's TTL is still ≥ 10 min, and both members count |

Existing `SetCACooldown` tests asserting that a shorter value overwrites are updated to the never-shorten rule.

DoD:
- [ ] Tests added and adapted.

---

## [ ] US5 — Configuration surface

This story adds the new flags for GTS accounts, budgets, attempt deadlines and polling, and makes every CA optional. The GTS EAB flags go away in US6 (A6.7.4/A6.7.5), together with their only consumer (`acmewire.go`), so every story's commit compiles.

- [ ] AC1: Defaults equal the decision record. `Validate()` rejects:
  - malformed rates;
  - bad, duplicate or colliding GTS ids;
  - non-positive durations;
  - a lone ZeroSSL EAB value;
  - no enabled CA.
- [ ] AC2: `UsesChallenge` / `ServesPlainHTTP` consider only enabled CAs.
- [ ] AC3: Every test config validates, every hermetic tier that lists a GTS account owns its registered key, and a test that relied on ZeroSSL being in the chain still has it.

### [ ] T5.1 — rate parser

- [ ] A5.1.1 `internal/config/rate.go` (create):

```go
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Rate struct {
	Count  int
	Period time.Duration
	Burst  int
}

func ParseRate(s string) (Rate, error) {
	spec, burst, hasBurst := strings.Cut(strings.TrimSpace(s), ":")
	count, period, ok := strings.Cut(spec, "/")
	if !ok {
		return Rate{}, fmt.Errorf("rate %q must be <count>/<period>[:<burst>]", s)
	}
	n, err := strconv.Atoi(count)
	if err != nil || n < 1 {
		return Rate{}, fmt.Errorf("rate %q: count must be a positive integer", s)
	}
	d, err := time.ParseDuration(period)
	if err != nil || d <= 0 {
		return Rate{}, fmt.Errorf("rate %q: period must be a positive duration", s)
	}
	r := Rate{Count: n, Period: d, Burst: n}
	if hasBurst {
		b, err := strconv.Atoi(burst)
		if err != nil || b < 1 {
			return Rate{}, fmt.Errorf("rate %q: burst must be a positive integer", s)
		}
		r.Burst = b
	}
	return r, nil
}
```

DoD:
- [ ] Parser in place.

### [ ] T5.2 — flags, enabled CAs, validation

- [ ] A5.2.1 `internal/config/config.go` (modify):
  - **Help texts:**
    - `--acme-dir-le` becomes `"LE ACME directory; empty leaves Let's Encrypt out of the chain."`;
    - `--acme-account-dir` becomes `"Directory holding the ACME account keys (<dir>/accounts/<id>.key: Let's Encrypt and ZeroSSL keys are created per node, GTS keys must already exist) + reserved-host self-certs. Required for serve."` (the old "persisted per-CA ACME account keys" is made wrong);
    - in the help of `--acme-cooldown-default`, `--acme-backoff-initial` and `--acme-backoff-max`, "Per-CA"/"per-CA" → "Per-account"/"per-account";
    - in the help of `--acme-cooldown-default`, the parenthetical " (an explicit Retry-After is honored as-is)" is removed (made wrong: the wait-until is never shortened). It reads `"Per-account cooldown when a CA answers rate-limited WITHOUT a Retry-After header."`.
  - **Added** after `ACMEDNSProvider`:

```go
	ACMEGTSAccounts []string `name:"acme-gts-account" help:"GTS ACME account ids, one per Public CA project (empty = no GTS); each EXISTING account's key lives at <acme-account-dir>/accounts/<id>.key (tunneld never creates GTS accounts). Repeatable."`

	ACMEBudgetLEDomain        string `name:"acme-budget-le-domain" default:"50/168h" help:"Let's Encrypt new certificates per registered domain, <count>/<period>[:<burst>]."`
	ACMEBudgetLEOrders        string `name:"acme-budget-le-orders" default:"300/3h" help:"Let's Encrypt new orders per account, <count>/<period>[:<burst>]."`
	ACMEBudgetLEName          string `name:"acme-budget-le-name" default:"5/168h" help:"Let's Encrypt certificates per exact name, <count>/<period>[:<burst>]."`
	ACMEBudgetGTSOrders       string `name:"acme-budget-gts-orders" default:"100/1h" help:"GTS new orders per account, <count>/<period>[:<burst>]."`
	ACMEBudgetGTSRequests     string `name:"acme-budget-gts-requests" default:"120/1m" help:"GTS ACME requests per account, <count>/<period>[:<burst>]."`
	ACMEBudgetGTSCertPolls    string `name:"acme-budget-gts-cert-polls" default:"50/1m" help:"GTS requests to /cert/ URLs per account (within the request budget), <count>/<period>[:<burst>]."`
	ACMEBudgetZeroSSLOrders   string `name:"acme-budget-zerossl-orders" default:"200/1h:40" help:"ZeroSSL new orders per account, <count>/<period>[:<burst>]."`
	ACMEBudgetZeroSSLRequests string `name:"acme-budget-zerossl-requests" default:"240/1m" help:"ZeroSSL ACME requests per account, <count>/<period>[:<burst>]."`

	ACMEAttemptTimeoutLE      time.Duration `name:"acme-attempt-timeout-le" default:"20s" help:"Deadline of one Let's Encrypt order attempt."`
	ACMEAttemptTimeoutGTS     time.Duration `name:"acme-attempt-timeout-gts" default:"40s" help:"Deadline of one GTS order attempt."`
	ACMEAttemptTimeoutZeroSSL time.Duration `name:"acme-attempt-timeout-zerossl" default:"90s" help:"Deadline of one ZeroSSL order attempt."`
	ACMEPollFirstLE           time.Duration `name:"acme-poll-first-le" default:"2s" help:"Delay of the first certificate poll after a Let's Encrypt order is finalized."`
	ACMEPollFirstGTS          time.Duration `name:"acme-poll-first-gts" default:"5.6s" help:"Delay of the first certificate poll after a GTS order is finalized."`
	ACMEPollFirstZeroSSL      time.Duration `name:"acme-poll-first-zerossl" default:"15.2s" help:"Delay of the first certificate poll after a ZeroSSL order is finalized."`
	ACMEPollInterval          time.Duration `name:"acme-poll-interval" default:"2s" help:"Spacing of the following certificate polls."`
```

  - **Enabled-CA methods** replace `UsesChallenge`:

```go
func (c ServeCmd) LEEnabled() bool      { return c.ACMEDirLE != "" }
func (c ServeCmd) GTSEnabled() bool     { return len(c.ACMEGTSAccounts) > 0 }
func (c ServeCmd) ZeroSSLEnabled() bool { return c.ACMEEABZeroSSLKID != "" && c.ACMEEABZeroSSLHMAC != "" }

func (c ServeCmd) UsesChallenge(method string) bool {
	return (c.LEEnabled() && c.ACMEChallengeLE == method) ||
		(c.GTSEnabled() && c.ACMEChallengeGTS == method) ||
		(c.ZeroSSLEnabled() && c.ACMEChallengeZeroSSL == method)
}
```

- [ ] A5.2.2 same file, `Validate()`:
  - **Imports:** add `regexp` (`errors` is already imported).
  - **URL check:** in the URL loop, `--acme-dir-le` is checked only when `c.LEEnabled()`. The loop's slice is built conditionally:

```go
	urls := []struct{ name, v string }{
		{"--acme-dir-gts", c.ACMEDirGTS},
		{"--acme-dir-zerossl", c.ACMEDirZeroSSL},
		{"--attest-root-url", c.AttestRootURL},
		{"--attest-status-url", c.AttestStatusURL},
		{"--s3-endpoint", c.S3Endpoint},
	}
	if c.LEEnabled() {
		urls = append(urls, struct{ name, v string }{"--acme-dir-le", c.ACMEDirLE})
	}
	for _, u := range urls {
```

  - **Durations:** the seven new durations join the `d.v <= 0` loop.
  - **After that loop** (next to the T1.2 check):

```go
	for _, r := range []struct{ name, v string }{
		{"--acme-budget-le-domain", c.ACMEBudgetLEDomain},
		{"--acme-budget-le-orders", c.ACMEBudgetLEOrders},
		{"--acme-budget-le-name", c.ACMEBudgetLEName},
		{"--acme-budget-gts-orders", c.ACMEBudgetGTSOrders},
		{"--acme-budget-gts-requests", c.ACMEBudgetGTSRequests},
		{"--acme-budget-gts-cert-polls", c.ACMEBudgetGTSCertPolls},
		{"--acme-budget-zerossl-orders", c.ACMEBudgetZeroSSLOrders},
		{"--acme-budget-zerossl-requests", c.ACMEBudgetZeroSSLRequests},
	} {
		if _, err := ParseRate(r.v); err != nil {
			return fmt.Errorf("%s: %w", r.name, err)
		}
	}
	if err := validGTSAccounts(c.ACMEGTSAccounts); err != nil {
		return err
	}
	if (c.ACMEEABZeroSSLKID == "") != (c.ACMEEABZeroSSLHMAC == "") {
		return errors.New("--acme-eab-zerossl-kid and --acme-eab-zerossl-hmac must be set together (ZeroSSL is used only with both)")
	}
	if !c.LEEnabled() && !c.GTSEnabled() && !c.ZeroSSLEnabled() {
		return errors.New("no ACME CA is enabled: keep --acme-dir-le, list a --acme-gts-account, or set the ZeroSSL EAB pair")
	}
```

  - **At package scope:**

```go
var gtsAccountRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validGTSAccounts(ids []string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		switch {
		case !gtsAccountRe.MatchString(id):
			return fmt.Errorf("--acme-gts-account %q must be lowercase letters, digits and hyphens", id)
		case id == "letsencrypt" || id == "zerossl":
			return fmt.Errorf("--acme-gts-account %q collides with another CA's account key file", id)
		case seen[id]:
			return fmt.Errorf("--acme-gts-account %q is listed twice", id)
		}
		seen[id] = true
	}
	return nil
}
```

- [ ] A5.2.3 `deploy/tunneld.env.example` (modify): add `TUNNELD_ACME_GTS_ACCOUNT=` (no comment) right after the `TUNNELD_ACME_CHALLENGE_ZEROSSL=http-01` line.

DoD:
- [ ] Flags, enabled-CA logic and template consistent.

### [ ] T5.3 — test configs + test GTS accounts

Test literals bypass kong defaults; a hermetic tier that lists a GTS account must own its registered key.

- [ ] A5.3.1 `internal/tunneltest/acme_config.go` (create):

```go
package tunneltest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
)

func LooseACMEBudgets(c *config.ServeCmd) {
	c.ACMEGTSAccounts = []string{"gts"}
	for _, r := range []*string{&c.ACMEBudgetLEDomain, &c.ACMEBudgetLEOrders, &c.ACMEBudgetLEName,
		&c.ACMEBudgetGTSOrders, &c.ACMEBudgetGTSRequests, &c.ACMEBudgetGTSCertPolls,
		&c.ACMEBudgetZeroSSLOrders, &c.ACMEBudgetZeroSSLRequests} {
		*r = "100000/1m"
	}
	c.ACMEAttemptTimeoutLE, c.ACMEAttemptTimeoutGTS, c.ACMEAttemptTimeoutZeroSSL = time.Minute, time.Minute, time.Minute
	c.ACMEPollFirstLE, c.ACMEPollFirstGTS, c.ACMEPollFirstZeroSSL = 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	c.ACMEPollInterval = 100 * time.Millisecond
}

type testACMEUser struct {
	key crypto.Signer
	reg *legoacme.ExtendedAccount
}

func (u *testACMEUser) GetEmail() string                           { return "ops@example.test" }
func (u *testACMEUser) GetRegistration() *legoacme.ExtendedAccount { return u.reg }
func (u *testACMEUser) GetPrivateKey() crypto.Signer               { return u.key }

func WriteACMEAccountKey(t *testing.T, accountDir, id string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(accountDir, "accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return key
}

func RegisterACMEAccountKey(t *testing.T, accountDir, id, dirURL string) {
	t.Helper()
	user := &testACMEUser{key: WriteACMEAccountKey(t, accountDir, id)}
	lc := lego.NewConfig(user)
	lc.CADirURL = dirURL
	client, err := lego.NewClient(lc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] A5.3.2 (modify) the shared test harnesses. Every config that reaches `Validate()` or `server.Run` gets the loose budgets and an existing `gts` key. A Pebble tier registers that key at Pebble first. lego's `NewConfig` reads `LEGO_CA_CERTIFICATES` on every call (`lego/client_config.go` `initCertPool`), and both harnesses set it before this point.
  - **`internal/server/server_test.go` `lifecycleConfig`:** `return config.ServeCmd{…}` becomes `cfg := config.ServeCmd{…}` followed by:

```go
	tunneltest.LooseACMEBudgets(&cfg)
	tunneltest.WriteACMEAccountKey(t, acmeDir, "gts")
	return cfg
```

  - **`internal/server/integration_test.go` `itServeConfig`:** the same change (`tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts")`). Its callers that point the directories at an unreachable or hanging endpoint need nothing else.
  - **`startIntegrationServer` and `startChallengeServer`:** right after the `itServeConfig(…)` call, before the `mutate` loop (inside the attempt loop in `startChallengeServer`):

```go
	tunneltest.RegisterACMEAccountKey(t, cfg.ACMEAccountDir, "gts", pebble.DirectoryURL)
```

  - **`e2e/e2e_test.go` `runReplicaOnce`:** right after the `cfg := config.ServeCmd{…}` literal, before `cfg.Validate()`:

```go
	tunneltest.LooseACMEBudgets(&cfg)
	tunneltest.RegisterACMEAccountKey(t, cfg.ACMEAccountDir, "gts", inf.pebble.DirectoryURL)
```

  - **Not changed:** `schedulers_test.go`, whose literals feed only `validNameFunc`. The `acmewire_test.go` literals change in US6 (T6.8), together with `buildACMEChain`.
- [ ] A5.3.3 `internal/config/config_test.go` (modify):
  - **Base valid literal (`validCfg`)** gains the lines below, directly, without tunneltest (tunneltest imports config). The ZeroSSL EAB pair keeps ZeroSSL enabled, so the existing ZeroSSL cases of `TestValidate_ACMEHTTPListen` ("http-01 malformed/empty") and `TestValidate_DNSProviderOnlyWithDNS01` ("zerossl dns-01 without provider") keep their meaning:

```go
		ACMEEABZeroSSLKID:         "k",
		ACMEEABZeroSSLHMAC:        "h",
		ACMEGTSAccounts:           []string{"gts"},
		ACMEBudgetLEDomain:        "50/168h",
		ACMEBudgetLEOrders:        "300/3h",
		ACMEBudgetLEName:          "5/168h",
		ACMEBudgetGTSOrders:       "100/1h",
		ACMEBudgetGTSRequests:     "120/1m",
		ACMEBudgetGTSCertPolls:    "50/1m",
		ACMEBudgetZeroSSLOrders:   "200/1h:40",
		ACMEBudgetZeroSSLRequests: "240/1m",
		ACMEAttemptTimeoutLE:      20 * time.Second,
		ACMEAttemptTimeoutGTS:     40 * time.Second,
		ACMEAttemptTimeoutZeroSSL: 90 * time.Second,
		ACMEPollFirstLE:           2 * time.Second,
		ACMEPollFirstGTS:          5600 * time.Millisecond,
		ACMEPollFirstZeroSSL:      15200 * time.Millisecond,
		ACMEPollInterval:          2 * time.Second,
```

  - **`TestServeCmd_UsesChallenge` and `TestServesPlainHTTP`:** their literals enable all three CAs (`ACMEDirLE: "https://le.example.test/dir"`, `ACMEGTSAccounts: []string{"gts"}`, `ACMEEABZeroSSLKID: "k"`, `ACMEEABZeroSSLHMAC: "h"`), so the existing cases keep their meaning.
- [ ] A5.3.4 `staging/staging_test.go` (modify):
  - the `config.ServeCmd` literal gains the 16 budget/deadline/poll/GTS field lines of A5.3.3 (not its `k`/`h` EAB pair; A5.3.5 sets this tier's own);
  - `writeAccountKey(t, accountDir, "gts", env.gtsKey)` runs in EVERY case, so `if tc.writeGTSKey` goes away. The `writeGTSKey` field is removed, and the LE cases' GTS directory stays unreachable.
- [ ] A5.3.5 ZeroSSL in the test tiers.
  - **Pebble tiers** (integration, e2e) set no EAB, so ZeroSSL is out of them; the US10 scenarios rely on that.
  - **Two configs keep ZeroSSL enabled**, so their chain and their `:80` binding stay as today:
    - `internal/server/server_test.go` `TestRun_ACMEHTTPBindFailureIsFatal`: `cfg.ACMEEABZeroSSLKID, cfg.ACMEEABZeroSSLHMAC = "changeme", "changeme"` next to its `ACMEChallengeZeroSSL` line. Its ZeroSSL HTTP-01 is what binds `:80`.
    - The `staging/staging_test.go` literal: `ACMEEABZeroSSLKID: "changeme", ACMEEABZeroSSLHMAC: "changeme"`. Its ZeroSSL directory is unreachable.

- [ ] A5.3.6 `internal/server/acmewire_test.go` (modify). A5.2.1 makes a CA's challenge method count only when that CA is enabled, and LE is enabled only with a directory URL. So the two literals whose cases depend on LE gain `ACMEDirLE: "https://le.example.test/dir"` in this story, keeping them passing at its commit:
  - `TestBuildACMEChain_DNSProviderOnlyWhenUsed`: the "le dns-01" case must still see LE's dns-01 and log the provider warning;
  - `TestBuildACMEChain_CorruptAccountKeyAborts`: LE must stay enabled, so its corrupt key is read once US6 builds only enabled CAs.

DoD:
- [ ] Every test config sets the new fields; every listed GTS account has its key.

### [ ] T5.4 — tests (`internal/config`)

| Test | Verifies |
|---|---|
| `TestParseRate_Variants` (table) | `50/168h`, `200/1h:40`, spaces; errors: no slash, count 0/neg/non-int, bad/zero period, burst 0/non-int |
| `TestValidate_ACMEBudgetFlags` | each of the 8 flags with `bad` → error naming the flag |
| `TestValidate_GTSAccounts` | `[]` ok (no GTS); `["Gts"]`, `["gts","gts"]`, `["zerossl"]` rejected; `["gts-1","gts-2"]` ok |
| `TestValidate_ACMEDurationsPositive` | each new duration 0 → error |
| `TestValidate_ZeroSSLEABPair` | kid without hmac and vice versa → error; both or neither ok |
| `TestValidate_NoCAEnabled` | empty LE dir, no GTS, no ZeroSSL EAB → error; any one enabled → ok; empty LE dir is not URL-checked |
| `TestUsesChallenge_OnlyEnabledCAs` | a disabled CA's method is ignored (e.g. ZeroSSL `http-01` without EAB → `ServesPlainHTTP` false with HTTPS dial-backs) |
| `TestServeCmd_ACMEDefaults` | kong-parsed defaults equal the decision record (GTS list empty) and validate |

DoD:
- [ ] Tests added and adapted.

---

## [ ] US6 — ACME chain: accounts, budgets, HTTP layer, selection, server wiring

The chain becomes account-aware (several GTS accounts, looked up by key; optional CAs), reserves budget before every order, and wraps lego's HTTP client so wait-until, request budgets and the poll schedule hold for every request. It is wired into `server.Run` in this same story, so the story's commit builds and runs a working server.

- [ ] AC1: An account without budget or under a wait-until gets ZERO requests, tracked or not.
- [ ] AC2: The first 429 ends the attempt; only the named bucket is resynced; the wait-until is never shortened.
- [ ] AC3: Settlement follows the decision record; an abandoned attempt removes its pending TLS-ALPN challenge.
- [ ] AC4: GTS accounts are tried by remaining order budget, random among equals (`crypto/rand`).
- [ ] AC5: Every account unavailable → `rateLimited(earliest + 1–10 s)`; a run never exceeds its budget (290 s).
- [ ] AC6: A GTS account is only looked up (`ResolveAccountByKey`), never registered.
- [ ] AC7: `server.Run` builds the chain from config. Only enabled CAs are in it, and a listed GTS id without its key file fails startup. `--acme-eab-gts-*` and `TUNNELD_ACME_EAB_GTS_*` no longer exist.
- [ ] AC8: `tunneld_acme_rate_limited_total{ca}` counts every 429 a CA answers, and is pre-created at zero for every CA.

### [ ] T6.1 — per-attempt order tracker

- [ ] A6.1.1 `internal/acme/track.go` (create):

```go
package acme

import (
	"context"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

type trackKey struct{}

type orderTrack struct {
	name        limit.Bucket
	domain      limit.Bucket
	mu          sync.Mutex
	orderURL    string
	finalizeURL string
	finalizedAt time.Time
	lastPoll    time.Time
	created     bool
	cleanups    []func(context.Context) error
	limited     chan time.Duration
	done        chan struct{}
	once        sync.Once
}

type orderOutcome struct {
	created   bool
	finalized bool
	abandoned bool
}

func newOrderTrack(name, domain limit.Bucket) *orderTrack {
	return &orderTrack{name: name, domain: domain, limited: make(chan time.Duration, 1), done: make(chan struct{})}
}

func withTrack(ctx context.Context, t *orderTrack) context.Context {
	return context.WithValue(ctx, trackKey{}, t)
}

func trackFrom(ctx context.Context) *orderTrack {
	t, _ := ctx.Value(trackKey{}).(*orderTrack)
	return t
}

func withoutTrack(ctx context.Context) context.Context {
	return context.WithValue(ctx, trackKey{}, (*orderTrack)(nil))
}

func (t *orderTrack) abandon() { t.once.Do(func() { close(t.done) }) }

func (t *orderTrack) abandoned() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

func (t *orderTrack) signalLimited(d time.Duration) {
	select {
	case t.limited <- d:
	default:
	}
}

func (t *orderTrack) onAbandon(f func(context.Context) error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanups = append(t.cleanups, f)
}

func (t *orderTrack) takeCleanups() []func(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	fs := t.cleanups
	t.cleanups = nil
	return fs
}

func (t *orderTrack) hasOrder() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.created
}

func (t *orderTrack) setOrder(orderURL, finalizeURL string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.orderURL, t.finalizeURL, t.created = orderURL, finalizeURL, true
}

func (t *orderTrack) isFinalize(u string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.finalizeURL != "" && u == t.finalizeURL
}

func (t *orderTrack) markFinalized(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finalizedAt = at
}

func (t *orderTrack) isPoll(u string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.finalizedAt.IsZero() && u == t.orderURL
}

func (t *orderTrack) pollDue(first, every time.Duration) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	due := t.finalizedAt.Add(first)
	if !t.lastPoll.IsZero() {
		if next := t.lastPoll.Add(every); next.After(due) {
			due = next
		}
	}
	return due
}

func (t *orderTrack) markPoll(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastPoll = at
}

func (t *orderTrack) outcome() orderOutcome {
	t.mu.Lock()
	defer t.mu.Unlock()
	return orderOutcome{created: t.created, finalized: !t.finalizedAt.IsZero(), abandoned: t.abandoned()}
}
```

- [ ] A6.1.2 `internal/acme/challenge_providers.go` (modify) `tlsALPNProvider.Present`:

```go
func (p *tlsALPNProvider) Present(ctx context.Context, domain, _, keyAuth string) error {
	if err := p.s.PutTLSALPN(ctx, domain, keyAuth); err != nil {
		return err
	}
	if tr := trackFrom(ctx); tr != nil {
		tr.onAbandon(func(cctx context.Context) error { return p.s.DeleteTLSALPN(cctx, domain, keyAuth) })
	}
	return nil
}
```

Context:
- lego calls `Present(ctx, …)` with the context passed to `ObtainForCSR` (`tlsalpn01.Challenge.Solve`), so the attempt's tracker is visible.
- `DeleteTLSALPN` is GET-compare-DEL, so a later run of lego's own `CleanUp` (or a newer challenge) is unaffected.

DoD:
- [ ] Tracker is concurrency-safe; a presented TLS-ALPN challenge is removable on abandon.

### [ ] T6.2 — budget policy

- [ ] A6.2.1 `internal/acme/budget.go` (create):

```go
package acme

import (
	"context"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

type Budgets struct {
	Domain          string
	LEDomain        limit.Rate
	LEOrders        limit.Rate
	LEName          limit.Rate
	GTSOrders       limit.Rate
	GTSRequests     limit.Rate
	GTSCertPolls    limit.Rate
	ZeroSSLOrders   limit.Rate
	ZeroSSLRequests limit.Rate
}

type NodeLister interface {
	LiveNodeIDs(ctx context.Context) ([]string, error)
}

type BudgetLevel struct {
	CA      string
	Account string
	Budget  string
	Ratio   float64
}

type account struct {
	ca      string
	id      string
	label   string
	timeout time.Duration
	issuer  caIssuer
}

type namedBucket struct {
	name string
	b    limit.Bucket
}

func registeredDomain(fqdn string) string {
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	d, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return name
	}
	return d
}

func (b Budgets) leDomain(fqdn string) limit.Bucket {
	return b.LEDomain.Bucket("letsencrypt:domain:" + registeredDomain(fqdn))
}
func (b Budgets) leOrders(a *account) limit.Bucket {
	return b.LEOrders.Bucket("letsencrypt:orders:" + a.id)
}
func (b Budgets) leName(fqdn string) limit.Bucket { return b.LEName.Bucket("letsencrypt:name:" + fqdn) }
func (b Budgets) gtsOrders(a *account) limit.Bucket { return b.GTSOrders.Bucket("gts:orders:" + a.id) }
func (b Budgets) gtsRequests(a *account) limit.Bucket {
	return b.GTSRequests.Bucket("gts:requests:" + a.id)
}
func (b Budgets) gtsCertPolls(a *account) limit.Bucket { return b.GTSCertPolls.Bucket("gts:cert:" + a.id) }
func (b Budgets) zerosslOrders(a *account) limit.Bucket {
	return b.ZeroSSLOrders.Bucket("zerossl:orders:" + a.id)
}
func (b Budgets) zerosslRequests(a *account) limit.Bucket {
	return b.ZeroSSLRequests.Bucket("zerossl:requests:" + a.id)
}

func (b Budgets) orderBuckets(a *account, fqdn string, leRenewal bool) (onCreate, onSuccess []limit.Bucket) {
	switch a.ca {
	case CALetsEncrypt:
		if leRenewal {
			return nil, []limit.Bucket{b.leName(fqdn)}
		}
		return []limit.Bucket{b.leOrders(a)}, []limit.Bucket{b.leName(fqdn), b.leDomain(fqdn)}
	case CAGTS:
		return []limit.Bucket{b.gtsOrders(a)}, nil
	case CAZeroSSL:
		return []limit.Bucket{b.zerosslOrders(a)}, nil
	}
	return nil, nil
}

func (b Budgets) requestBuckets(a *account, req *http.Request) []limit.Bucket {
	switch a.ca {
	case CAGTS:
		if strings.Contains(req.URL.Path, "/cert/") {
			return []limit.Bucket{b.gtsRequests(a), b.gtsCertPolls(a)}
		}
		return []limit.Bucket{b.gtsRequests(a)}
	case CAZeroSSL:
		return []limit.Bucket{b.zerosslRequests(a)}
	}
	return nil
}

func (b Budgets) resyncBuckets(a *account, detail string, tr *orderTrack) []limit.Bucket {
	switch a.ca {
	case CALetsEncrypt:
		switch {
		case strings.Contains(detail, "#new-orders-per-account"):
			return []limit.Bucket{b.leOrders(a)}
		case tr == nil:
			return nil
		case strings.Contains(detail, "#new-certificates-per-registered-domain") && tr.domain.Key != "":
			return []limit.Bucket{tr.domain}
		case strings.Contains(detail, "#new-certificates-per-exact-set-of-identifiers") && tr.name.Key != "":
			return []limit.Bucket{tr.name}
		}
		return nil
	case CAGTS:
		if strings.Contains(detail, `resource "cert"`) {
			return []limit.Bucket{b.gtsCertPolls(a)}
		}
		return []limit.Bucket{b.gtsRequests(a)}
	case CAZeroSSL:
		return []limit.Bucket{b.zerosslRequests(a)}
	}
	return nil
}

func (b Budgets) accountBuckets(a *account) []namedBucket {
	switch a.ca {
	case CALetsEncrypt:
		return []namedBucket{{"domain", b.leDomain(b.Domain)}, {"orders", b.leOrders(a)}}
	case CAGTS:
		return []namedBucket{{"orders", b.gtsOrders(a)}, {"requests", b.gtsRequests(a)}, {"cert-polls", b.gtsCertPolls(a)}}
	case CAZeroSSL:
		return []namedBucket{{"orders", b.zerosslOrders(a)}, {"requests", b.zerosslRequests(a)}}
	}
	return nil
}

func (b Budgets) ordersBucket(a *account) limit.Bucket {
	switch a.ca {
	case CAGTS:
		return b.gtsOrders(a)
	case CAZeroSSL:
		return b.zerosslOrders(a)
	}
	return b.leOrders(a)
}
```

Context:
- The LE anchors are the ones Boulder appends to each rate-limit error's detail (`errors/errors.go`).
- `registeredDomain` falls back to the name itself when it has no eTLD+1. That happens only for a public suffix, which LE cannot issue for.
- `Budgets.Domain` (the tunnel domain) only labels the LE domain budget in the metrics.

- [ ] A6.2.2 `go.mod` / `go.sum` (modify): `make tidy` moves `golang.org/x/net v0.61.0` (the latest version) from the `// indirect` block to the direct requirements, now that `budget.go` imports `publicsuffix`. The tidied files are committed with this story, so CI's tidy-drift check passes on its commit.

DoD:
- [ ] Policy matches the decision record bucket for bucket; `go.mod` lists x/net as a direct requirement.

### [ ] T6.3 — budgeted HTTP transport

- [ ] A6.3.1 (modify) the 429 counter, together with every `Recorder` implementation, so this story compiles (the server passes `metrics.PromRecorder` as the `acme.Recorder`). No comment is added; the new struct field gets no trailing `// {ca}`.
  - **`internal/acme/chain.go`:** the `Recorder` interface gains `ACMERateLimited(ca string)`; `nopRecorder` gains `func (nopRecorder) ACMERateLimited(string) {}`.
  - **`internal/observ/recorder.go`:**
    - the `Recorder` interface gains `ACMERateLimited(ca string)`;
    - in the trailing comment `// a per-CA cooldown/backoff was set` on `ACMECooldown`, only "per-CA " is removed (made wrong: the wait-until is per account), so it reads `// a cooldown/backoff was set`;
    - `Nop` gains `func (Nop) ACMERateLimited(ca string) {}`.
  - **`internal/metrics/metrics.go`:**
    - a new field `acmeRateLimited *prometheus.CounterVec`, built as:

```go
		acmeRateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tunneld_acme_rate_limited_total", Help: "ACME 429 (rate-limited) answers by CA.",
		}, []string{"ca"}),
```

    - the field is added to `reg.MustRegister(…)` after `m.acmeCooldown`, and pre-created at zero in the `observ.ACMECAs` loop (`m.acmeRateLimited.WithLabelValues(ca)`);
    - the help text of `tunneld_acme_cooldown_total`, `"Per-CA cooldown activations."`, becomes `"ACME account wait-until activations by CA."`.
  - **`internal/metrics/recorder.go`:** `func (p *PromRecorder) ACMERateLimited(ca string) { p.m.acmeRateLimited.WithLabelValues(ca).Inc() }`.
  - **`internal/tunneltest/recorder.go`:** `func (r *Recorder) ACMERateLimited(ca string) { r.add(RecCall{Kind: "acmeratelimited", CA: ca}) }`.
- [ ] A6.3.2 `internal/acme/transport.go` (create):

```go
package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

var (
	errOrderAbandoned = errors.New("acme: order attempt abandoned")
	errAccountCooling = errors.New("acme: account is waiting out a CA rate limit")
	errAccountBudget  = errors.New("acme: account has no request budget left")
)

const (
	maxACMEBody     = 1 << 20
	budgetOpTimeout = 3 * time.Second
)

type requestBudget interface {
	TakeACME(ctx context.Context, ca string, bs []limit.Bucket) (time.Duration, error)
	ResyncACME(ctx context.Context, ca string, bs []limit.Bucket, retryAfter time.Duration) error
}

type accountCooldowns interface {
	CACooldown(ctx context.Context, ca string) (time.Duration, error)
	SetCACooldown(ctx context.Context, ca string, d time.Duration) error
}

type budgetTransport struct {
	base      http.RoundTripper
	acct      *account
	budgets   Budgets
	requests  requestBudget
	cooldowns accountCooldowns
	recorder  Recorder
	cooldown  time.Duration
	firstPoll time.Duration
	pollEvery time.Duration
	logger    *slog.Logger
	now       func() time.Time
}

func (t *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr := trackFrom(req.Context())
	if err := t.before(req, tr); err != nil {
		if req.Body != nil {
			if cerr := req.Body.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
		}
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return t.rateLimited(req.Context(), resp, tr)
	}
	if tr == nil {
		return resp, nil
	}
	return t.observe(req, resp, tr)
}

func (t *budgetTransport) before(req *http.Request, tr *orderTrack) error {
	ctx := req.Context()
	if tr != nil && tr.abandoned() {
		return errOrderAbandoned
	}
	cool := t.cooling(ctx)
	bs := t.budgets.requestBuckets(t.acct, req)
	if tr == nil {
		if cool > 0 {
			return errAccountCooling
		}
		wait, err := t.take(ctx, bs)
		if err != nil {
			t.logger.Warn("acme request budget unavailable (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
			return nil
		}
		if wait > 0 {
			return errAccountBudget
		}
		return nil
	}
	if err := t.sleep(ctx, tr, cool); err != nil {
		return err
	}
	if tr.isPoll(req.URL.String()) {
		if err := t.sleep(ctx, tr, tr.pollDue(t.firstPoll, t.pollEvery).Sub(t.now())); err != nil {
			return err
		}
		tr.markPoll(t.now())
	}
	for {
		wait, err := t.take(ctx, bs)
		if err != nil {
			t.logger.Warn("acme request budget unavailable (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
			return nil
		}
		if wait <= 0 {
			return nil
		}
		if err := t.sleep(ctx, tr, wait); err != nil {
			return err
		}
	}
}

func (t *budgetTransport) cooling(ctx context.Context) time.Duration {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	cool, err := t.cooldowns.CACooldown(octx, t.acct.id)
	if err != nil {
		t.logger.Warn("acme account wait-until check failed (request sent)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
		return 0
	}
	return cool
}

func (t *budgetTransport) take(ctx context.Context, bs []limit.Bucket) (time.Duration, error) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	return t.requests.TakeACME(octx, t.acct.ca, bs)
}

func (t *budgetTransport) sleep(ctx context.Context, tr *orderTrack, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tr.done:
		return errOrderAbandoned
	case <-timer.C:
		return nil
	}
}

func (t *budgetTransport) rateLimited(ctx context.Context, resp *http.Response, tr *orderTrack) (*http.Response, error) {
	t.recorder.ACMERateLimited(t.acct.ca)
	header := resp.Header.Get("Retry-After")
	d, perr := retryAfter(header, t.now())
	if perr != nil {
		t.logger.Warn("acme 429 with an unparseable Retry-After (the default cooldown applies)", "ca", t.acct.ca, "account", t.acct.label, "err", perr)
	}
	if d <= 0 {
		d = t.cooldown
	}
	t.setWaitUntil(ctx, d)
	if tr != nil {
		tr.signalLimited(d)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEBody))
	if cerr := resp.Body.Close(); cerr != nil {
		err = errors.Join(err, cerr)
	}
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &problem); err != nil {
		t.logger.Debug("acme 429 body is not a problem document (no budget resync)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
	}
	t.resync(ctx, t.budgets.resyncBuckets(t.acct, problem.Detail, tr), d)
	t.logger.Warn("acme CA answered 429; the account waits", "ca", t.acct.ca, "account", t.acct.label, "retry_after", d, "detail", problem.Detail)
	return resp, nil
}

func (t *budgetTransport) setWaitUntil(ctx context.Context, d time.Duration) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	if err := t.cooldowns.SetCACooldown(octx, t.acct.id, d); err != nil {
		t.logger.Warn("acme account wait-until write failed", "ca", t.acct.ca, "account", t.acct.label, "err", err)
	}
}

func (t *budgetTransport) resync(ctx context.Context, bs []limit.Bucket, d time.Duration) {
	octx, cancel := context.WithTimeout(ctx, budgetOpTimeout)
	defer cancel()
	if err := t.requests.ResyncACME(octx, t.acct.ca, bs, d); err != nil {
		t.logger.Warn("acme budget resync failed", "ca", t.acct.ca, "account", t.acct.label, "err", err)
	}
}

func (t *budgetTransport) observe(req *http.Request, resp *http.Response, tr *orderTrack) (*http.Response, error) {
	if tr.isFinalize(req.URL.String()) {
		if resp.StatusCode/100 == 2 {
			tr.markFinalized(t.now())
		}
		return resp, nil
	}
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || location == "" || tr.hasOrder() {
		return resp, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEBody))
	if cerr := resp.Body.Close(); cerr != nil {
		err = errors.Join(err, cerr)
	}
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	var order struct {
		Finalize string `json:"finalize"`
	}
	if err := json.Unmarshal(raw, &order); err != nil {
		t.logger.Debug("acme 201 body is not JSON (not an order)", "ca", t.acct.ca, "account", t.acct.label, "err", err)
		return resp, nil
	}
	if order.Finalize != "" {
		tr.setOrder(location, order.Finalize)
	}
	return resp, nil
}

func retryAfter(v string, now time.Time) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	if sec, err := strconv.Atoi(v); err == nil {
		return time.Duration(sec) * time.Second, nil
	}
	at, err := http.ParseTime(v)
	if err != nil {
		return 0, fmt.Errorf("acme: Retry-After %q is neither seconds nor an HTTP date: %w", v, err)
	}
	return at.Sub(now), nil
}
```

Context:
- `newAccount` also answers `201` with a `Location` but carries no `finalize`, so it's never taken for an order.
- An untracked request (lego's directory GET at client build) is refused while the account cools or has no request budget; the build then fails and is retried on the next use.
- Every Valkey call in the transport has its own `budgetOpTimeout` (3 s ≈ 2× the budget lock's worst wait of 100 × 10 ms plus round-trips). lego's obtain context has no deadline (`context.WithoutCancel`), and a hold (`sleep`) still ends on abandon or ctx cancel.

DoD:
- [ ] No request bypasses the wait-until or the request budget; tracked requests also follow the poll schedule.

### [ ] T6.4 — lego client

- [ ] A6.4.1 `internal/acme/lego_client.go` (modify):
  - **Imports:** `net/http`.
  - **`LegoConfig` gains:**

```go
	AccountID      string
	Label          string
	ResolveOnly    bool
	AttemptTimeout time.Duration
	PollFirst      time.Duration
	Wrap           func(http.RoundTripper) http.RoundTripper
```

  - **Comment parts removed** (made wrong by several accounts per CA, by look-up-only accounts and by the retry jitter). Only the wrong words go:
    - `acmeUser` doc: " per CA" → "acmeUser implements lego's registration.User for one operator ACME account.";
    - `LegoConfig` doc: "per-CA " → "LegoConfig configures one lego client.";
    - `AccountKey` field comment: "per-CA " → `// persisted account key`;
    - `NewLegoClient` doc: " and registers (or EAB-registers)" and "per-CA " → "NewLegoClient constructs the account. Network-touching; exercised by the Pebble-backed integration tier." A `ResolveOnly` account is never registered;
    - `classifyLego` doc: only the clause "so the chain and the phone are told exactly when the CA will accept a retry;". The phone's answer now adds a 1–10 s jitter.
- [ ] A6.4.2 same file, `NewLegoClient`:
  - right after `lc.CADirURL = cfg.DirectoryURL`:

```go
	if cfg.Wrap != nil {
		lc.HTTPClient.Transport = cfg.Wrap(lc.HTTPClient.Transport)
	}
```

  - the registration `if cfg.EABKID != "" { … } else { … }` becomes:

```go
	switch {
	case cfg.ResolveOnly:
		reg, err := client.Registration.ResolveAccountByKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("acme: resolve the existing account by key (%s %s; tunneld never creates this account): %w", cfg.CAID, cfg.Label, err)
		}
		user.reg = reg
	case cfg.EABKID != "":
		reg, err := client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true, Kid: cfg.EABKID, HmacEncoded: cfg.EABHMAC,
		})
		if err != nil {
			return nil, fmt.Errorf("acme: EAB register (%s): %w", cfg.CAID, err)
		}
		user.reg = reg
	default:
		reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("acme: register (%s): %w", cfg.CAID, err)
		}
		user.reg = reg
	}
```

- [ ] A6.4.3 same file:
  - **Added:** `var errCARateLimited = errors.New("acme: the CA answered 429 (rate limited)")`.
  - **`obtain`:** keep the goroutine, `logAbandoned` and the comment above it, and replace the `select` with:

```go
	var limited <-chan time.Duration
	tr := trackFrom(ctx)
	if tr != nil {
		limited = tr.limited
	}
	abandon := func() {
		mu.Lock()
		abandoned = true
		select {
		case r := <-ch:
			logAbandoned(r)
		default:
		}
		mu.Unlock()
		if tr != nil {
			tr.abandon()
		}
	}
	select {
	case <-ctx.Done():
		abandon()
		return nil, store.CertInfo{}, transient(ctx.Err())
	case d := <-limited:
		abandon()
		return nil, store.CertInfo{}, rateLimited(d, errCARateLimited)
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
```

DoD:
- [ ] A transport-signalled 429 ends `obtain` immediately; GTS accounts are only resolved.

### [ ] T6.5 — chain

- [ ] A6.5.1 `internal/acme/chain.go` (modify):
  - **Imports:** `cmp`, `slices`, `encoding/binary`, `encoding/hex`.
  - **`ChainConfig` gains:**
    - `NodeID string`, `Nodes NodeLister`, `Budgets Budgets`;
    - `PollEvery time.Duration`;
    - `RunBudget time.Duration` (0 → 290 s);
    - `Rand func(n int) int` (nil → `crypto/rand`).
  - **`chainIssuer`:** `groups [][]*account` replaces `cas []caIssuer`.
  - **Comment parts removed** (made wrong). Only the wrong words go; the resulting texts are the ones in the code below:
    - `chainIssuer` type comment: " with reactive per-CA cooldown/backoff (a rate-limited CA gets a Valkey retry-after; the spillover skips a cooling CA)" and " (an LE renewal costs nothing)". It reads "chainIssuer implements enroll.PublicIssuer. Issue and renew use the SAME LE→GTS→ZeroSSL order, so every renewal opportunistically migrates the name to LE.";
    - `NewChainIssuer` doc: " cas MUST be ordered [LE, GTS, ZeroSSL]." goes ("NewChainIssuer builds the chain.");
    - `run` doc: ", skipping any that are cooling (an active Valkey retry-after)" and "; a rate-limited CA gets a retry-after honoring its Retry-After" go, because cooling and skipping are now per account (other accounts of the same CA are still tried), and " with the shortest remaining cooldown" goes, because the answer now adds a jitter and can be the earliest budget slot;
    - `Renew` doc: the clause " (an LE renewal costs nothing)", because an LE renewal now draws the per-name budget, and the sentence "cur is unused: a name already on LE simply renews on LE first; a GTS/ZeroSSL name is retried on LE first.";
    - the inline comment before `if shortest == 0`: " with the shortest remaining cooldown" goes ("Every CA was cooling or failed transiently: retryable.");
    - `handleFailure` doc: " for ca" goes ("handleFailure applies the reactive cooldown/backoff, returning the cooldown it set (0 for a permanent error) and whether the error is permanent."). It now takes an account;
    - `handleFailure`'s `ClassRateLimited` case comment: only "The CA's explicit Retry-After is honored AS-IS (it is the authoritative statement of when a retry will be accepted); " goes, because the wait-until is now never shortened. It reads "--acme-cooldown-default applies only when the CA sent no hint. Cooldown writes are best-effort: …";
    - `ObtainSelf` doc: only "subject to the per-CA cooldowns, but ", because the cooldowns are per account and budgets apply too. It reads "…via the same spillover (NOT the per-tunnel issuance cap — that lives in enroll and is keyed on tunnel names).".

    Kept unchanged: the `Obtain` doc, the rest of `Renew`'s doc, and the other inline comments of `run` (reproduced below).
  - **Log message texts and the final error text stay as today;** a new `"account", a.label` attribute is appended LAST on each changed log call.
  - **Code:**

```go
const (
	settleTimeout    = 5 * time.Second
	defaultRunBudget = 290 * time.Second
)

// chainIssuer implements enroll.PublicIssuer. Issue and renew use the SAME LE→GTS→
// ZeroSSL order, so every renewal opportunistically migrates the name to LE.
type chainIssuer struct {
	cfg    ChainConfig
	groups [][]*account
	now    func() time.Time
}

// NewChainIssuer builds the chain.
func NewChainIssuer(cfg ChainConfig, accounts ...*account) *chainIssuer {
	if cfg.Recorder == nil {
		cfg.Recorder = nopRecorder{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Rand == nil {
		cfg.Rand = cryptoIntN
	}
	if cfg.RunBudget <= 0 {
		cfg.RunBudget = defaultRunBudget
	}
	c := &chainIssuer{cfg: cfg, now: time.Now}
	for _, ca := range []string{CALetsEncrypt, CAGTS, CAZeroSSL} {
		var g []*account
		for _, a := range accounts {
			if a.ca == ca {
				g = append(g, a)
			}
		}
		if len(g) > 0 {
			c.groups = append(c.groups, g)
		}
	}
	return c
}

func cryptoIntN(n int) int {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int(binary.LittleEndian.Uint64(b[:]) % uint64(n))
}

// Obtain runs the initial LE→GTS→ZeroSSL spillover, trying LE first.
func (c *chainIssuer) Obtain(ctx context.Context, csr *x509.CertificateRequest, name string) ([]byte, store.CertInfo, error) {
	return c.run(ctx, csr, name, "")
}

// Renew renews an existing name using the SAME LE→GTS→ZeroSSL order as initial issuance, so every
// renewal opportunistically migrates the name to LE.
func (c *chainIssuer) Renew(ctx context.Context, csr *x509.CertificateRequest, name string, cur store.CertInfo) ([]byte, store.CertInfo, error) {
	return c.run(ctx, csr, name, cur.CA)
}

// run tries the CAs in order. The first
// success wins. When every CA is cooling
// or failing, the error is retryable ("quota exhausted, retry later").
func (c *chainIssuer) run(ctx context.Context, csr *x509.CertificateRequest, name, curCA string) ([]byte, store.CertInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RunBudget)
	defer cancel()
	live := c.liveNodes(ctx)
	fqdn := name
	if csr != nil {
		switch {
		case len(csr.DNSNames) > 0:
			fqdn = csr.DNSNames[0]
		case csr.Subject.CommonName != "":
			fqdn = csr.Subject.CommonName
		}
	}
	shortest := time.Duration(0)
	note := func(d time.Duration) {
		if d > 0 && (shortest == 0 || d < shortest) {
			shortest = d
		}
	}
	for _, group := range c.groups {
		for _, a := range c.ordered(ctx, group, live) {
			if err := ctx.Err(); err != nil {
				return nil, store.CertInfo{}, transient(err)
			}
			// Cooldown bookkeeping is best-effort: a Valkey error reads as "not cooling" (fail-open — try
			// the CA) rather than blocking issuance on the control plane.
			cool, cerr := c.cfg.Limiter.CACooldown(ctx, a.id)
			if cerr != nil {
				c.cfg.Logger.Warn("acme CA cooldown check failed (trying the CA)", "ca", a.ca, "name", name, "err", cerr, "account", a.label)
			}
			if cool > 0 {
				note(cool)
				continue
			}
			pemChain, info, wait, err := c.attempt(ctx, a, csr, name, fqdn, curCA == CALetsEncrypt && a.ca == CALetsEncrypt, live)
			if wait > 0 {
				note(wait)
				continue
			}
			if err == nil {
				if rerr := c.cfg.Limiter.ResetCAFailures(ctx, a.id); rerr != nil { // best-effort streak reset; a stale count self-expires at TTL
					c.cfg.Logger.Warn("acme CA failure-streak reset failed", "ca", a.ca, "name", name, "err", rerr, "account", a.label)
				}
				c.cfg.Recorder.ACMEIssue(a.ca, "ok")
				c.cfg.Logger.Info("acme certificate issued", "ca", a.ca, "name", name, "serial", info.Serial, "not_after", info.NotAfter, "account", a.label)
				return pemChain, info, nil
			}
			if ctx.Err() != nil {
				return nil, store.CertInfo{}, transient(fmt.Errorf("%w (CA order: %v)", ctx.Err(), err))
			}
			class := ClassTransient
			var ie *IssuerError
			if asIssuerError(err, &ie) {
				class = ie.Class
			}
			c.cfg.Logger.Warn("acme CA order failed", "ca", a.ca, "name", name, "class", class, "err", err, "account", a.label)
			if class == ClassLocal {
				return nil, store.CertInfo{}, rateLimited(ie.Retry, err)
			}
			c.cfg.Recorder.ACMEIssue(a.ca, "fail")
			cool, permanent := c.handleFailure(ctx, a, err)
			if permanent {
				return nil, store.CertInfo{}, err // permanent (e.g. bad CSR) — stop
			}
			// Fold the cooldown this failure JUST set into the shortest-remaining computation, so the
			// Retry-After reflects when the chain would actually accept a retry (a run where every CA
			// fails transitively must not report the 1h default when a 1m backoff applies).
			note(cool)
		}
	}
	// Every CA was cooling or failed transiently: retryable.
	if shortest == 0 {
		shortest = c.cfg.CooldownDefault
	}
	jitter := time.Duration(1+c.cfg.Rand(10)) * time.Second
	return nil, store.CertInfo{}, rateLimited(shortest+jitter, fmt.Errorf("all issuance CAs are rate-limited; quota exhausted, retry later"))
}

func (c *chainIssuer) attempt(ctx context.Context, a *account, csr *x509.CertificateRequest, name, fqdn string, leRenewal bool, live []string) ([]byte, store.CertInfo, time.Duration, error) {
	onCreate, onSuccess := c.cfg.Budgets.orderBuckets(a, fqdn, leRenewal)
	member := mintMember()
	timeout := a.timeout
	if d, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(d))
	}
	ok, wait, err := c.cfg.Limiter.ReserveACME(ctx, a.ca, append(slices.Clone(onCreate), onSuccess...), c.cfg.NodeID, member, c.now().Add(timeout), live)
	switch {
	case err != nil:
		c.cfg.Logger.Warn("acme budget reservation failed (trying the account)", "ca", a.ca, "name", name, "err", err, "account", a.label)
	case !ok:
		c.cfg.Logger.Debug("acme account out of budget (skipped)", "ca", a.ca, "name", name, "retry_after", wait, "account", a.label)
		return nil, store.CertInfo{}, wait, nil
	}
	var nameBucket, domainBucket limit.Bucket
	if a.ca == CALetsEncrypt {
		nameBucket, domainBucket = c.cfg.Budgets.leName(fqdn), c.cfg.Budgets.leDomain(fqdn)
	}
	tr := newOrderTrack(nameBucket, domainBucket)
	actx, cancel := context.WithTimeout(withTrack(ctx, tr), timeout)
	pemChain, info, oerr := a.issuer.obtain(actx, csr, name)
	cancel()
	out := tr.outcome()
	tr.abandon()
	c.settle(ctx, a, member, onCreate, onSuccess, tr, out, oerr == nil)
	return pemChain, info, 0, oerr
}

func (c *chainIssuer) settle(ctx context.Context, a *account, member string, onCreate, onSuccess []limit.Bucket, tr *orderTrack, out orderOutcome, ok bool) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer cancel()
	var spend, release []limit.Bucket
	if ok || out.created {
		spend = append(spend, onCreate...)
	} else {
		release = append(release, onCreate...)
	}
	if ok || out.finalized {
		spend = append(spend, onSuccess...)
	} else {
		release = append(release, onSuccess...)
	}
	for _, b := range spend {
		if err := c.cfg.Limiter.CommitACME(sctx, a.ca, b, c.cfg.NodeID, member); err != nil {
			c.cfg.Logger.Warn("acme budget spend failed (the reservation expires at its deadline)", "ca", a.ca, "bucket", b.Key, "err", err, "account", a.label)
		}
	}
	if err := c.cfg.Limiter.ReleaseACME(sctx, release, c.cfg.NodeID, member); err != nil {
		c.cfg.Logger.Warn("acme budget release failed (the reservation expires at its deadline)", "ca", a.ca, "err", err, "account", a.label)
	}
	if out.abandoned {
		for _, f := range tr.takeCleanups() {
			if err := f(sctx); err != nil {
				c.cfg.Logger.Warn("abandoned order's challenge cleanup failed (it expires by TTL)", "ca", a.ca, "err", err, "account", a.label)
			}
		}
	}
}

func (c *chainIssuer) ordered(ctx context.Context, group []*account, live []string) []*account {
	out := slices.Clone(group)
	if len(out) < 2 {
		return out
	}
	for i := len(out) - 1; i > 0; i-- {
		j := c.cfg.Rand(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	levels := make(map[*account]float64, len(out))
	for _, a := range out {
		lv, err := c.cfg.Limiter.ACMEBudgetLevel(ctx, c.cfg.Budgets.ordersBucket(a), live)
		if err != nil {
			c.cfg.Logger.Warn("acme budget levels unavailable (accounts in random order)", "ca", a.ca, "err", err)
			return out
		}
		levels[a] = lv
	}
	slices.SortStableFunc(out, func(x, y *account) int { return cmp.Compare(levels[y], levels[x]) })
	return out
}

func (c *chainIssuer) liveNodes(ctx context.Context) []string {
	ids, err := c.cfg.Nodes.LiveNodeIDs(ctx)
	if err != nil {
		c.cfg.Logger.Warn("live node list unavailable (counting only this node's in-flight orders)", "err", err)
		ids = nil
	}
	if !slices.Contains(ids, c.cfg.NodeID) {
		ids = append(ids, c.cfg.NodeID)
	}
	return ids
}

func (c *chainIssuer) ACMEBudgetLevels(ctx context.Context) ([]BudgetLevel, error) {
	live, err := c.cfg.Nodes.LiveNodeIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("live node list: %w", err)
	}
	if !slices.Contains(live, c.cfg.NodeID) {
		live = append(live, c.cfg.NodeID)
	}
	var out []BudgetLevel
	for _, g := range c.groups {
		for _, a := range g {
			for _, nb := range c.cfg.Budgets.accountBuckets(a) {
				lv, err := c.cfg.Limiter.ACMEBudgetLevel(ctx, nb.b, live)
				if err != nil {
					return nil, err
				}
				out = append(out, BudgetLevel{CA: a.ca, Account: a.label, Budget: nb.name, Ratio: lv})
			}
		}
	}
	return out, nil
}

func mintMember() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
```

  - **`handleFailure` and `setCooldown`** take `a *account`:
    - the Valkey keys use `a.id` (`SetCACooldown` now never shortens, T4.1);
    - `Recorder.ACMECooldown(a.ca)`;
    - their log message texts stay, with `"account", a.label` appended last.
  - **`ObtainSelf`** takes the reserved host's current cert info, so an LE renewal of a reserved host is exempt from the domain and orders budgets like any other: `func (c *chainIssuer) ObtainSelf(ctx context.Context, host string, cur store.CertInfo) (certPEM, keyPEM []byte, info store.CertInfo, err error)`, calling `c.run(ctx, csr, host, cur.CA)`.
  - **`byID(id)`** returns `g[0].issuer` of the group whose `g[0].ca == id` (nil when that CA is not in the chain).

Context: `cryptoIntN` and `mintMember` discard `crypto/rand.Read`'s error because Go documents that it "never returns an error, and always fills b entirely" (`go doc crypto/rand.Read`). `math/rand` is avoided because gosec G404 flags it.

DoD:
- [ ] The chain runs on accounts; its log message texts and final error text are unchanged; no comment states something false.

### [ ] T6.6 — `NewChain` + package doc

- [ ] A6.6.1 `internal/acme/lazy.go` (modify):
  - **Imports:** `net/http`.
  - **`NewChain`** becomes the function below. Only the wrong parts of its doc comment are removed: "per-CA ", " (order preserved: MUST be LE, GTS, ZeroSSL)" (the accounts are now grouped by CA) and " (ACME account registration)" (GTS accounts are only looked up).

```go
// NewChain builds the [LE, GTS, ZeroSSL] chain with lazy, self-healing clients constructed from
// the given lego configs. Each client's network-touching construction is deferred to first use, so
// startup never blocks on CA reachability and an unreachable CA self-heals once it recovers.
func NewChain(cfg ChainConfig, legoCfgs ...LegoConfig) *chainIssuer {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	var rec Recorder = nopRecorder{}
	if cfg.Recorder != nil {
		rec = cfg.Recorder
	}
	accounts := make([]*account, 0, len(legoCfgs))
	for _, lc := range legoCfgs {
		a := &account{ca: lc.CAID, id: lc.AccountID, label: lc.Label, timeout: lc.AttemptTimeout}
		lc.Wrap = func(base http.RoundTripper) http.RoundTripper {
			return &budgetTransport{base: base, acct: a, budgets: cfg.Budgets, requests: cfg.Limiter, cooldowns: cfg.Limiter,
				recorder: rec, cooldown: cfg.CooldownDefault, firstPoll: lc.PollFirst, pollEvery: cfg.PollEvery, logger: logger, now: time.Now}
		}
		a.issuer = newLazyCA(lc.CAID, lc.Shortlived, lc.RenewMargin,
			func(ctx context.Context) (caIssuer, error) { return NewLegoClient(ctx, lc) }, logger)
		accounts = append(accounts, a)
	}
	return NewChainIssuer(cfg, accounts...)
}
```

- [ ] A6.6.2 same file, comments made wrong by per-account clients that may only look their account up. Only the wrong parts are removed:
  - `lazyCA` doc: "per-CA " and " (ACME account registration)" are removed, so it starts "lazyCA defers the network-touching client construction to first use, …";
  - the `group` field's trailing comment `// dedups concurrent first-use registration` is removed;
  - `newLazyCA` doc: " for one CA's client" is removed ("newLazyCA wraps a builder behind lazy, self-healing construction.");
  - `resolve` doc: ", performing first-use registration once (deduped via singleflight)" is removed ("resolve returns the built client."). The "It is ctx-aware: …" sentences stay.
- [ ] A6.6.3 same file, `resolve`: the shared build must not inherit the triggering attempt's tracker. That attempt ends (and abandons its tracker) on its own deadline, and every concurrent waiter of the same singleflight build would then get `errOrderAbandoned`. The build context becomes:

```go
		bctx, cancel := context.WithTimeout(withoutTrack(context.WithoutCancel(ctx)), lazyBuildTimeout)
```

  The build's requests are then untracked, so the transport refuses them while the account waits or lacks request budget, and the build is retried on the next use.
- [ ] A6.6.4 `internal/acme/issuer.go` (modify): two parts of the package doc comment are removed (made wrong):
  - "per-CA " in "lego-backed per-CA clients";
  - the clause "and reactive per-CA cooldown+backoff (a rate-limited CA gets a Valkey retry-after; the spillover skips a cooling CA)".

DoD:
- [ ] Each lego client of each account gets its own budget transport; no comment states something false.

### [ ] T6.7 — server wiring

- [ ] A6.7.1 `internal/server/acmewire.go` (modify):
  - **Imports:** `strings`, `internal/ca`.
  - **`buildACMEChain`** is replaced by the code below. Only "per-CA " is removed from its doc comment, because accounts are now per account. `loadAccountKey` and its doc comment stay unchanged.

```go
// buildACMEChain constructs the LE→GTS→ZeroSSL chain from config: accounts whose keys are
// persisted under --acme-account-dir/accounts, and lazy self-healing clients (startup never blocks on CA
// reachability).
func buildACMEChain(cfg config.ServeCmd, lim *limit.Limiter, chal *acme.ChallengeStore, rec acme.Recorder, logger *slog.Logger, nodeID string, nodes acme.NodeLister) (acmeChain, error) {
	acme.SetLogOutput(os.Stderr)
	budgets, err := budgetsFrom(cfg)
	if err != nil {
		return nil, err
	}
	legoCfgs, err := acmeLegoConfigs(cfg, chal, logger, nodeID)
	if err != nil {
		return nil, err
	}
	chainCfg := acme.ChainConfig{
		Limiter: lim, Recorder: rec, Logger: logger,
		CooldownDefault: cfg.ACMECooldownDefault, BackoffInitial: cfg.ACMEBackoffInitial,
		BackoffMax: cfg.ACMEBackoffMax, RenewMargin: cfg.ACMERenewMargin, ShortlivedLifetime: shortlivedLifetime,
		NodeID: nodeID, Nodes: nodes, Budgets: budgets, PollEvery: cfg.ACMEPollInterval,
	}
	return acme.NewChain(chainCfg, legoCfgs...), nil
}

func acmeLegoConfigs(cfg config.ServeCmd, chal *acme.ChallengeStore, logger *slog.Logger, nodeID string) ([]acme.LegoConfig, error) {
	accountsDir := filepath.Join(cfg.ACMEAccountDir, "accounts")
	var cfgs []acme.LegoConfig
	if cfg.LEEnabled() {
		key, err := loadAccountKey(accountsDir, acme.CALetsEncrypt, logger)
		if err != nil {
			return nil, err
		}
		id, err := accountID(acme.CALetsEncrypt, nodeID, key)
		if err != nil {
			return nil, err
		}
		cfgs = append(cfgs, acme.LegoConfig{
			CAID: acme.CALetsEncrypt, DirectoryURL: cfg.ACMEDirLE, Email: cfg.ACMEEmail,
			AccountKey: key, AccountID: id, Label: "local",
			AttemptTimeout: cfg.ACMEAttemptTimeoutLE, PollFirst: cfg.ACMEPollFirstLE,
			Profile: cfg.ACMELEProfile, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
			UseARI:    true,
			Challenge: cfg.ACMEChallengeLE, TLSALPN: chal, HTTP: chal, Logger: logger,
			DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
		})
	}
	for _, gtsName := range cfg.ACMEGTSAccounts {
		key, err := loadExistingAccountKey(accountsDir, gtsName)
		if err != nil {
			return nil, err
		}
		id, err := accountID(acme.CAGTS, nodeID, key)
		if err != nil {
			return nil, err
		}
		cfgs = append(cfgs, acme.LegoConfig{
			CAID: acme.CAGTS, DirectoryURL: cfg.ACMEDirGTS, Email: cfg.ACMEEmail,
			AccountKey: key, AccountID: id, Label: gtsName, ResolveOnly: true,
			AttemptTimeout: cfg.ACMEAttemptTimeoutGTS, PollFirst: cfg.ACMEPollFirstGTS,
			Validity: cfg.ACMEGTSValidity, RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
			Challenge: cfg.ACMEChallengeGTS, TLSALPN: chal, HTTP: chal, Logger: logger,
			DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
		})
	}
	if cfg.ZeroSSLEnabled() {
		key, err := loadAccountKey(accountsDir, acme.CAZeroSSL, logger)
		if err != nil {
			return nil, err
		}
		id, err := accountID(acme.CAZeroSSL, nodeID, key)
		if err != nil {
			return nil, err
		}
		cfgs = append(cfgs, acme.LegoConfig{
			CAID: acme.CAZeroSSL, DirectoryURL: cfg.ACMEDirZeroSSL, Email: cfg.ACMEEmail,
			AccountKey: key, AccountID: id, Label: "local",
			AttemptTimeout: cfg.ACMEAttemptTimeoutZeroSSL, PollFirst: cfg.ACMEPollFirstZeroSSL,
			RenewMargin: cfg.ACMERenewMargin, Shortlived: shortlivedLifetime,
			EABKID: cfg.ACMEEABZeroSSLKID, EABHMAC: cfg.ACMEEABZeroSSLHMAC,
			Challenge: cfg.ACMEChallengeZeroSSL, TLSALPN: chal, HTTP: chal, Logger: logger,
			DNSResolvers: cfg.ACMEDNSResolvers, DNSSkipPropagationCheck: cfg.ACMEDNSSkipPropagationCheck,
		})
	}
	if cfg.UsesChallenge(config.ChallengeDNS01) {
		dnsProvider, err := acme.DNSProviderByName(cfg.ACMEDNSProvider)
		if err != nil {
			logger.Warn("acme dns provider unavailable (issuance degraded until configured)",
				"provider", cfg.ACMEDNSProvider, "err", err)
		} else {
			for i := range cfgs {
				cfgs[i].RawDNS = dnsProvider
			}
		}
	}
	return cfgs, nil
}

func loadExistingAccountKey(dir, id string) (crypto.Signer, error) {
	path := filepath.Join(dir, id+".key")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gts account key %s (tunneld never creates GTS accounts; place the registered account's key here): %w", path, err)
	}
	key, err := parseECPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("gts account key %s exists but is unparseable: %w", path, err)
	}
	return key, nil
}

func accountID(caID, nodeID string, key crypto.Signer) (string, error) {
	if key == nil {
		return caID + "-ephemeral-" + nodeID, nil
	}
	fp, err := ca.KeyFingerprint(key.Public())
	if err != nil {
		return "", fmt.Errorf("acme account id (%s): %w", caID, err)
	}
	return caID + "-" + strings.TrimPrefix(fp, "sha256:")[:16], nil
}

func budgetsFrom(cfg config.ServeCmd) (acme.Budgets, error) {
	b := acme.Budgets{Domain: strings.ToLower(cfg.TunnelDomain)}
	for _, r := range []struct {
		name string
		v    string
		dst  *limit.Rate
	}{
		{"--acme-budget-le-domain", cfg.ACMEBudgetLEDomain, &b.LEDomain},
		{"--acme-budget-le-orders", cfg.ACMEBudgetLEOrders, &b.LEOrders},
		{"--acme-budget-le-name", cfg.ACMEBudgetLEName, &b.LEName},
		{"--acme-budget-gts-orders", cfg.ACMEBudgetGTSOrders, &b.GTSOrders},
		{"--acme-budget-gts-requests", cfg.ACMEBudgetGTSRequests, &b.GTSRequests},
		{"--acme-budget-gts-cert-polls", cfg.ACMEBudgetGTSCertPolls, &b.GTSCertPolls},
		{"--acme-budget-zerossl-orders", cfg.ACMEBudgetZeroSSLOrders, &b.ZeroSSLOrders},
		{"--acme-budget-zerossl-requests", cfg.ACMEBudgetZeroSSLRequests, &b.ZeroSSLRequests},
	} {
		p, err := config.ParseRate(r.v)
		if err != nil {
			return acme.Budgets{}, fmt.Errorf("%s: %w", r.name, err)
		}
		*r.dst = limit.Rate{Count: p.Count, Period: p.Period, Burst: p.Burst}
	}
	return b, nil
}
```

- [ ] A6.7.2 same file, the `acmeChain` interface: `ObtainSelf` becomes `ObtainSelf(ctx context.Context, host string, cur store.CertInfo) (certPEM, keyPEM []byte, info store.CertInfo, err error)`, and the interface gains `ACMEBudgetLevels(ctx context.Context) ([]acme.BudgetLevel, error)`.
- [ ] A6.7.3 `internal/server/reserved.go` (modify):
  - `type selfIssuer func(ctx context.Context, host string, cur store.CertInfo) (certPEM, keyPEM []byte, info store.CertInfo, err error)`;
  - in `issue`, `rc.obtain(issueCtx, rh.host)` → `rc.obtain(issueCtx, rh.host, rh.currentInfo())`. That is the zero `CertInfo` until a cert is held.
  - The `selfIssuer` doc comment stays (still true).
- [ ] A6.7.4 `internal/config/config.go` (modify): the `ACMEEABGTSKID` and `ACMEEABGTSHMAC` fields are removed. Their only reader was the old `buildACMEChain`.
- [ ] A6.7.5 `deploy/tunneld.env.example` (modify):
  - the `TUNNELD_ACME_EAB_GTS_KID=` and `TUNNELD_ACME_EAB_GTS_HMAC=` lines are removed;
  - in the comment "# GTS / ZeroSSL External Account Binding (optional; leave empty to use LE only until configured).", only the parts made wrong are removed: "GTS / " and "; leave empty to use LE only until configured". It reads "# ZeroSSL External Account Binding (optional)." No new comment text is added.
- [ ] A6.7.6 `deploy/docker-compose.yml` (modify): in the `./acme:/acme` mount's comment, only "per-CA " is removed (made wrong: the keys are per account). It reads `# bind mount (operator-owned): ACME account keys + reserved-host self-certs`.
- [ ] A6.7.7 `internal/server/server.go` (modify): add

```go
type liveNodeIDs struct{ reg *router.Registry }

func (n liveNodeIDs) LiveNodeIDs(ctx context.Context) ([]string, error) {
	nodes, err := n.reg.LiveNodes(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	return ids, nil
}
```

  - **Chain construction:** `chain, err := buildACMEChain(cfg, lim, chal, rec, logger, nodeID, liveNodeIDs{reg})`.

DoD:
- [ ] `server.Run` builds the new chain before any listener binds: only enabled CAs, listed GTS keys must exist, no GTS EAB setting is left, no comment states something false.

### [ ] T6.8 — tests (`internal/acme`: miniredis limiter, fake issuers, `httptest` CA; `internal/server`; `internal/metrics`)

| Test | Verifies |
|---|---|
| `TestRegisteredDomain` | `a.b.example.com` → `example.com`; `x.example.co.uk` → `example.co.uk`; trailing dot and upper case normalised; a public suffix itself (`co.uk`) → itself |
| `TestOrderBuckets_PerCAAndPath` | LE new: create {orders}, success {name, domain = `letsencrypt:domain:<eTLD+1 of the name>`}; LE renewal: success {name}; GTS/ZeroSSL: create {orders} |
| `TestRequestBuckets_GTSCertURL` | GTS `/cert/x` → requests + cert-polls; other GTS → requests; ZeroSSL → requests; LE → none |
| `TestResyncBuckets_NamedLimit` | with a tracker: the three LE anchors → the tracker's domain / orders / the tracker's name; without a tracker: orders anchor → orders, the others → none; unknown LE detail → none; GTS `resource "cert"` → cert, `resource "order"` and anything else → requests; ZeroSSL → requests |
| `TestOrderTrack_PollDueAndCleanups` | first = finalizedAt + first; next = max(that, lastPoll + every); `takeCleanups` returns once |
| `TestLazyCA_BuildIgnoresAttemptTracker` | `newLazyCA` with a build func that records `trackFrom(ctx)` and blocks until released; `resolve` with a tracked ctx, then the tracker is abandoned before the build is released → the build saw a nil tracker, and a second waiter gets the built client |
| `TestTLSALPNPresent_RegistersCleanup` | `Present` with a tracker in ctx → the cleanup removes the challenge; without a tracker nothing registered |
| `TestBudgetTransport_429` | fake CA 429 `Retry-After: 7` + LE domain-anchor detail → one `ACMERateLimited("letsencrypt")` recorded, wait-until 7 s on the account id, ONLY the domain bucket resynced, body intact for lego, tracker signalled |
| `TestBudgetTransport_429NeverShortens` | existing wait-until 60 s + 429 `Retry-After: 5` → still 60 s |
| `TestBudgetTransport_HoldsUnderWaitUntil` | tracked request under a 300 ms wait-until reaches the CA ≥ 300 ms later |
| `TestBudgetTransport_UntrackedRefused` | untracked request under a wait-until → `errAccountCooling`; with an exhausted request budget → `errAccountBudget`; nothing sent |
| `TestBudgetTransport_AbandonedFailsFast` | abandoned tracker → `errOrderAbandoned`, nothing sent, request body closed; an ongoing hold aborts on abandon and on ctx cancel |
| `TestBudgetTransport_RecordsOrderAndFinalize` | 201 + Location + `finalize` → order recorded, body intact; newAccount 201 (no `finalize`) ignored; a 200 on the finalize URL → finalized; a 4xx/5xx on it → not finalized |
| `TestBudgetTransport_PollSchedule` | after finalize: first poll ≥ first delay, next ≥ interval; non-poll requests not delayed |
| `TestBudgetTransport_RequestBudgetWaits` | request bucket 2/1s: third tracked request held until the next token |
| `TestBudgetTransport_ValkeyCallsBounded` | fake `requestBudget` / `accountCooldowns` that block until their ctx ends → each call returns within `budgetOpTimeout`, the request is sent (fail open) and a Warn is logged |
| `TestRetryAfter_Parse` | seconds, HTTP-date, empty → (0, nil); garbage → an error naming the value |
| `TestBudgetTransport_429EdgeCases` | an unparseable `Retry-After` → a Warn, and the wait-until uses `--acme-cooldown-default`; a 429 whose body read fails → the wait-until is still set from the header and the tracker signalled, and the read error is returned |
| `TestLegoObtain_LimitedSignalEndsAttempt` | blocked `obtainCSR` + `signalLimited(3s)` → `rateLimited(3s)` at once, tracker abandoned |
| `TestNewLegoClient_ResolveOnly` | `httptest` ACME stub (directory, new-nonce, new-account): `ResolveOnly` sends `onlyReturnExisting: true`; an `accountDoesNotExist` answer fails `NewLegoClient` with no other new-account request |
| `TestChain_SkipsWithoutBudget` | exhausted LE orders bucket → LE fake never called, GTS issues |
| `TestChain_SkipsUnderWaitUntil` | account wait-until set → never called |
| `TestChain_AllUnavailable_RetryAfter` | every account exhausted → `rateLimited(earliest + 1+Rand(10) s)` with a fixed `Rand` |
| `TestChain_GTSOrderedByBudget` | fixed `Rand`; 3 GTS accounts with different order-bucket levels → tried highest first; equal levels → the `Rand`-shuffled order is kept |
| `TestChain_SettleSuccess` | success spends create + success buckets, no in-flight left |
| `TestChain_SettleCreatedThenFailed` | order created then definitive failure → order bucket spent, success buckets released |
| `TestChain_SettleFailedBeforeCreate` | everything released |
| `TestChain_SettleFinalizedAbandoned` | finalized then deadline → create + success buckets spent; registered challenge cleanups run |
| `TestChain_SettleFinalizedThenError` | finalized (2xx), then the fake's `obtain` returns an error (lego's certificate wait or a download error) → create + success buckets spent; no cleanups run (lego cleaned up itself) |
| `TestChain_LiveNodesError` | the `NodeLister` errors → a Warn "live node list unavailable…", and only this node's reservations count |
| `TestChain_OrderedLevelsError` | `ACMEBudgetLevel` errors on a 2-account group → a Warn "acme budget levels unavailable…", and the `Rand`-shuffled order is kept |
| `TestChain_SettleWithoutReservation` | `ReserveACME` error → account tried; on success the buckets are still spent |
| `TestChain_LERenewalExempt` | `Renew` with cur.CA=letsencrypt draws only the name bucket |
| `TestChain_BucketNameFromCSR` | the LE name and domain buckets are keyed on the CSR's first SAN; with a CN-only CSR (accepted by `enroll`'s `csrMatchesTunnel`), on its CN (`<name>.example.test` → name bucket for that FQDN, domain bucket `example.test`), never on the bare tunnel name |
| `TestObtainSelf_LERenewalExempt` | `ObtainSelf` with cur.CA=letsencrypt draws only the host's name bucket; with a zero `CertInfo` it draws orders + name + domain |
| `TestChain_AttemptDeadline` | blocking fake with timeout 50 ms → abandoned at ~50 ms, next CA tried; the abandoned account gets a `"fail"` in `ACMEIssue` and a backoff cooldown (`--acme-backoff-initial`) |
| `TestChain_LocalRefusalBacksOff` | the account's lazy build fails with `errAccountBudget` (its untracked directory request refused) → a `"fail"` and a backoff cooldown on that account; the next account is tried |
| `TestChain_RunBudget` | `RunBudget` 100 ms with blocking fakes of 1 s timeout → the run ends at ~100 ms (no attempt outlives it) |
| `TestChain_MissingCAsSkipped` | a chain built without GTS or ZeroSSL accounts runs only the present CAs; `byID` of a missing CA → nil and `ShouldRenew` falls back to the fixed floor |
| `TestChain_BudgetLevels` | `ACMEBudgetLevels` lists every account bucket with its label and ratio; a node-list error is returned |
| `TestNewLegoClient_ResolveOnlyNeverCreates` (`internal/acme/resolve_integration_test.go`, `//go:build integration`, `tunneltest.StartPebble`) | an unregistered key (`tunneltest.WriteACMEAccountKey`): `NewLegoClient` with `ResolveOnly` fails naming "tunneld never creates this account", and a second identical call fails the same way (the first created nothing). A key registered with `tunneltest.RegisterACMEAccountKey`: `ResolveOnly` succeeds. Pebble v2.10.1 answers `onlyReturnExisting` for an unknown key with `accountDoesNotExist` (`wfe/wfe.go`) |
| `TestACMELegoConfigs_EnabledCAs` (`internal/server`) | LE on + `gts-1,gts-2` keys present + ZeroSSL EAB set → 4 configs in order LE, gts-1, gts-2, ZeroSSL (GTS `ResolveOnly`, labels = ids, distinct `AccountID`s); empty LE dir / no GTS / no EAB → that CA absent; a missing `gts-2.key` → error naming the path; an existing but unparseable `gts-2.key` → "exists but is unparseable" error naming the path, file left untouched |
| `TestAccountID` | fingerprint-derived, stable for the same key; nil key → ephemeral id with the node id |
| `TestBudgetsFrom` | flag strings → `limit.Rate`s; a bad rate names its flag |
| `TestLiveNodeIDs` | ids of the registry's live nodes |
| `TestServeCmd_NoGTSEABFlags` (`internal/config`) | kong rejects `--acme-eab-gts-kid` / `--acme-eab-gts-hmac` as unknown flags |

**Existing tests to adapt:**

| Test / helper | Change |
|---|---|
| `newChainOn` / `newChain` (`chain_test.go`) | wrap each fake `caIssuer` into `&account{ca: f.id(), id: f.id(), label: "local", timeout: time.Minute, issuer: f}`; set a fake `NodeLister`, `Budgets` with large rates, and `Rand` returning 0. Cooldown keys keep matching the CA ids |
| Exact `Retry` assertions (`chain_test.go` lines 148, 286, 302, 319) | add the fixed 1 s jitter |
| `TestRenewTriesLEFirst` (`chain_test.go:157`) | in its comment "A name currently on GTS renews: LE is tried FIRST (opportunistic migration), no budget involved.", only ", no budget involved" is removed (made wrong: the LE attempt reserves budget) |
| `ObtainSelf` calls (`chain_test.go` lines 255, 540) | pass `store.CertInfo{}` |
| `recordingChainRecorder` (`chain_test.go`) | gains `ACMERateLimited` |
| `lazy_test.go`, `lego_client_test.go` | new `LegoConfig` fields; `obtain` select |
| `eab_integration_test.go` | unchanged (EAB still serves ZeroSSL) |
| `countingIssuer` (`internal/server/reserved_test.go`) | the `selfIssuer` signature gains `cur store.CertInfo`; a new assertion checks that a renewal passes the held cert's info and a first issuance the zero value |
| the `obtain` literal of `TestReservedCerts_PublishSurvivesShutdownAfterOrder` (`internal/server/reserved_shared_test.go:286`) | gains the `store.CertInfo` parameter: `func(context.Context, string, store.CertInfo) ([]byte, []byte, store.CertInfo, error)` |
| `TestChain_LogsBookkeepingErrors` (`chain_test.go`) | its closed miniredis now also fails the budget calls, so each case also expects "acme budget reservation failed (trying the account)". The "failed order" and "rate-limited order" cases also expect "acme budget release failed (the reservation expires at its deadline)", and the "successful order" case "acme budget spend failed (the reservation expires at its deadline)" |
| `TestLabelledCountersPreCreatedAtZero` (`internal/metrics`) | also expects `tunneld_acme_rate_limited_total` with `ca=<each CA>` |
| `TestE2EFamiliesExportedNoTunnelLabels` (`internal/metrics`) | also calls `rec.ACMERateLimited("zerossl")` and gathers `tunneld_acme_rate_limited_total` |
| `registeredFamilies` (`internal/metrics/deploy_test.go`) | also calls `rec.ACMERateLimited("letsencrypt")` |

Log substrings (`ca=… name=… class=…`, `msg="acme CA cooldown check failed"` …) and the error text "quota exhausted, retry later" are unchanged, so `TestChain_LogsEachCAFailure`, `TestChain_LogsBookkeepingErrors`, `TestChain_LogsTheIssuingCA` and `TestAllCoolingMessageIsQuotaExhausted` keep passing.

**Existing tests to adapt** (`internal/server/acmewire_test.go`). Each of the three `buildACMEChain` calls takes the new signature (`…, testLogger(), "node-test", fakeNodes{})` with a `fakeNodes` `NodeLister` returning `["node-test"]`). Each literal becomes a `cfg` variable followed by `tunneltest.LooseACMEBudgets(&cfg)` and `tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts")`. The `ACMEDirLE` the two LE-dependent tests need is already set by A5.3.6.

DoD:
- [ ] Tests added and adapted.

---

## [ ] US7 — Budget metrics, dashboard, integration tests

The server exports the remaining budget, the dashboard shows it, and the integration tier exercises the budgets through the real server.

- [ ] AC1: `/metrics` exposes `tunneld_acme_budget_ratio{ca,account,budget}`. A Valkey or node-list error drops only the budget family for that scrape. Its Warn is at most 1/min and carries the count of suppressed errors.
- [ ] AC2: The tunneld overview dashboard shows the remaining budget as a percentage.
- [ ] AC3: Integration tests through the real server cover the budget-exhausted answer and a GTS-only chain.

### [ ] T7.1 — `internal/metrics/acme_budget.go`

- [ ] A7.1.1 `internal/metrics/acme_budget.go` (create):

```go
package metrics

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	acmeBudgetScrapeTimeout = 2 * time.Second
	acmeBudgetWarnEvery     = time.Minute
)

type ACMEBudgetLevel struct {
	CA      string
	Account string
	Budget  string
	Ratio   float64
}

type acmeBudgetCollector struct {
	desc       *prometheus.Desc
	levels     func(context.Context) ([]ACMEBudgetLevel, error)
	logger     *slog.Logger
	mu         sync.Mutex
	warned     time.Time
	suppressed int
}

func (c *acmeBudgetCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *acmeBudgetCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), acmeBudgetScrapeTimeout)
	defer cancel()
	levels, err := c.levels(ctx)
	if err != nil {
		c.warn(err)
		return
	}
	c.reportSuppressed()
	for _, l := range levels {
		m, err := prometheus.NewConstMetric(c.desc, prometheus.GaugeValue, l.Ratio, l.CA, l.Account, l.Budget)
		if err != nil {
			c.warn(err)
			continue
		}
		ch <- m
	}
}

func (c *acmeBudgetCollector) warn(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.warned) < acmeBudgetWarnEvery {
		c.suppressed++
		return
	}
	c.logger.Warn("acme budget metrics unavailable for this scrape", "err", err, "suppressed_since_last_report", c.suppressed)
	c.warned, c.suppressed = time.Now(), 0
}

func (c *acmeBudgetCollector) reportSuppressed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.suppressed == 0 || time.Since(c.warned) < acmeBudgetWarnEvery {
		return
	}
	c.logger.Warn("acme budget metrics: scrape errors since the last report", "count", c.suppressed)
	c.warned, c.suppressed = time.Now(), 0
}

func (m *Metrics) RegisterACMEBudgets(levels func(context.Context) ([]ACMEBudgetLevel, error), logger *slog.Logger) error {
	if levels == nil || logger == nil {
		return errors.New("metrics: acme budget levels and logger are required")
	}
	return m.reg.Register(&acmeBudgetCollector{
		desc: prometheus.NewDesc("tunneld_acme_budget_ratio",
			"Remaining ACME issuance budget (0-1) by CA, account and budget.", []string{"ca", "account", "budget"}, nil),
		levels: levels,
		logger: logger,
	})
}
```

DoD:
- [ ] Family registered; no per-tunnel labels.

### [ ] T7.2 — `internal/server/server.go`: budget metrics

- [ ] A7.2.1 right after the chain construction (A6.7.7):

```go
	if err := m.RegisterACMEBudgets(func(ctx context.Context) ([]metrics.ACMEBudgetLevel, error) {
		levels, err := chain.ACMEBudgetLevels(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]metrics.ACMEBudgetLevel, len(levels))
		for i, l := range levels {
			out[i] = metrics.ACMEBudgetLevel{CA: l.CA, Account: l.Account, Budget: l.Budget, Ratio: l.Ratio}
		}
		return out, nil
	}, logger); err != nil {
		return fmt.Errorf("acme budget metrics: %w", err)
	}
```

DoD:
- [ ] The budget family is registered before any listener binds.

### [ ] T7.3 — dashboard

- [ ] A7.3.1 `deploy/grafana/provisioning/dashboards/tunneld.json` (modify):
  - **New panel:** id 28, `timeseries`, title `ACME issuance budget left`, unit `percent`, gridPos `{"h": 8, "w": 24, "x": 0, "y": 46}`.
  - **Every panel/row with `y ≥ 46`** moves down by 8.
  - **Target** (same datasource and fieldConfig style as its neighbours):

```json
{"refId": "A", "datasource": {"type": "prometheus", "uid": "prometheus"},
 "expr": "min by (ca, account, budget) (100 * tunneld_acme_budget_ratio{node=~\"$node\"})",
 "legendFormat": "{{ca}} {{account}} {{budget}}"}
```

DoD:
- [ ] The file keeps its formatting (indent 1, no trailing newline).

### [ ] T7.4 — tests

| Test | Verifies |
|---|---|
| `TestACMEBudgetCollector_Emits` (`internal/metrics`) | one gauge per level with the 3 labels |
| `TestACMEBudgetCollector_ErrorKeepsScrape` | source error → family absent, other families still gathered, ≤ 1 Warn per minute. Errors inside the window are counted: the next Warn after the window carries `suppressed_since_last_report`, and a successful scrape after the window logs the pending count once (the `warned` time is moved back in the test) |
| `TestRegisterACMEBudgets_RejectsNil` | nil func / nil logger → error |
| `registeredFamilies` (shared helper in `deploy_test.go`) | also registers the budget collector with a one-level fake, so the dashboard reference is checked |
| `TestIntegration_ACMEBudgetExhaustedRetryAfter` (`internal/server/acme_budget_integration_test.go`, `//go:build integration`) | `startIntegrationServer` with `ACMEBudgetLEName "1/1h"`, `ACMEGTSAccounts nil` (only LE in the chain). `E` = the time elapsed since just before `client.Enroll`. Enroll (Pebble issues on LE). Then `Client.Renew` with a fresh nonce under a 30 s ctx. It sleeps the server's wait internally, so it returns at the ctx deadline with `errors.Join(*EnrollError, context.DeadlineExceeded)`. The `*EnrollError` is `acme_rate_limited`, and its `RetryAfter` is within [3600 s − E, 3610 s]: the name bucket's wait plus 1–10 s, with `retry_after_seconds` truncated to whole seconds. `tunneld_acme_issue_total{ca="letsencrypt"}` `ok` and `fail` are unchanged by the renewal (the LE account was never asked), and `/metrics` has a `tunneld_acme_budget_ratio{ca="letsencrypt",account="local",budget="orders"}` series |
| `TestIntegration_GTSOnlyIssues` (same file) | `ACMEDirLE ""` (GTS only, the harness's registered `gts` key): the server becomes ready (reserved hosts issued on GTS) and `client.Enroll` issues on GTS (`ident.CA == "gts"`) |

DoD:
- [ ] Tests added and adapted.

---

## [ ] US8 — Reference tunnel app (`support/tunnel-app`)

The faithful Kotlin client implements both phone rules and the 300 s issuance wait; its retry and single-flight logic are pure, JVM-tested types.

- [ ] AC1: 90 s without a control frame cancels the call, evicts the connection and reconnects on a new one.
- [ ] AC2: Issuance follows the retry rule, network errors and failed nonce fetches included.
- [ ] AC3: A `RENEW_NUDGE` that arrives while a nudge-driven renewal (or its retries) is running is ignored; no thread is started for it.

### [ ] T8.1 — watchdog

- [ ] A8.1.1 `.../tunnelapp/ControlWatchdog.kt` (create):

```kotlin
package com.example.tunnelapp

import android.util.Log
import okhttp3.Call
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

internal object ControlWatchdog {
    private val silenceNanos = TimeUnit.SECONDS.toNanos(90)
    private const val CHECK_SECONDS = 5L
    private val scheduler = ScheduledThreadPoolExecutor(1) { r -> Thread(r, "control-watchdog").apply { isDaemon = true } }
        .apply { removeOnCancelPolicy = true }

    fun watch(label: String, call: Call, lastFrameAt: AtomicLong, silent: AtomicBoolean): ScheduledFuture<*> =
        scheduler.scheduleWithFixedDelay({
            if (System.nanoTime() - lastFrameAt.get() > silenceNanos && !call.isCanceled()) {
                Log.w(TAG, "$label: no control frame for 90s; dropping the connection")
                silent.set(true)
                call.cancel()
            }
        }, CHECK_SECONDS, CHECK_SECONDS, TimeUnit.SECONDS)
}
```

- [ ] A8.1.2 `.../tunnelapp/SingleFlight.kt` (create):

```kotlin
package com.example.tunnelapp

import java.util.concurrent.atomic.AtomicBoolean

internal class SingleFlight {
    private val busy = AtomicBoolean(false)

    fun launch(name: String, block: () -> Unit): Boolean {
        if (!busy.compareAndSet(false, true)) return false
        try {
            Thread({
                try { block() } finally { busy.set(false) }
            }, name).apply { isDaemon = true }.start()
        } catch (t: Throwable) {
            busy.set(false)
            throw t
        }
        return true
    }
}
```

- [ ] A8.1.3 `.../tunnelapp/Tunnel.kt` (modify):
  - **Imports:** add `java.util.concurrent.atomic.AtomicLong`.
  - **`serveControlOnce`:** the existing comments in the method and in `duplexBody` stay.

```kotlin
    private fun serveControlOnce() {
        var sink: BufferedSink? = null
        val body = duplexBody { sink = it }
        val call = client.newCall(Request.Builder().url("https://$controlHost:$port/api/v1/control").post(body).build())
        val lastFrameAt = AtomicLong(System.nanoTime())
        val silent = AtomicBoolean(false)
        val watch = ControlWatchdog.watch("control", call, lastFrameAt, silent)
        try {
            call.execute().use { resp ->
                if (resp.code != 200) {
                    Log.w(TAG, "control connect rejected: ${resp.code}")
                    return
                }
                val s = sink ?: run {
                    Log.w(TAG, "control request body was not opened")
                    return
                }
                bound.countDown()
                val source = resp.body.source()
                try {
                    while (running.get()) {
                        val frame = Frames.read(source) ?: break
                        lastFrameAt.set(System.nanoTime())
                        when (frame.first) {
                            Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                            Frames.OPEN -> JSONObject(String(frame.second)).let { o ->
                                Thread {
                                    try { handleOpen(o) } catch (t: Throwable) { Log.w(TAG, "dial-back handling failed", t) }
                                }.apply { isDaemon = true }.start()
                            }
                            Frames.RENEW_NUDGE -> JSONObject(String(frame.second)).optString("nonce")
                                .takeIf { it.isNotEmpty() }
                                ?.let { n ->
                                    val started = renewals.launch("renewal") {
                                        try { onRenewNudge(n) } catch (t: Throwable) { Log.w(TAG, "renewal failed; keeping the current certs", t) }
                                    }
                                    if (!started) Log.i(TAG, "renewal already in progress; RENEW_NUDGE ignored")
                                }
                                ?: Log.w(TAG, "RENEW_NUDGE without a nonce ignored")
                        }
                    }
                } finally {
                    try { s.close() } catch (t: Throwable) { Log.d(TAG, "control request body close failed", t) }
                }
            }
        } finally {
            watch.cancel(false)
            if (silent.get()) client.connectionPool.evictAll()
        }
    }
```

  - **`Tunnel` gains** the field `private val renewals = SingleFlight()` (A8.1.2). It lives as long as the `Tunnel`, so it spans reconnections.

DoD:
- [ ] One shared scheduler thread; after silence the dead pooled connection is evicted; at most one renewal thread per tunnel.

### [ ] T8.2 — pure retry logic + 300 s

- [ ] A8.2.1 `.../tunnelapp/IssueRetry.kt` (create):

```kotlin
package com.example.tunnelapp

import java.io.IOException

internal object IssueRetry {
    const val RETRIES = 3

    fun waitMs(t: Throwable, retry: Int): Long? = when (t) {
        is EnrollError -> when {
            !t.retryable -> null
            t.retryAfterSec > 0 -> t.retryAfterSec * 1000
            else -> (retry + 1) * 5_000L
        }
        is IOException -> (retry + 1) * 5_000L
        else -> null
    }

    fun run(
        nonce: String?,
        issue: (String) -> Unit,
        freshNonce: () -> String,
        sleep: (Long) -> Unit,
        onRetry: (Int, Long, Throwable) -> Unit,
    ) {
        var n: String? = nonce
        var retry = 0
        while (true) {
            try {
                issue(n ?: freshNonce())
                return
            } catch (t: Throwable) {
                val wait = waitMs(t, retry)
                if (wait == null || retry >= RETRIES) throw t
                onRetry(retry + 1, wait, t)
                sleep(wait)
                n = null
                retry++
            }
        }
    }
}
```

- [ ] A8.2.2 `.../tunnelapp/Enroll.kt` (modify):
  - **Removed:** `MAX_ISSUE_RETRIES`.
  - **`getJson`:** `require(resp.code == 200) { … }` → `if (resp.code != 200) fail(resp.code, b)`, so a refused nonce fetch is a typed, possibly retryable `EnrollError`.
  - **`postJson`:** `readTimeout(60, …)` → `readTimeout(300, TimeUnit.SECONDS)`.
  - **Comment partly removed:** in the comment above `issue`, only the sentence "On a RETRYABLE server error it follows the documented retry path (docs/PROTOCOL.md §3): fetch a FRESH nonce from GET /api/v1/enroll/nonce, wait retry_after, then re-issue (bounded)." is removed. It is made wrong: the order and the scope of the retries changed. The first sentence ("issue: Phase 2 / every renewal, serialized by id.issueLock …") stays.
  - **`issue`** takes `nonce: String?` (`null` = fetch a fresh one first, inside the retry rule), plus the new `freshNonce`:

```kotlin
    fun issue(id: Identity, nonce: String?) {
        synchronized(id.issueLock) {
            IssueRetry.run(nonce, { n -> issueOnce(id, n) }, { freshNonce(id) }, { Thread.sleep(it) }) { n, wait, t ->
                Log.w(TAG, "issuance failed; retry $n in ${wait}ms", t)
            }
        }
    }

    private fun freshNonce(id: Identity): String =
        getJson(Tls.serverClient(id.trust), "https://${id.enrollHost}:${id.port}/api/v1/enroll/nonce").getString("nonce")
```

  - **`renew(id)`** becomes `issue(id, null)`, so the manual refresh's first nonce fetch is covered by the retry rule too. Its comment ("renew: the MANUAL refresh path (no RENEW_NUDGE frame to carry a nonce) mints a fresh nonce, then issues. …") stays true.
- [ ] A8.2.3 `support/tunnel-app/app/build.gradle.kts` (modify): `testImplementation("junit:junit:4.13.2")`.
- [ ] A8.2.4 `Makefile` (modify) `tunnel-app`: `./gradlew assembleDebug` → `./gradlew testDebugUnitTest assembleDebug`.

DoD:
- [ ] Issuance uses `IssueRetry`; the issuance wait is 300 s; a refused nonce fetch is an `EnrollError`; `make tunnel-app` runs the JVM unit tests.

### [ ] T8.3 — tests (JUnit 4, `support/tunnel-app/app/src/test/java/com/example/tunnelapp/`)

| Test | Verifies |
|---|---|
| `IssueRetryTest.successFirstTryNoSleep` | one issue, no sleep, no fresh nonce |
| `nullNonceFetchesFirst` | `nonce = null` → a fresh nonce is fetched before the first issue; a failure of that fetch is retried like any other |
| `retryAfterHonoured` | retryable `EnrollError` with `retryAfterSec` 7 → sleep 7000 ms, then success with a fresh nonce |
| `defaultSchedule` | retryable without `retryAfterSec` → sleeps 5000 / 10000 / 15000, then the 4th failure is rethrown |
| `ioExceptionRetried` | `IOException` → retried with the default schedule |
| `nonRetryableStops` | `retryable = false` → rethrown at once, no sleep |
| `freshNonceFailureCountsAsRetry` | `freshNonce` throws `IOException` once → one more retry consumed, then success |
| `otherThrowableStops` | `IllegalStateException` → rethrown at once |
| `SingleFlightTest.secondLaunchWhileBusyIsDropped` | a block waiting on a latch: a second `launch` returns false and its block never runs; after the latch opens, a new `launch` returns true |
| `SingleFlightTest.releasedAfterBlockThrows` | a block that throws, with `Thread.setDefaultUncaughtExceptionHandler` temporarily set to record it and restored after: the next `launch` returns true |

DoD:
- [ ] Tests added; `make tunnel-app` runs them.

---

## [ ] US9 — Soak app (`support/soak-app`)

Same phone rules; the phone answers on the dial-back connection itself (about 3 threads per phone) and there's no phone cap.

- [ ] AC1: Watchdog, retry rule, 300 s and single-flight renewals, as in US8. A failed issuance never re-enrolls: the phone is saved right after Phase 1, and a later `start` resumes it with issuance only.
- [ ] AC2: No Ktor/Netty, no local socket/port, no `maxPhones`.
- [ ] AC3: The soak client works against the HTTP/1.1-only responder without code changes.
- [ ] AC4: The responder's request parsing and its refusals are covered by JVM unit tests.

### [ ] T9.1 — watchdog + pure retry logic

- [ ] A9.1.1 `.../soakapp/ControlWatchdog.kt` (create): identical to A8.1.1 with `package com.example.soakapp`.
- [ ] A9.1.2 `.../soakapp/IssueRetry.kt` (create): identical to A8.2.1 with `package com.example.soakapp`.
- [ ] A9.1.3 `.../soakapp/SingleFlight.kt` (create): identical to A8.1.2 with `package com.example.soakapp`.
- [ ] A9.1.4 `.../soakapp/Tunnel.kt` (modify) `serveControlOnce`: the same structure as A8.1.3, including the `renewals` `SingleFlight` field and its `RENEW_NUDGE` branch, with:
  - this app's URL `net.url(controlHost, "/api/v1/control")`;
  - label `"phone $phone"`;
  - log prefixes `"phone $phone: "`;
  - the `AtomicLong` import.

DoD:
- [ ] As T8.1/T8.2.

### [ ] T9.2 — responder replaces the local server

Each action only uses what earlier actions created.

- [ ] A9.2.1 `.../soakapp/Responder.kt` (create):

```kotlin
package com.example.soakapp

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class Responder(private val phone: Int) {
    private class Head(val method: String, val target: String, val length: Long, val close: Boolean)

    private val context = AtomicReference<SSLContext>()

    fun install(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ServerTls.keyStore(tlsKey, chain), ServerTls.PASSWORD)
        context.set(SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) })
    }

    fun serve(conn: Socket, host: String) {
        val tls = try {
            (context.get().socketFactory.createSocket(conn, host, conn.port, true) as SSLSocket).apply {
                useClientMode = false
                sslParameters = sslParameters.apply { applicationProtocols = arrayOf("http/1.1") }
            }
        } catch (t: Throwable) {
            try { conn.close() } catch (c: Throwable) { t.addSuppressed(c) }
            throw t
        }
        tls.use { s ->
            s.startHandshake()
            val input = BufferedInputStream(s.inputStream)
            val output = BufferedOutputStream(s.outputStream)
            while (true) {
                val head = readHead(input) ?: return
                discard(input, head.length)
                val path = head.target.substringBefore('?')
                val size = head.target.substringAfter('?', "").split('&')
                    .firstOrNull { it.startsWith("resp=") }?.removePrefix("resp=")?.toIntOrNull()
                    ?.takeIf { it in 0..MAX_RESPONSE }
                when {
                    head.method != "POST" || path != "/op" -> { respond(output, 404, 0, true); return }
                    size == null -> { respond(output, 400, 0, true); return }
                    else -> respond(output, 200, size, head.close)
                }
                if (head.close) return
            }
        }
    }

    private fun readHead(input: InputStream): Head? {
        val start = readLine(input) ?: return null
        val parts = start.split(' ')
        if (parts.size != 3 || !parts[2].startsWith("HTTP/1.")) throw IOException("phone $phone: malformed request line")
        var length = 0L
        var close = parts[2] == "HTTP/1.0"
        repeat(MAX_HEADERS) {
            val line = readLine(input) ?: throw IOException("phone $phone: connection closed inside the request head")
            if (line.isEmpty()) return Head(parts[0], parts[1], length, close)
            val sep = line.indexOf(':')
            if (sep <= 0) throw IOException("phone $phone: malformed header line")
            val value = line.substring(sep + 1).trim()
            when (line.substring(0, sep).trim().lowercase()) {
                "content-length" -> length = value.toLongOrNull()?.takeIf { it in 0..MAX_BODY }
                    ?: throw IOException("phone $phone: bad Content-Length $value")
                "transfer-encoding" -> throw IOException("phone $phone: chunked request bodies are not supported")
                "connection" -> if (value.equals("close", ignoreCase = true)) close = true
            }
        }
        throw IOException("phone $phone: too many request headers")
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) {
                if (sb.isEmpty()) return null
                throw IOException("phone $phone: connection closed inside a line")
            }
            if (b == '\n'.code) return sb.toString().removeSuffix("\r")
            if (sb.length >= MAX_LINE) throw IOException("phone $phone: request line too long")
            sb.append(b.toChar())
        }
    }

    private fun discard(input: InputStream, length: Long) {
        var left = length
        val buf = ByteArray(16384)
        while (left > 0) {
            val n = input.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
            if (n < 0) throw IOException("phone $phone: connection closed inside the request body")
            left -= n
        }
    }

    private fun respond(out: OutputStream, status: Int, size: Int, close: Boolean) {
        val reason = when (status) {
            200 -> "OK"
            400 -> "Bad Request"
            else -> "Not Found"
        }
        val head = "HTTP/1.1 $status $reason\r\nContent-Type: application/octet-stream\r\nContent-Length: $size\r\n" +
            (if (close) "Connection: close\r\n" else "") + "\r\n"
        out.write(head.toByteArray(Charsets.US_ASCII))
        out.write(PATTERN, 0, size)
        out.flush()
    }

    companion object {
        private const val MAX_RESPONSE = 65536
        private const val MAX_BODY = 1L shl 20
        private const val MAX_HEADERS = 64
        private const val MAX_LINE = 8192
        private val PATTERN = ByteArray(MAX_RESPONSE) { (it % 251).toByte() }
    }
}
```

Context: Conscrypt always builds an engine socket when wrapping an existing socket (`USE_ENGINE_SOCKET_BY_DEFAULT = true`), so server-mode TLS over the dial-back socket works; that's why the dial-back reader must not buffer past the `101` (A9.2.2).

- [ ] A9.2.2 `.../soakapp/DialBack.kt` (modify):
  - **Removed:** `class Conn` and the `BufferedInputStream` (and its import).
  - **`open`** returns the `Socket`; signature `fun open(token: String, addr: String, useHttps: Boolean, useMtls: Boolean): Socket`. Its end becomes:

```kotlin
            val status = readStatus(s.getInputStream())
            check(status == 101) { "dial-back refused: $status" }
            s.soTimeout = 0
            return s
```

- [ ] A9.2.3 `.../soakapp/Tunnel.kt` (modify):
  - **Constructor:** `responder: Responder` replaces `localServerPort: () -> Int`.
  - **`handleOpen`,** after the `OPEN` validation:

```kotlin
        val remote = try {
            dialBack.open(token, addr, useHttps, useMtls)
        } catch (t: Throwable) {
            Log.w(TAG, "phone $phone: dial-back to $addr failed", t)
            return
        }
        try {
            responder.serve(remote, controlHost)
        } catch (t: Throwable) {
            Log.d(TAG, "phone $phone: dial-back session from $addr ended", t)
        }
```

  - **Removed:** `splice`, `copy`, and the `InputStream` / `OutputStream` / `Socket` imports.

DoD:
- [ ] The responder and the unbuffered dial-back are in place; `Tunnel` serves each dial-back through the responder.

### [ ] T9.3 — enrollment, issuance and saving

- [ ] A9.3.1 `.../soakapp/Enroll.kt` (modify):
  - **Constants:** `MAX_ISSUE_RETRIES` is removed; `postJson` uses `readTimeout(300, TimeUnit.SECONDS)`.
  - **Phase 1:** `enrollOnce` becomes `phase1Once(...): Pair<Identity, String>`, returning `id to r.getString("issue_nonce")` without calling `issue`.
  - **`enroll`** is Phase 1 only. It keeps the existing retry loop body unchanged and returns the bootstrap identity plus the issue nonce, so the caller can save the phone before issuing. **`issue`** takes `nonce: String?`, where `null` means fetch a fresh one first:

```kotlin
    fun enroll(net: Net, phone: Int, enrollHost: String, controlHost: String, tunnelDomain: String): Pair<Identity, String> {
        var attempt = 0
        while (true) {
            try {
                return phase1Once(net, phone, enrollHost, controlHost, tunnelDomain)
            } catch (e: EnrollError) {
                if (!e.retryable || attempt++ >= MAX_ENROLL_RETRIES) throw e
                Log.w(TAG, "phone $phone: enrollment refused (${e.reason}), retrying in ${e.retryAfterSec}s")
                Thread.sleep(e.retryAfterSec.coerceAtLeast(1) * 1000)
            } catch (e: IOException) {
                if (attempt++ >= MAX_ENROLL_RETRIES) throw e
                Log.w(TAG, "phone $phone: enrollment network error, retrying in 2s", e)
                Thread.sleep(2000)
            } catch (e: ProviderException) {
                if (attempt++ >= MAX_ENROLL_RETRIES) throw e
                Log.w(TAG, "phone $phone: key generation failed, retrying in 3s", e)
                Thread.sleep(3000)
            }
        }
    }

    fun issue(id: Identity, nonce: String?) {
        synchronized(id.issueLock) {
            IssueRetry.run(nonce, { n -> issueOnce(id, n) }, { freshNonce(id) }, { Thread.sleep(it) }) { n, wait, t ->
                Log.w(TAG, "phone ${id.phone}: issuance failed; retry $n in ${wait}ms", t)
            }
        }
    }

    private fun freshNonce(id: Identity): String =
        getJson(id.net.serverClient(), id.net.url(id.enrollHost, "/api/v1/enroll/nonce")).getString("nonce")
```

- [ ] A9.3.2 `.../soakapp/PhoneStore.kt` (modify) `parse`: a phone saved before its first issuance has an empty `public_chain`, so that field is parsed as `j.getString("public_chain").let { if (it.isEmpty()) emptyArray() else Enroll.parseChain(it) }`. `save` already writes an empty chain and an empty `tls_alias` for such a phone, and `forgetAll` already skips empty aliases.
- [ ] A9.3.3 `Makefile` (modify) `soak-app`: `./gradlew assembleDebug` → `./gradlew testDebugUnitTest assembleDebug`.

DoD:
- [ ] Phase 1 and issuance are separate; a phone without a public cert can be saved and loaded.

### [ ] T9.4 — `SoakService` wiring

- [ ] A9.4.1 `.../soakapp/SoakService.kt` (modify):
  - **Phone:** `Phone(val name: String, val tunnel: Tunnel)`.
  - **Removed:** `basePort` and `maxPhones`; `require(count >= 1) { "count must be >= 1, got $count" }`.
  - **`bringUp`** saves a new phone right after Phase 1, and resumes a saved phone that has no public cert with issuance only:

```kotlin
    private fun bringUp(net: Net, store: PhoneStore, env: Env, i: Int, jitter: Boolean) {
        val saved = store.load(i)
        val id = if (saved != null) {
            restore(net, i, saved)
        } else {
            if (jitter) Thread.sleep(Random.nextLong(0, 5001))
            Keys.deleteAll(Enroll.aliasPrefix(env, i))
            val (fresh, issueNonce) = Enroll.enroll(net, i, env.enrollHost, env.controlHost, env.tunnelDomain)
            store.save(i, fresh)
            Enroll.issue(fresh, issueNonce)
            store.save(i, fresh)
            fresh
        }
        if (id.state().tlsAlias.isEmpty()) {
            Log.i(TAG, "phone $i (${id.name}): saved without a public cert; issuing only, never re-enrolling")
            Enroll.issue(id, null)
            store.save(i, id)
        }
        val (key, chain) = id.tlsCredential()
        val responder = Responder(i).also { it.install(key, chain) }
        val renewLock = Any()
        val tunnel = Tunnel(i, net, id.mtlsClient(), env.controlHost, net.dialBack(env.controlHost, id), responder) { nonce ->
            synchronized(renewLock) {
                Enroll.issue(id, nonce)
                store.save(i, id)
                id.tlsCredential().let { (k, c) -> responder.install(k, c) }
            }
        }
        Thread { tunnel.run() }.apply { isDaemon = true }.start()
        if (!tunnel.awaitBound(60)) {
            tunnel.stop()
            error("phone $i (${id.name}): control stream not bound within 60s")
        }
        phones[i] = Phone(id.name, tunnel)
        Log.i(TAG, "phone $i bound as ${id.name}${if (saved != null) " (resumed)" else ""}")
    }
```

  - **`restore`:** the TLS key check runs only for a phone that has one: `if (s.tlsAlias.isNotEmpty()) Keys.privateKey(s.tlsAlias)`.
  - **`doStop`:** `phones.values.forEach { it.tunnel.stop() }`.
- [ ] A9.4.2 delete `.../soakapp/Server.kt` (no longer referenced).
- [ ] A9.4.3 `support/soak-app/app/build.gradle.kts` (modify):
  - **Removed:** the `ktor-server-core`, `ktor-server-netty` (with its exclude) and `slf4j-jdk14` dependencies, and the `"META-INF/io.netty.versions.properties"` packaging exclude.
  - **Added:** `testImplementation("junit:junit:4.13.2")`.

DoD:
- [ ] No reference to Ktor/Netty/`Server`/`basePort`/`maxPhones` remains. A phone whose issuance gave up stays saved, and the next `start` resumes it without enrolling again.

### [ ] T9.5 — tests (JUnit 4, `support/soak-app/app/src/test/java/com/example/soakapp/`)

| Test | Verifies |
|---|---|
| (same `IssueRetryTest` and `SingleFlightTest` cases as T8.3) | the soak copies behave identically |
| `ResponderTest` | Setup, shared by every case: a self-signed P-256 cert and key built with BouncyCastle (already an `implementation` dependency); `Responder.install`; a loopback `ServerSocket` whose accepted socket goes to `serve` on a thread; the client is an `SSLSocket` trusting that cert. All cases below run in this class |
| `ResponderTest.okResponseSizedByResp` | `POST /op?resp=100` with a 10-byte body → `200`, `Content-Length: 100`, bytes `i % 251` |
| `ResponderTest.keepAliveServesSeveral` | two requests on one connection → two `200`s, the connection stays open |
| `ResponderTest.wrongMethodOrPath404` | `GET /op?resp=1` and `POST /x?resp=1` → `404` with `Connection: close`, then EOF |
| `ResponderTest.badResp400` | `resp` missing, non-numeric, `-1`, `65537` → `400` with `Connection: close`, then EOF |
| `ResponderTest.http10AndConnectionClose` | `HTTP/1.0` request, and `Connection: close` on 1.1 → response, then EOF |
| `ResponderTest.refusedHeadsCloseWithoutResponse` | a malformed request line, `Transfer-Encoding: chunked`, a non-numeric or > 1 MiB `Content-Length`, 65 header lines, an 8193-byte line → `serve` throws `IOException`, and the client reads EOF with no response |
| `ResponderTest.setupFailureClosesSocket` | `serve` before any `install` → it throws, and the raw socket is closed |
| `TestRun_TrustsTheCAFileAndDialsTheConnectAddress` (existing, `support/soak-client/soak`, unchanged) | the real `transportFactory` against an `httptest` TLS server, whose ALPN is only `http/1.1` (`httptest.Server.StartTLS` without `EnableHTTP2`), ends with `errors=0`; this covers AC3 at unit level. `TestE2E_SoakApp` (existing) covers it against the device |

DoD:
- [ ] Tests added; `make soak-app` runs them.

---

## [ ] US10 — Device-gate coverage of the app rules (`e2e/`)

The Kotlin liveness, retry and give-up rules get automated coverage on the attached device.

- [ ] AC1: Both apps reconnect over a new connection after a black-holed control connection.
- [ ] AC2: The reference app completes a renewal through exactly one server-paced retry, and gives up after 3 retries when issuance stays impossible.
- [ ] AC3: A soak phone whose issuance stays impossible fails after 3 retries without enrolling a second name, also across a second `start`.
- [ ] AC4: Every "give up" scenario finishes in minutes. The retry waits come from a replica whose CAs are unreachable (backoff 1 s / 5 s + 1–10 s jitter), never from an hour-long budget.

### [ ] T10.1 — harness (shared test infrastructure, in full)

- [ ] A10.1.1 `e2e/e2e_test.go` (modify):
  - **`replicaOpts` gains** (no comments):

```go
	acmeDirGTS     string
	leNameBudget   string
	backoffInitial time.Duration
	backoffMax     time.Duration
```

  - **`runReplicaOnce`:** the two lines A5.3.2 added after the `cfg` literal become:

```go
	tunneltest.LooseACMEBudgets(&cfg)
	if opts.leNameBudget != "" {
		cfg.ACMEBudgetLEName = opts.leNameBudget
	}
	if opts.backoffInitial != 0 {
		cfg.ACMEBackoffInitial = opts.backoffInitial
	}
	if opts.backoffMax != 0 {
		cfg.ACMEBackoffMax = opts.backoffMax
	}
	if opts.acmeDirGTS != "" {
		cfg.ACMEDirGTS = opts.acmeDirGTS
		tunneltest.WriteACMEAccountKey(t, cfg.ACMEAccountDir, "gts")
	} else {
		tunneltest.RegisterACMEAccountKey(t, cfg.ACMEAccountDir, "gts", inf.pebble.DirectoryURL)
	}
```

- [ ] A10.1.2 `e2e/app_rules_test.go` (create): the device-side wiring shared by the T10.2 scenarios. The existing device gates keep their own inline setup. The "failing issuer" uses two replicas: replica A issues the reserved-host certificates and publishes them in Valkey, and replica B adopts them at startup (`reservedCerts.loadCache` → `adoptShared`) while its LE and GTS directories are unreachable. ZeroSSL is out of the e2e chain (no EAB, A5.3.5). So every issuance on B fails at once, and the answer's `retry_after_seconds` is B's backoff (1 s, at most 5 s) plus 1–10 s.

```go
//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

const (
	appRulesDevicePort = 18446
	unreachableACMEDir = "https://127.0.0.1:1/dir"
)

func attestedOpts(fixture string) replicaOpts {
	return replicaOpts{
		attestRootURL:     googleAttestRootURL,
		attestStatusURL:   googleAttestStatusURL,
		attestSignerFile:  filepath.Join("..", "fixtures", fixture, "signers.allow"),
		dialBackAdvertise: "127.0.0.1:" + strconv.Itoa(appRulesDevicePort),
	}
}

func startFailingIssuer(t *testing.T, inf *e2eInfra, opts replicaOpts) string {
	t.Helper()
	inf.startReplica(t, opts)
	broken := opts
	broken.acmeDirLE, broken.acmeDirGTS = unreachableACMEDir, unreachableACMEDir
	return inf.startReplica(t, broken)
}

func reverseVia(t *testing.T, serial, edge string) *tunneltest.BlackholeProxy {
	t.Helper()
	p := tunneltest.StartBlackholeProxy(t, edge)
	_, port, err := net.SplitHostPort(p.Addr())
	if err != nil {
		t.Fatalf("split proxy addr %q: %v", p.Addr(), err)
	}
	adb(t, serial, "reverse", "tcp:"+strconv.Itoa(appRulesDevicePort), "tcp:"+port)
	t.Cleanup(func() { adbCleanup(t, serial, "reverse", "--remove", "tcp:"+strconv.Itoa(appRulesDevicePort)) })
	return p
}

func prepareApp(t *testing.T, serial string, inf *e2eInfra, pkg, fixture string) string {
	t.Helper()
	apkPath := filepath.Join("..", "fixtures", fixture, fixture+".apk")
	wantSum, err := os.ReadFile(apkPath + ".sha256")
	if err != nil {
		t.Fatalf("read committed APK sha256: %v", err)
	}
	if got := apkSHA256(t, apkPath); got != strings.TrimSpace(string(wantSum)) {
		t.Fatalf("committed %s APK sha256 mismatch: got %s want %s (run 'make %s')", fixture, got, strings.TrimSpace(string(wantSum)), fixture)
	}
	adb(t, serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
	adbCtx(t, serial, adbInstallTimeout, "install", "-r", apkPath)
	adb(t, serial, "shell", "cmd", "deviceidle", "whitelist", "+"+pkg)
	t.Cleanup(func() { adbCleanup(t, serial, "shell", "cmd", "deviceidle", "whitelist", "-"+pkg) })
	t.Cleanup(func() {
		adbCleanup(t, serial, "shell", "am", "broadcast", "-a", pkg+".stop", "-n", pkg+"/.CommandReceiver", "-f", "0x00000020")
	})
	adbRunAs(t, serial, pkg, "rm -f files/ready files/error files/info.json files/names.txt files/failures.txt files/forgotten")
	caB64 := base64.StdEncoding.EncodeToString(inf.pebble.IssuingRootsPEM)
	adbRunAs(t, serial, pkg, "mkdir -p files && echo "+caB64+" | base64 -d > files/pebble-ca.pem")
	return strings.TrimSpace(string(adbRunAs(t, serial, pkg, "pwd"))) + "/files/pebble-ca.pem"
}

func enrollTunnelApp(t *testing.T, serial, caPath string) string {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	appNonce := hex.EncodeToString(nonce[:])
	amBroadcast(t, serial, tunnelAppPkg, "enroll",
		"edgePort", strconv.Itoa(appRulesDevicePort),
		"appNonce", appNonce,
		"pebbleCaPath", caPath,
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	return appNonce
}

func forgetSoakPhones(t *testing.T, serial string) {
	t.Helper()
	amBroadcast(t, serial, soakAppPkg, "forget",
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	pollAppFile(t, serial, soakAppPkg, "forgotten", 60*time.Second)
}

func startSoakPhones(t *testing.T, serial, caPath string, count int) string {
	t.Helper()
	adbRunAs(t, serial, soakAppPkg, "rm -f files/ready files/failures.txt")
	amBroadcast(t, serial, soakAppPkg, "start",
		"count", strconv.Itoa(count),
		"spacingSeconds", "0",
		"parallel", "true",
		"edgePort", strconv.Itoa(appRulesDevicePort),
		"caPath", caPath,
		"enrollHost", e2eEnrollHost,
		"controlHost", e2eControlHost,
		"tunnelDomain", e2eTunnelDomain,
	)
	return strings.TrimSpace(string(pollAppFile(t, serial, soakAppPkg, "ready", 300*time.Second)))
}

func pollAppError(t *testing.T, serial, pkg string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		status := string(adbRunAs(t, serial, pkg, "if [ -f files/error ]; then echo ERR; cat files/error; fi"))
		if rest, ok := strings.CutPrefix(status, "ERR"); ok {
			return strings.TrimSpace(rest)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not produce files/error within %s", pkg, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func metricSeriesValue(t *testing.T, internalAddr, series string) float64 {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + internalAddr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer tunneltest.CloseOrLog(t, resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, series+" "); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return f
		}
	}
	return 0
}
```

DoD:
- [ ] Harness options and device helpers in place. The device port 18446 is used by no other gate.

### [ ] T10.2 — scenarios (`e2e/app_rules_test.go`; each skips without a single adb device, like the existing gates)

| Test | Setup | Verifies |
|---|---|---|
| `TestE2E_ReferenceTunnelAppReconnectsAfterSilence` | `edge := inf.startReplica(t, attestedOpts("tunnel-app"))`; `p := reverseVia(t, serial, edge)`; `prepareApp(…, tunnelAppPkg, "tunnel-app")`; `enrollTunnelApp`; poll `ready` (150 s) | `p.Freeze()`. Within 150 s, `p.Accepted()` grows (the app dialed a new control connection after 90 s of silence), and `fetchInfo(edge, fqdn, roots)` succeeds again with the same app nonce |
| `TestE2E_ReferenceTunnelAppRenewRetrySucceeds` | one replica: `attestedOpts("tunnel-app")` + `leNameBudget "1/60s"`, `acmeDirGTS: unreachableACMEDir`, backoff 2 min / 2 min (so GTS's cooldown is longer than the LE name wait); enroll as above | `adb logcat -c`, `rm files/ready files/info.json`, broadcast `refresh`, poll `ready` (150 s). The app's wait is read from `adb logcat -d -v raw -s TunnelApp:W`. There is exactly one `issuance failed; retry 1 in <ms>ms` line and no `retry 2` line, and `<ms>` is in (5000, 70000]: the server's pace (the LE name wait + 1–10 s), not the 5 s default. `info.json` keeps the name and has a changed `tls_cert_sha256`; `tunneld_rejections_total{reason="acme-failed"}` = 1 |
| `TestE2E_ReferenceTunnelAppIssueGivesUp` | `edgeB := startFailingIssuer(t, inf, attestedOpts("tunnel-app"))`; `reverseVia(t, serial, edgeB)`; `prepareApp`; `enrollTunnelApp` | `pollAppError(t, serial, tunnelAppPkg, 150*time.Second)` returns (the existing `pollAppFile` fails on `files/error`, so it cannot be used here). On B (`inf.internal[edgeB]`): `tunneld_rejections_total{reason="acme-failed"}` = 4 (the first attempt + 3 retries) and `tunneld_enrollments_total{result="ok"}` = 1 |
| `TestE2E_SoakAppReconnectsAfterSilence` | `edge := inf.startReplica(t, attestedOpts("soak-app"))`; `p := reverseVia`; `prepareApp(…, soakAppPkg, "soak-app")`; `forgetSoakPhones`; `startSoakPhones(…, 2)` = `"2"` | `p.Freeze()`. Within 150 s `p.Accepted()` grows by at least 2 more control connections. Then a 20 s `soak.Run` (names from `files/names.txt`, `--connect` the edge, as in `TestE2E_SoakApp`) ends with zero errors |
| `TestE2E_SoakAppIssueGivesUpWithoutReEnrolling` | `edgeB := startFailingIssuer(t, inf, attestedOpts("soak-app"))`; `reverseVia(t, serial, edgeB)`; `prepareApp`; `forgetSoakPhones` | `startSoakPhones(…, 1)` = `"0"`, `files/failures.txt` lists phone 0, and on B `acme-failed` = 4 and `enrollments_total{result="ok"}` = 1. A second `startSoakPhones(…, 1)` = `"0"` again: `acme-failed` = 8 and enrollments still 1, because the saved phone resumed with issuance only |

DoD:
- [ ] Scenarios added.

---

## [ ] US11 — CI uses the new GTS staging account

The staging tier must run on the dedicated `arc-tunnel-acme-gts-staging` project's account.

- [ ] AC1: GitHub secret `TUNNELD_STAGING_GTS_ACCOUNT_KEY` holds `~/.secrets/arc-tunnel-acme-gts-staging-account.key`.

### [ ] T11.1 — switch the secret

- [ ] A11.1.1 (the value is read from stdin, never on a command line):

```bash
gh secret set TUNNELD_STAGING_GTS_ACCOUNT_KEY < ~/.secrets/arc-tunnel-acme-gts-staging-account.key
gh secret list | grep -E '^TUNNELD_STAGING_GTS_ACCOUNT_KEY'
```

DoD:
- [ ] Secret updated (new timestamp).

---

## [ ] US12 — Documentation

Canonical docs and the project rules describe what was built.

- [ ] AC1: PROJECT, ARCHITECTURE, README, `deploy/tunneld.env.example` and `.claude/rules/project.md` are accurate; no duplication beyond references.

### [ ] T12.1 — docs

- [ ] A12.1.1 `docs/PROJECT.md` (modify):
  - **§2:** the "Server-run ACME chain" bullet gains, after its first sentence:

> Each CA is optional: Let's Encrypt is used unless `--acme-dir-le` is empty, GTS only for the EXISTING accounts
> listed in `--acme-gts-account` (one per Public CA project; tunneld looks them up by key and never creates
> them), ZeroSSL only when its EAB pair is set. Issuance is planned against per-CA budgets kept in Valkey (token
> buckets per registered domain, account, name and request rate), so a CA is asked only when it has budget; a
> 429 makes that account wait out its Retry-After cluster-wide.

  - **§4:** after the caps table, insert:

> ### ACME issuance budgets
>
> | Budget | Flag | Default |
> |---|---|---|
> | LE new certificates / registered domain | `--acme-budget-le-domain` | `50/168h` |
> | LE new orders / account | `--acme-budget-le-orders` | `300/3h` |
> | LE certificates / exact name | `--acme-budget-le-name` | `5/168h` |
> | GTS new orders / account | `--acme-budget-gts-orders` | `100/1h` |
> | GTS requests / account | `--acme-budget-gts-requests` | `120/1m` |
> | GTS `/cert/` requests / account | `--acme-budget-gts-cert-polls` | `50/1m` |
> | ZeroSSL new orders / account | `--acme-budget-zerossl-orders` | `200/1h:40` |
> | ZeroSSL requests / account | `--acme-budget-zerossl-requests` | `240/1m` |
> | Order attempt deadline LE / GTS / ZeroSSL | `--acme-attempt-timeout-{le,gts,zerossl}` | `20s` / `40s` / `90s` |
> | First certificate poll LE / GTS / ZeroSSL | `--acme-poll-first-{le,gts,zerossl}` | `2s` / `5.6s` / `15.2s` |
> | Following polls | `--acme-poll-interval` | `2s` |
>
> Rates are `<count>/<period>[:<burst>]` token buckets. The registered domain is the certificate name's eTLD+1
> (Public Suffix List), as Let's Encrypt counts it. A renewal of an LE certificate on LE draws only the per-name
> budget, for phone names and tunneld's own reserved hosts alike.

  - **§5 Valkey list:**
    - "ACME cooldown/backoff" → "per-account ACME wait-until/backoff";
    - after it, add "the ACME issuance budgets (`acme-budget:{bucket}` token buckets, the per-node in-flight orders `acme:inflight:{bucket}:{node}`, the per-CA lock `lock:acme-budget:{ca}`)";
    - the TTL sentence ("…or a pipelined `PEXPIRE` (the `conc:{name}` and `nodes` sets); NO Lua/WATCH/MULTI-EXEC.") gains, before "; NO Lua", "; the per-account ACME wait-until is a pipelined `EXPIRE GT` + `SET NX EX` and the in-flight order sets a pipelined `EXPIRE NX` + `EXPIRE GT`, so neither TTL is ever shortened".
  - **§6:** after "`tunneld_connlog_dropped_total` counts…" sentence, add: "`tunneld_acme_budget_ratio{ca,account,budget}` is the remaining issuance budget (0–1) per CA account; `tunneld_acme_rate_limited_total{ca}` counts the CAs' 429 answers."
  - **§7 soak paragraph:**
    - "local HTTPS server answering `POST /op?resp=<bytes>`" → "answers on the dial-back connection itself (TLS with the phone's public cert, HTTP/1.1) `POST /op?resp=<bytes>`";
    - delete "(max 200)";
    - after "…a saved phone whose keys are unusable fails its start instead of being replaced." insert: "A phone is saved right after its enrollment. If its issuance gives up after the retries (docs/PROTOCOL.md §3), it stays saved without a public cert and the next `start` retries only the issuance, so a phone never enrolls a second name."
- [ ] A12.1.2 `docs/ARCHITECTURE.md` (modify):
  - **§1 package map:**
    - `internal/acme`: "per-CA cooldown/backoff retry-after" → "per-account issuance budgets + wait-until/backoff, budgeted HTTP transport, optional CAs, several GTS accounts looked up by key";
    - `internal/limit`: "ACME cooldown" → "ACME issuance budgets + wait-until".
  - **§3:**
    - in the TLS-ALPN-01 paragraph, "sets no per-CA cooldown" → "sets no per-account wait-until";
    - append the paragraph:

> **Issuance budgets.** Each enabled CA contributes accounts: Let's Encrypt and ZeroSSL one per node (its key
> under `--acme-account-dir`), GTS one per listed existing account. Before an order the chain reserves one slot in
> every Valkey token bucket the order draws on (`acme:inflight:{bucket}:{node}`, scored by the attempt's
> deadline); only live nodes' reservations count. The LE per-domain bucket is keyed on the name's registered domain
> (eTLD+1), and an LE renewal of an LE certificate (phone or reserved host) draws only the per-name bucket.
> Success spends the reservation; a created order always spends
> its order bucket; an order finalized and then abandoned counts as issued; other failures release. Every ACME
> request goes through a per-account HTTP transport around lego that refuses or holds requests while the account
> waits out a 429 (a cluster-wide wait-until, never shortened) or lacks request budget, delays the first
> certificate poll after finalize to the CA's median wait + 2 s and spaces the rest 2 s apart, and on a 429
> resyncs only the bucket the CA named. Each attempt has a deadline (LE 20 s, GTS 40 s, ZeroSSL 90 s); an
> abandoned attempt removes its pending TLS-ALPN-01 challenge; a run is capped at 290 s. Any unsuccessful attempt
> other than a 429 (a CA error, the attempt deadline, or a request tunneld refused or held) puts the account on the
> exponential backoff. GTS accounts are tried
> by remaining order budget. When no account can take the order, the issue answer is `acme_rate_limited` with
> `retry_after_seconds` = the earliest free slot + a random 1–10 s. Decision record:
> [Plan 17](plans/17_acme_budgets_and_client_resilience_20261015170942.md).

  - **§5:**
    - the header's mechanism list "SET EX / a SETNX lock / a pipelined EXPIRE NX / a pipelined PEXPIRE" gains " / a pipelined EXPIRE GT";
    - "per-CA ACME cooldown/backoff" → "per-account ACME wait-until/backoff (the wait-until a pipelined `EXPIRE GT` + `SET NX EX`, never shortened)";
    - append: "the ACME issuance budgets — `acme-budget:{bucket}` (hash `{t, at}`, `HSET` + pipelined `PEXPIRE` = time to refill to full + 1 h), `acme:inflight:{bucket}:{node}` (`ZADD` + pipelined `EXPIRE NX` + `EXPIRE GT` = deadline + 1 min, never shortened) and the per-CA lock `lock:acme-budget:{ca}` (`SETNX`, 2 s TTL)".
  - **§8:**
    - after the Valkey pool sentence add: "`tunneld_acme_budget_ratio{ca,account,budget}` reads the budget buckets at scrape time (2 s timeout; an error drops only that family, Warn ≤ 1/min)."
    - after the `tunneld_acme_renew_total{ca,result}` sentence (ending "every CA in the chain declined).") add: "`tunneld_acme_cooldown_total{ca}` counts account wait-until activations and `tunneld_acme_rate_limited_total{ca}` the CAs' 429 answers."
- [ ] A12.1.3 `README.md` (modify):
  - **Line 49:** "per-CA account keys" → "per-account ACME keys".
  - **ACME quickstart:** after the challenge-method step, add:

> GTS (optional): create one Google Cloud Public CA project per GTS account, register each account once with that
> project's single-use EAB (outside tunneld), put its key at `<acme-account-dir>/accounts/<id>.key` and list the
> ids in `TUNNELD_ACME_GTS_ACCOUNT`; tunneld only looks the accounts up and never creates them. ZeroSSL is used
> only when both `TUNNELD_ACME_EAB_ZEROSSL_*` values are set; Let's Encrypt unless `TUNNELD_ACME_DIR_LE` is empty.

- [ ] A12.1.4 `.claude/rules/project.md` (modify):
  - **ACME tech-stack row:** "per-CA cooldown/backoff retry-after" → "optional CAs, per-account Valkey issuance budgets + wait-until/backoff, several GTS accounts looked up by key".
  - **Valkey invariant:**
    - the key list adds "the ACME issuance budgets (`acme-budget:` via `HSET` + pipelined `PEXPIRE`, TTL = time to refill + 1 h; `acme:inflight:` via `ZADD` + pipelined `EXPIRE NX` + `EXPIRE GT`, TTL = deadline + 1 min, never shortened; `lock:acme-budget:` a `SETNX` lock, 2 s TTL)";
    - the mechanism sentence ("…or a pipelined `PEXPIRE` (the `conc:{name}` and `nodes` sets).") gains "; the per-account ACME wait-until uses a pipelined `EXPIRE GT` + `SET NX EX` so it is never shortened".
  - **Commit scopes** (full new texts):
    - `acme`: "`internal/acme`: LE→GTS→ZeroSSL issuance chain (lego clients, DNS-01 / HTTP-01 / TLS-ALPN-01, challenge store, per-account issuance budgets + wait-until/backoff, budgeted HTTP transport, several GTS accounts looked up by key)";
    - `limit`: "`internal/limit`: rate windows, enroll quota, global stream counter, per-second bandwidth+packet windows, ACME issuance budgets + wait-until".
  - **Standard Commands:** the line "`make soak-app` / `make soak-client` — build the soak-test app (into `fixtures/soak-app/`) and its load client (`docs/PROJECT.md` §7)" becomes "`make tunnel-app` / `make soak-app` — run the app's JVM unit tests (`testDebugUnitTest`) and build its APK fixture (into `fixtures/tunnel-app/` / `fixtures/soak-app/`); `make soak-client` — the soak load client (`docs/PROJECT.md` §7)".
  - **Status line:** mentions Plan 17.

DoD:
- [ ] Docs match the code.

---

## [ ] US13 — Ground-up verification

Everything built in this plan is checked from the ground up before the PR.

- [ ] AC1: Every user story is verified against the code and every deviation is recorded.
- [ ] AC2: All quality gates and CI are green.

### [ ] T13.1 — double-check EVERYTHING from the ground up

- [ ] A13.1.1 Re-read this plan and verify every US/AC/action against the code; record every deviation in `## Deviations`.
- [ ] A13.1.2 Rebuild the app fixtures (this runs their JVM unit tests): `make tunnel-app` and `make soak-app`. APK + sha256; the signer digests are unchanged.
- [ ] A13.1.3 Quality gates via the Makefile, each tee'd to `/tmp/plan17-*.log`:
  - `make lint`, `make vet`, `make build`, `make govulncheck`, `make tidy` (no diff);
  - `make test-unit`, `make test-integration`, `make test-e2e`. The Realme is attached, so every device gate runs, including US10.
  - `make test-scripts`, `make compose-config`.
- [ ] A13.1.4 CI on the pushed branch is green, including `test-staging` on the new GTS staging account (US11). Branch pushes do not trigger `ci.yml`, so the run is dispatched: `gh workflow run ci.yml --ref feat/plan-17-acme-budgets-client-resilience`, then `gh run watch` on that run.
- [ ] A13.1.5 Grep checks:
  - no new comment in changed Go/Kotlin files. Manually review every added `//` / `/*` line in the diff: it must be a `//go:build` directive of a new tagged test file, or a shortened form of a comment removed in the same hunk (a part made wrong was cut). Anything else is a violation;
  - no `maxPhones`, `basePort`, `io.ktor` or `Server(` in `support/soak-app`;
  - `git grep -nE 'ACMEEABGTS|acme-eab-gts|ACME_EAB_GTS' -- ':!docs/plans'` → only `TestServeCmd_NoGTSEABFlags`'s rejected-flag strings (plan files are permanent records and keep the old names);
  - no `TODO`.

DoD:
- [ ] All gates green; plan checkmarks complete; deviations recorded.

---

## Deviations

- **A2.1.1** (`internal/tunneltest/blackhole.go`). The cleanup's `conns := p.conns` became `conns := slices.Clone(p.conns)`. `reap` removes finished pairs with `slices.DeleteFunc`, which since Go 1.22 zeroes the freed tail of the same backing array. The cleanup's view of the old slice header could therefore hold nil entries and dereference them. The action's code block is updated to match.
