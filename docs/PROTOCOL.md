# tunneld Wire Protocol (v2 — End-to-End Encrypted)

This is the CANONICAL wire contract for the E2E-encrypted tunnel. The Go client in `client/` and the
Android (Kotlin) client both conform to THIS document, not to the Go source. `internal/wire` holds the
frame codec.

tunneld relays **opaque TLS bytes** and can NEVER read tunnel traffic: external clients establish TLS
directly with the phone, which holds a publicly-trusted (WebPKI) certificate for its assigned hostname.
tunneld is the internet edge (raw TCP `:443`), peeks the ClientHello (SNI/ALPN/version/JA4), routes on
SNI (a ClientHello whose first ALPN protocol is `acme-tls/1` is an ACME TLS-ALPN-01 validation answered locally by tunneld, never spliced), and splices the encrypted byte stream to a connection the phone dials back to the entry node.

## 1. Identity & authentication

- **No TLS mutual auth on the public side.** The phone authenticates to tunneld with an internal-CA
  **identity client certificate** over its outbound HTTP/2 **control connection** (mTLS). The assigned
  tunnel name is the certificate's **CN**; the server DERIVES the name from the CN (the phone dials the
  single shared `--control-host`, so there is no per-tunnel Host on the control connection). The phone
  presents its current identity certificate on each dial-back connection (§4) when the `OPEN` sets `use_mtls`.
  A renewal does not revoke the previous identity certificate: every unexpired generation is accepted. An
  identity certificate is valid for `--cert-validity` (default 1440 h = 60 days) from the issuance that
  produced it.
- **Two TEE keys per tunnel**: the identity key (mTLS) and the TLS key (the public WebPKI cert). Both
  are generated in the phone's hardware keystore; only CSRs leave the phone.
- **Enrollment is gated by Android hardware key attestation** (seven-point predicate, §2) PLUS a
  **key-binding** check: the enrolled identity key MUST equal the attested TEE key, and the CSR
  signatures are verified (proof-of-possession — the identity CSR at Phase 1, the TLS CSR at Phase 2).
  This closes the "attest a real key, enroll a software key" bypass.
- **The tunnel name is server-assigned and server-dictated.** The public WebPKI cert is issued for
  `<name>.<tunnel-domain>`, where `<name>` is the random name the server assigned at Phase-1 enrollment
  and wrote into the identity cert CN; at issuance the server reads the name from the mTLS client-cert CN
  and REQUIRES the TLS CSR to request exactly `<name>.<tunnel-domain>`.
- **Revocation is the ban engine ONLY** (no CRL): `ip` / `cidr` / `country` bans on the peer address, and
  `tunnel-name` bans. A banned name is refused when the phone connects (`/api/v1/control`, `/api/v1/issue`,
  the mTLS dial-back); on a ban reload the node holding its control connection closes it and the splices
  opened through it end on every node (§3). The public edge checks only the client's address, never the
  tunnel. Each node reloads its own ban files, so until every node has loaded a ban the phone can still
  connect to one that has not.

## 2. Enrollment (two-phase)

Enrollment is TWO phases. **Phase 1** (server-TLS `POST /api/v1/enroll` on `--enroll-host`, no client cert —
the phone has no identity yet) verifies attestation, assigns + claims the name, and signs a
**bootstrap identity cert** (CN = the assigned name). **Phase 2** (mTLS `POST /api/v1/issue` on `--control-host`)
generates the certificates: because the server assigned the name in Phase 1, the phone learns it BEFORE
building the TLS CSR, so the public cert is issued for the server-dictated `<name>.<tunnel-domain>` while
the TLS private key never leaves the phone. Phase 2 regenerates the identity cert and the public cert
**together** and is also the single path for every renewal. A name is claimed under a per-name **Valkey
lock**, then written to the registry over plain S3 (no conditional writes), so it runs on any S3 provider.

```mermaid
sequenceDiagram
    participant PhoneApp as Phone app
    participant EP as enroll endpoint
    participant IS as issue endpoint
    participant AT as Attestation verifier
    participant REG as Name registry
    participant ACME as ACME chain
    Note over PhoneApp,ACME: Phase 1 - name plus bootstrap identity (server-TLS)
    PhoneApp->>EP: GET nonce
    EP-->>PhoneApp: challenge nonce
    PhoneApp->>PhoneApp: generate TEE identity key K1
    PhoneApp->>EP: attestation chain for K1 plus identity CSR
    EP->>AT: verify seven point predicate
    AT-->>EP: pass plus attested leaf key
    EP->>EP: key binding plus identity CSR proof-of-possession
    EP->>REG: claim name (Valkey lock SET NX EX, then GET absent, PUT the record)
    REG-->>EP: name claimed
    EP->>EP: sign bootstrap identity cert for K1 (CN is the assigned name)
    EP-->>PhoneApp: assigned name plus identity cert plus issue nonce
    Note over PhoneApp,ACME: Phase 2 - certificate generation (mTLS, also every renewal)
    PhoneApp->>PhoneApp: generate TEE identity key K2 and TLS key T1
    PhoneApp->>IS: POST issue with fresh attestation over the nonce plus identity CSR plus TLS CSR
    IS->>AT: re-verify seven point predicate
    AT-->>IS: pass plus attested leaf key
    IS->>IS: key binding plus TLS CSR must request name dot tunnel-domain
    IS->>IS: issuance read-only cap on the name
    IS->>IS: sign identity cert for K2 (rotate)
    IS->>ACME: obtain WebPKI cert for T1 (LE then GTS then ZeroSSL)
    ACME-->>IS: public cert L1
    IS->>IS: record successful issuance
    IS-->>PhoneApp: identity cert plus public cert
```

At Phase 2 and at every renewal the server reads the name from the **mTLS client-cert CN**, so the name
is fixed at Phase 1 and stays stable across renewals (which rotate the identity key). Phase 1 records the
claim; Phase 2 is retryable and its name is never rolled back.

**Key type — ECDSA P-256 ONLY (both CSRs).** Enrollment accepts ECDSA P-256 keys only. The server
enforces this on the identity CSR (Phase 1 and Phase 2) AND on the Phase-2 **TLS CSR**: a non-P-256 TLS
key is refused (`unsupported_key_type`) before the public cert is ever obtained.

**Seven-point attestation predicate** (ALL mandatory): chain roots at a Google attestation root ∧
`attestationChallenge == nonce` ∧ signing digest ∈ the hot-reloadable allowlist ∧ `securityLevel ≥
TrustedEnvironment` (Software rejected; StrongBox not required) ∧ `verifiedBootState == Verified` ∧
`deviceLocked == true` ∧ not revoked (status list refreshed with last-known-good; refused if `> 24h`
stale). A KeyDescription that does not parse — including a malformed informational field such as the OS
version or a patch level — fails the chain (the phone gets `401` `unauthorized`; `attest-untrusted` is the
server's metric label). The root set is fetched from `--attest-root-url` (default
`https://android.googleapis.com/attestation/root`) and refreshed every `--attest-refresh` (default 1 h); no
root is pinned in the binary. Any status-list entry for a certificate of the chain counts as revoked,
whatever its status (`SUSPENDED` included). The signer allowlist file holds one hex SHA-256
signing-certificate digest per line (case-insensitive; `#` starts a comment, also after a digest; blank lines
are ignored; any even number of hex digits is accepted, the length is not otherwise checked); a line that is
not valid hex, an odd number of digits included, rejects the whole file (fatal at startup, the last good set
is kept at runtime); an empty file allows no signer.

**Name-claim invariant**: a candidate name is claimed only by the request that set its Valkey lock
(`lock:claim:{name}`, `SET NX EX`; a lock already taken draws a new name). The lock, the registry read and the claim PUT run under one
`--registry-claim-timeout` deadline that starts before the lock. The lock is never released and lives
`--registry-claim-settle`, which MUST strictly exceed that deadline, so a timed-out claim PUT has landed or died
before the name can be claimed again. Registry writes disable SDK
auto-retries (a retried claim PUT would be a self-inflicted zombie write).

**Phase-1 HTTP surface** (server-TLS on `--enroll-host`, JSON, all binary blobs hex/PEM as noted):

- `GET /api/v1/enroll/nonce` → `{"nonce": "<hex>"}` — 32 random bytes as hex, single-use, valid 5 minutes.
  The attestation challenge is the hex-DECODED bytes. The nonce route and `POST /api/v1/enroll` share the
  per-IP enroll windows (`--limit-enroll-minute`, default 2; `--limit-enroll-hour`, default 20): each nonce
  call, and each POST that passes parsing and the read-only rate pre-check, spends one slot, so an attempt
  (nonce + POST) spends two.
- `POST /api/v1/enroll` with `{"nonce": "<hex>", "attestation_chain": "<PEM bundle>", "identity_csr": "<PEM>"}`
  → `{"name": "<assigned>", "identity_cert": "<PEM>", "issue_nonce": "<hex>"}`. `issue_nonce` is the
  single-use nonce the phone echoes in its follow-up `POST /api/v1/issue`. Errors are
  `{"reason", "retryable", "retry_after_seconds"?}`; the status mapping (both enroll routes): `403`
  banned, `429` nonce-route rate limit, `401` unauthorized, `503` retryable (the body's `retryable`
  field is authoritative), `400` otherwise. Reasons: `bad_source_ip` 400 (not reachable through the edge);
  `banned` 403; `enroll_rate` 429 on the nonce route and 503 on POST (retryable, `retry_after_seconds` = time
  to the next window); `bad_request`, `bad_json`, `bad_nonce`, `bad_attestation_chain`, `bad_identity_csr`
  400; `invalid_nonce` 503 retryable; `unauthorized` 401; `name_unavailable` 503; `internal` 503;
  `unsupported_key_type` 400; `identity_sign_failed` 503 retryable. An unknown path or method on
  `--enroll-host` gets a plain-text `404`.
- **Retrying a failed enrollment**: the phone retries Phase 1 at most 3 times. A refusal with `retryable: true`
  waits its `retry_after_seconds`, at least 1 s; a network error or a timeout waits 2 s; `retryable: false` ends
  the attempts at once. A request that reaches the nonce check consumes the nonce, even if it fails later; one
  refused before it (ban, a body that does not parse, the rate limit) leaves it unused until it expires. Either
  way the next attempt first fetches a fresh one from `GET /api/v1/enroll/nonce`; a failed nonce fetch is a failed attempt like any other. A device that
  fails to generate the attested identity key (Android Keystore: a `ProviderException`, for example when the
  remote key provisioning service times out) also spends an attempt and waits 3 s, but nothing was sent and the
  nonce is still unused, so it generates the key again over the SAME nonce. After the third failed retry the
  phone gives up.

## 3. Phone control connection (HTTP/2 + mTLS)

The control stream is a `POST /api/v1/control` on an HTTP/2 connection to `--control-host` (mTLS, identity
client cert); over HTTP/1.x it is refused with `505` (an IP ban, a rejected certificate, a banned name or a
non-POST method is answered first, as below; every HTTP/1.x answer carries `Connection: close`). Its request
body is the phone→server frame stream (only `PONG`) and its response body the server→phone frame stream
(`OPEN`, `PING`, `RENEW_NUDGE`), both length-framed as below; the server flushes each frame and the stream
stays open for the connection's lifetime. `POST /api/v1/issue` (below) may use the same connection or another
one, over HTTP/2 or HTTP/1.1: the server authenticates every request by its client certificate.

`/api/v1/control` answers: `200` + the stream. `403` `forbidden` (a mesh-role or invalid-name certificate, or,
with `--dialback-mtls=false`, no certificate; with the default `--dialback-mtls=true` a missing, untrusted or
expired certificate fails the TLS handshake, with no HTTP answer) or `banned`, JSON. `405` non-POST, `505`
HTTP/1.x, `503` "too many pending" (more than `--limit-stream-pending`, default 64, handshakes waiting to bind)
and `503` "bind failed (retry)", plain text. `400` `bad_source_ip`, JSON (not reachable through the edge). A
new control connection for a name REPLACES the previous one, on any node and whatever identity-certificate
generation it presents: the old connection is closed at once on the same node, or at its next route heartbeat
(every `--route-ttl`/3, 10 s by default) on another node. There is no `409`.

**Liveness.** The server sends a `PING` every `--control-ping-interval` (at most 30 s). It sends the first
`PING` one interval after the stream opens and closes the connection when no `PONG` arrived for more than three
intervals, checked at each `PING`: 90–120 s after the phone went silent with the default 30 s (about 90 s for a
phone that never answers). Frames other than `PONG` are ignored and do not count as liveness; a frame whose
payload exceeds 1 MiB closes the connection. The phone MUST treat 90 s without ANY control frame as a dead connection: it closes the
control CONNECTION — the TCP/TLS connection, not only the stream — and reconnects on a new one. Without this
rule a half-open TCP connection (a NAT that dropped the mapping, a server that is gone) is never noticed,
because the phone writes only to answer a `PING`.

Public traffic never rides on this connection: each public connection gets its own **dial-back
connection** (§4).

Control-frame layout: `[type:1][payloadLen:4 BE][payload JSON]`. The type values are FROZEN:

| Frame | Type | Direction | Payload |
|---|---|---|---|
| `OPEN` | `0x01` | server→phone | `{token, addr, use_https, use_mtls}` — dial back to `addr` for one public connection (§4) |
| `PING` | `0x02` | server→phone | (none) — application liveness |
| `PONG` | `0x03` | phone→server | (none) — liveness answer |
| `RENEW_NUDGE` | `0x04` | server→phone | `{nonce, ari_window?}` — "renew now"; the phone answers by calling `POST /api/v1/issue` |

`ari_window` is optional and is NOT an ACME ARI window: it is the RFC 3339 renewal time the server computed
(now or already past); an admin reissue omits it; for a tunnel with no certificate yet it is a year-1
placeholder (`0001-01-01T00:00:00Z` + 160 h − `--acme-renew-margin`, `0001-01-05T16:00:00Z` by default). Clients
may ignore it. Each node's renewal watcher scans its own control connections hourly (the first scan 1 h after
start) and nudges a tunnel whose certificate is due: a Let's Encrypt certificate at NotAfter −
`--acme-renew-margin` (default 48 h), or at NotBefore + 160 h − margin while that node's Let's Encrypt client is
not built yet; a GTS or ZeroSSL certificate, or none, at NotBefore + 160 h − margin. With the default
shortlived profile (160 h certificates) every rule gives a renewal 112 h (≈4.7 days) after issuance.

The control stream carries only small frames. All certificate material (attestation chains, CSRs, issued
certs) — and every issuance/renewal ERROR — travels over the mTLS `POST /api/v1/issue` endpoint below, NEVER the
stream. The only phone→server frame is `PONG` (liveness); a stream tears down via HTTP/2 `END_STREAM`,
never a control frame.

When the control connection closes (for any reason), every splice opened through it ends, on every node
(§5 `evict`). A crashed owner node sends no `evict`: such splices end within 10 s after the route expires
(`--route-ttl`) or is re-bound, when the entry node's per-splice route check (every 10 s each splice re-reads
its tunnel's route) finds the route gone or bound to another connection. A ban eviction closes the control
connection with close reason `ban-evict`, which every node keeps for the splices it ends.

### `POST /api/v1/issue` (mTLS certificate-generation endpoint)

`/api/v1/issue` is the single cert-generation endpoint for BOTH the initial public cert (Phase 2) and every
renewal, authenticated by the phone's mTLS identity cert (name = its CN). Request/response are JSON:

- Request: `{nonce, attestation_chain, identity_csr, tls_csr}` — `nonce` is the Phase-1 `issue_nonce`
  (initial) or the `RENEW_NUDGE` nonce (renewal); `tls_csr` MUST request exactly `<name>.<tunnel-domain>`
  (byte-exact, lowercase): as its single DNS SAN or, with no SAN, as its CN; a non-empty CN must equal it; no
  IP / email / URI SAN; anything else is `400` `csr_domain_mismatch` (not retryable).
- Response: `{identity_cert, public_cert, ca}` — the regenerated identity + public certs; `ca` is the issuing
  CA's id (`letsencrypt`, `gts` or `zerossl`), not a certificate.
- **Latency**: the response arrives only after a live ACME order (validation + issuance, possibly spilling
  over to the next CA), so the phone MUST allow at least 400 s for it; the server gives up on the request
  after 390 s. A phone that gives up earlier can lose the issued certificate (the server discards an order
  whose requester is gone).
- Errors: `{"reason", "retryable", "retry_after_seconds"?}`; the status mapping: `403`
  banned/forbidden identity, `405` non-POST method, `401` unauthorized, `503` retryable (the body's
  `retryable` field is authoritative; `retry_after_seconds` carries the pacing hint when known, e.g.
  an ACME rate-limit cooldown), `400` otherwise. Reasons: `bad_source_ip` 400 (not reachable through the
  edge); `forbidden` (as for `/api/v1/control`), `banned` 403; `method_not_allowed` 405; `bad_request`,
  `bad_json`, `bad_nonce`, `bad_attestation`, `bad_identity_csr`, `bad_tls_csr` 400; `invalid_nonce` 503;
  `unauthorized` 401; `name_unknown` 400; `csr_domain_mismatch` 400; `unsupported_key_type` 400;
  `identity_sign_failed` 503; `issuance_cap` 503; `acme_rate_limited` 503; `acme_transient` 503
  (`retry_after_seconds` 60); `acme_failed` 400; `internal` 503.
- **Retrying a failed issuance**: the phone retries `POST /api/v1/issue` at most 3 times, and only the issuance — it
  NEVER re-enrolls (a new enrollment assigns a new name and orphans the old one). A network error, a timeout, or
  an error answer with `retryable: true` is retried; `retryable: false` ends the attempts at once. Retry n
  (1–3) waits the answer's `retry_after_seconds` when it carries one, otherwise 5 s, 10 s, 15 s. An attempt that
  reaches the nonce check consumes its nonce, even if it fails later, and one refused before it leaves it unused;
  the enroll and issue nonces share ONE namespace, so
  after the wait the phone fetches a fresh challenge from `GET /api/v1/enroll/nonce` (server-TLS, per-IP
  rate-limited) and repeats `POST /api/v1/issue` with a fresh attestation over it (so a new identity key, as for
  every issuance); a failed nonce fetch is a failed retry like any other. After the third failed retry the phone
  gives up. A device that fails to generate a new key (Android Keystore: a `ProviderException`) has sent nothing
  and its nonce is still unused, so it generates it again over the SAME nonce, at most 5 times and 2 s apart,
  without spending any of the 3 retries; a further key-generation failure ends the attempts. When
  every CA is out of issuance budget the server answers `503` `acme_rate_limited` with `retry_after_seconds` =
  the earliest free budget slot plus a random 1–10 s. While another issuance for the same name is still in
  progress (for example a request on a connection the phone has given up on), the answer is `503` `issuance_cap`
  with `retry_after_seconds` = 300; this 300 s is a fixed pacing hint (the other issuance may run up to 390 s).
  The weekly issuance cap allows `--issue-per-week` (default 3) SUCCESSFUL issuances per name in a fixed 7-day
  window that starts at the first success (failures never count); once it is reached the answer is `503`
  `issuance_cap` with `retry_after_seconds` = the time left in that window. A phone that is already BOUND on the control stream is
  also re-nudged: the renewal watcher sees a cert-less or renewal-due tunnel and sends a fresh
  `RENEW_NUDGE{nonce}` on its next scan.

**Renewal rotates the identity key**: on a `RENEW_NUDGE{nonce}` the phone calls `POST /api/v1/issue` with a
FRESH identity key attested over the nonce; the server re-runs the full seven-point predicate + key binding,
rotates the identity cert (CN = the mTLS CN), renews the public cert, and returns both in the response. The
identity key cannot be kept: Android attests a key only when it generates it, with the challenge fixed at that
moment, and every `/api/v1/issue` requires an attestation over a new nonce for the identity key it binds. The TLS
key is not attested and the server does not require a new one: the phone may keep its TLS key or generate a new
one. Renewal does not change the live control connection: it keeps the
certificate it was opened with; the new identity certificate is used from the next TLS handshake (a reconnect,
a dial-back), and the previous one stays valid until it expires. An identity certificate expires 60 days (by
default) after the issuance that produced it, so a phone that has not renewed successfully for that long —
being offline alone is not the cause — can no longer connect or renew: it must enroll again and gets a NEW
name; an old name is never reassigned. A control connection still open at that moment is closed by the server
at its next `PING` (close reason `cert-expired`).

## 4. Dial-back connection (opaque splice)

`OPEN` (`0x01`, server→phone) payload:

```json
{"token": "<26 chars, crypto/rand.Text, 128 bits>", "addr": "203.0.113.10:443", "use_https": true, "use_mtls": true}
```

`addr` is the `host:port` of the node where the public connection entered (`--dialback-advertise`). On
`OPEN` the phone opens a NEW connection to `addr` — TLS with SNI = `--control-host` and ALPN `http/1.1` when
`use_https`, presenting its identity client certificate when `use_mtls` (`use_mtls` without `use_https` is
invalid and ignored); plain TCP otherwise — and sends:

```http
GET /api/v1/data HTTP/1.1
Host: <control-host>
Connection: Upgrade
Upgrade: tunneld-dial
X-Dial-Token: <token>

```

The server checks the method (`GET`), exactly HTTP/1.1, the `X-Dial-Token`, and `Upgrade: tunneld-dial`
(case-insensitive); `Host` must be present and well-formed but its value is not checked, and `Connection` is
not checked. With `use_mtls` any unexpired identity-certificate generation is accepted.

Success: `HTTP/1.1 101 Switching Protocols` + `Connection: Upgrade` + `Upgrade: tunneld-dial`, then the
connection is a **raw, bidirectional, opaque byte splice** carrying the client↔phone TLS session — NO
framing; either side closing ends it. Failures (then the connection closes): `400` malformed (not exactly
HTTP/1.1, no token, no `Upgrade: tunneld-dial`), `403` banned source IP or identity certificate rejected
(mesh-role, invalid name, banned tunnel; with `use_mtls` a missing or untrusted client certificate already
fails the TLS handshake, with no HTTP response), `404`
unknown, expired or already-used token, or — with `use_mtls` — a token of another tunnel (without `use_mtls`
the token alone authorises the dial-back), `405` non-`GET`. The token is single-use
and valid only while the entry node waits (`--limit-dialback-timeout`). If the open fails — the `OPEN` could
not be delivered, or no dial-back arrived within `--limit-dialback-timeout` — the entry node takes ONE fresh
route lookup and, when the route changed, sends a second `OPEN` with the SAME token; if that also fails, or the
route did not change, it closes the client. A phone can therefore receive one token twice; a dial-back for a
token already used gets `404`. A `101` does not guarantee a splice: when the wait is already over (timed out,
another dial-back for the token won, or the node is shutting down), the connection is closed right after the
`101`. `wire.ChunkSize` (16384) is the bandwidth-pacing read-slice size the splice reads, NOT a wire frame.

Public connection limits: the entry node closes a public connection once it is older than both 60 s and
`--limit-conn-min-grace` (default 60 s) and carried fewer than `--limit-conn-min-rate` (default 2 KiB) bytes
over the last 60 s, both directions together; with the defaults an idle public connection therefore lasts
about 60 s, and `--limit-conn-idle` (default 120 s without any byte) only matters when set below that.

## 5. Replica mesh (control RPCs)

Replicas talk over an internal HTTP/2 mTLS mesh (mesh-role certs, SAN = node id) that carries control RPCs
only — no tunnel data ever crosses nodes. The mesh is replica↔replica only — it is NOT part of the
phone-client contract. Every call has a per-request deadline.

`POST /api/v1/mesh/control`: a JSON request → response `{applied}` (mesh-role mTLS). The ops:

- `renew`: `{"op":"renew","tunnel":"<name>"}` — mint a fresh renewal nonce and enqueue a `RENEW_NUDGE` to the
  named tunnel's live phone connection.
- `terminate`: `{"op":"terminate","tunnel":"<name>"}` — evict this node's in-flight public splices of the
  tunnel (`close_reason=admin-terminate`) and, on the owner, close its phone connection (the phone reconnects
  afterwards). The internal `POST /api/v1/admin/tunnels/{name}/terminate` endpoint sends it to EVERY node.
- `open`: `{"op":"open","tunnel":"<name>","conn_id":"<route connID>","open":{<OPEN payload>}}` →
  `{"applied":true}` when the receiver holds that live connection and queued the `OPEN`, else
  `{"applied":false}`. The entry node uses it when another node holds the phone's control connection.
- `evict`: `{"op":"evict","tunnel":"<name>","conn_id":"<closed connID>","reason":"<the control connection's
  close reason>"}` → `{"applied":<any splice ended>}`. A node whose phone control connection closes sends it
  to every node; each ends the splices opened through that connection, keeping `ban-evict` /
  `admin-terminate` when that is the reason, else `phone-close`.

`renew` is the mechanism behind the internal `POST /api/v1/admin/tunnels/{name}/reissue` endpoint (sent to
the owner). Unknown op → `400`, missing tunnel → `400`, `open`/`evict` without `conn_id` → `400`, `open`
without a payload carrying `token` + `addr` → `400`, non-POST → `405`, op failure → `502`; `403` a non-mesh-role
certificate; `404` any other path; `400` a body that is not valid JSON within its first 4096 bytes; error bodies
are plain text. `renew` answers `applied:false` when the node holds no live connection for the tunnel or its
send buffer is full; `terminate` answers `applied` = whether a live phone connection existed on that node.

## 6. Security invariants

- E2E: forward-secret TLS 1.3 between client and phone; tunneld holds no tunnel cert key, ever.
- No reverse proxy anywhere; tunneld is the raw `:443` edge; the trusted client IP is the TCP peer.
- Caps are UNIFORM (no per-path exceptions); rate limiting is global across replicas via Valkey.
- `ChunkSize == 16384` is the paced-copy slice size only; the dial-back carries no framing.
- The dial-back token is 128-bit random, single-use, valid only while the entry node waits; without
  `use_mtls` it is the only authorisation of a dial-back.
- No secrets, key material, or tunnel payloads are ever logged.
- A ClientHello whose first ALPN protocol is `acme-tls/1` is an ACME validation addressed to tunneld: it is answered locally with tunneld's challenge certificate and NEVER spliced to a phone.
- An IP-ban `403` on `/api/v1/enroll` or `/api/v1/control` comes only on a connection opened before the ban was
  loaded; a new connection from a banned address is closed by the edge before TLS.
