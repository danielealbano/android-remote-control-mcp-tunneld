# tunneld Wire Protocol (v2 — End-to-End Encrypted)

This is the CANONICAL wire contract for the E2E-encrypted tunnel. The Go client in `client/` and the
Android (Kotlin) client both conform to THIS document, not to the Go source. `internal/wire` holds the
frame codec.

tunneld relays **opaque TLS bytes** and can NEVER read tunnel traffic: external clients establish TLS
directly with the phone, which holds a publicly-trusted (WebPKI) certificate for its assigned hostname.
tunneld is the internet edge (raw TCP `:443`), peeks the ClientHello (SNI/ALPN/version/JA4), routes on
SNI, and splices the encrypted byte stream to the phone over an internal HTTP/2 mesh.

## 1. Identity & authentication

- **No TLS mutual auth on the public side.** The phone authenticates to tunneld with an internal-CA
  **identity client certificate** over its outbound HTTP/2 **control connection** (mTLS). The assigned
  tunnel name is the certificate's **CN**; the server DERIVES the name from the CN (the phone dials the
  single shared `--control-host`, so there is no per-tunnel Host on the control connection).
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
- **Revocation is the ban engine ONLY** (no CRL): tunnel-name / identity-fingerprint bans are enforced
  at the phone control connection, at the public SNI edge on the resolved route, and by live eviction
  on ban reload.

## 2. Enrollment (two-phase)

Enrollment is TWO phases. **Phase 1** (server-TLS `POST /enroll` on `--enroll-host`, no client cert —
the phone has no identity yet) verifies attestation, assigns + write-verify-claims the name, and signs a
**bootstrap identity cert** (CN = the assigned name). **Phase 2** (mTLS `POST /issue` on `--control-host`)
generates the certificates: because the server assigned the name in Phase 1, the phone learns it BEFORE
building the TLS CSR, so the public cert is issued for the server-dictated `<name>.<tunnel-domain>` while
the TLS private key never leaves the phone. Phase 2 regenerates the identity cert and the public cert
**together** and is also the single path for every renewal. The name registry uses a **write-verify
claim** over plain S3 (no conditional writes), so it runs on any S3 provider.

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
    EP->>REG: claim name (GET absent, PUT with nonce, settle wait, GET verify nonce)
    REG-->>EP: claim verified
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

**Seven-point attestation predicate** (ALL mandatory): chain roots at a Google attestation root ∧
`attestationChallenge == nonce` ∧ signing digest ∈ the hot-reloadable allowlist ∧ `securityLevel ≥
TrustedEnvironment` (Software rejected; StrongBox not required) ∧ `verifiedBootState == Verified` ∧
`deviceLocked == true` ∧ not revoked (status list refreshed with last-known-good; refused if `> 24h`
stale).

**Write-verify claim invariant**: the settle wait MUST strictly exceed the claim-PUT timeout, and
registry writes disable SDK auto-retries (a retried claim PUT would be a self-inflicted zombie write).

## 3. Phone control connection (HTTP/2 + mTLS)

The phone opens ONE outbound HTTP/2 connection to `--control-host`. It carries:

- a long-lived **control stream** with length-framed control messages (below), and
- one **data stream per public connection**, opened by the phone via **dial-back** (the server announces
  an incoming connection on the control stream; the phone opens the data stream — HTTP/2 streams are
  always client-initiated).

Control-frame layout: `[type:1][payloadLen:4 BE][payload JSON]`.

| Frame | Direction | Payload |
|---|---|---|
| `OPEN` | server→phone | `{stream_id}` — dial back for one public connection |
| `CLOSE` | either | `{stream_id, reason}` |
| `PING` / `PONG` | either | (none) — application liveness |
| `RENEW_NUDGE` | server→phone | `{nonce, ari_window}` — "renew now"; the phone answers by calling `POST /issue` |
| `ERROR` | server→phone | `{reason, retryable, retry_after_seconds}` |

The control stream carries only small frames. All certificate material (attestation chains, CSRs, issued
certs) travels over the mTLS `POST /issue` endpoint below — NEVER the stream. The only phone→server frame
is `PONG` (liveness).

### `POST /issue` (mTLS certificate-generation endpoint)

`/issue` is the single cert-generation endpoint for BOTH the initial public cert (Phase 2) and every
renewal, authenticated by the phone's mTLS identity cert (name = its CN). Request/response are JSON:

- Request: `{nonce, attestation_chain, identity_csr, tls_csr}` — `nonce` is the Phase-1 `issue_nonce`
  (initial) or the `RENEW_NUDGE` nonce (renewal); `tls_csr` MUST request `<name>.<tunnel-domain>`.
- Response: `{identity_cert, public_cert, ca}` — the regenerated identity + public certs.

**Renewal rotates the identity key**: on a `RENEW_NUDGE{nonce}` the phone calls `POST /issue` with a
FRESH identity key + fresh TLS key + fresh attestation over the nonce; the server re-runs the full
seven-point predicate + key binding, rotates the identity cert (CN = the mTLS CN), renews the public cert,
and returns both in the response. The connection stays up on the old certs until the response installs
the new ones.

## 4. Data stream (opaque splice)

Once the phone opens the data stream in response to `OPEN{stream_id}` (matched by `stream_id`), it is a
**raw, bidirectional, opaque byte splice** carrying the client↔phone TLS session. It has NO framing —
HTTP/2 provides the framing and `END_STREAM` is the teardown signal. `wire.ChunkSize` (32768) is the
bandwidth-pacing slice size the bridge reads, NOT a wire frame.

## 5. Replica mesh

When the accepting edge node is not the node holding the phone, it bridges to the owner over an internal
HTTP/2 mTLS mesh (mesh-role certs, SAN = node id). The mesh data stream is prefixed with ONE
`StreamOpen` header: `[len:4 BE][ {tunnel, conn_id, stream_id} JSON ]`. The owner verifies `conn_id`
against its live phone connection before bridging (one fresh route lookup + retry on mismatch, then
close). Everything after the header is the opaque splice.

## 6. Security invariants

- E2E: forward-secret TLS 1.3 between client and phone; tunneld holds no tunnel cert key, ever.
- No reverse proxy anywhere; tunneld is the raw `:443` edge; the trusted client IP is the TCP peer.
- Caps are UNIFORM (no per-path exceptions); rate limiting is global across replicas via Valkey.
- `ChunkSize == 32768`; both peers set the HTTP/2 read limits accordingly.
- No secrets, key material, or tunnel payloads are ever logged.
