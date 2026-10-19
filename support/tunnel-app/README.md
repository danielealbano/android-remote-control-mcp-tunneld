# tunnel-app

A complete **reference tunnel client** — a faithful Kotlin implementation of the phone side of
`docs/PROTOCOL.md` — for the adb-gated e2e test `TestE2E_ReferenceTunnelApp`
(`e2e/tunnel_app_test.go`). It is **not** the Android client (which lives with the app — see
`docs/PROJECT.md` Non-goals); it exists to exercise the real endpoints end to end from a real device:
real hardware-attested enrollment, a phone-terminated TLS server reached *through the tunnel*, and cert
renewal.

## What it does

The app is one full-screen activity driven over adb with `am start` commands. It keeps the screen on while
the tunnel runs (shown over the lock screen) and shows live figures: the tunnel (name, node, reconnects),
traffic (requests, connections, errors, in and out in Mbit/s averaged over the last minute), the certificate (CA, expiry, renewals, enrollment and issuance failures) and
device health. It has no foreground service (Android 15+ lets a `dataSync` one run only 6 h a day), so it
runs only while it is on screen.

It runs against the e2e setup or a real deployment. With the `edgePort` and `caPath` extras it dials
`127.0.0.1:<edgePort>` (an `adb reverse`) with the enroll/control hosts as TLS names and trusts the CA file at
`caPath`; without them it resolves the hosts with the system DNS, connects on port 443 and trusts the
system CAs.

The identity is saved per environment (enroll host, control host and tunnel domain): `enroll` resumes a saved
identity under the same name and only asks for a certificate if it has none yet, never enrolling again; with no
saved identity it enrolls, saves the identity at once, and saves it again after every issuance and renewal,
including the previous generation's key aliases so they are still deleted one generation late after a restart.
On `enroll` it:

- generates two **non-exportable, TEE-backed EC P-256** AndroidKeyStore keys — an **identity** key
  hardware-attested over the server enroll nonce, and a **TLS** key for the local server;
- runs **two-phase attested enrollment** (`POST /enroll` → `POST /issue`) with PKCS#10 CSRs signed by
  those keys (BouncyCastle), presenting the identity key over client-mTLS on the `/issue` exchange, and
  retries both phases as `docs/PROTOCOL.md` §2 prescribes;
- starts a local **Ktor (Netty engine) `sslConnector`** HTTPS server on a fixed loopback port,
  terminating TLS with the non-exportable TLS key + the issued `<name>.<tunnel-domain>` cert, and
  serving `GET /info` (echoes the app nonce + the current cert digest) and `GET /wait` (a paced,
  hash-trailed stream for throughput checks);
- opens the **duplex HTTP/2 `/control`** connection (OkHttp), answering `PING`/`OPEN`/`RENEW_NUDGE`, and
  answers each `OPEN` with a dial-back: a new connection to the `OPEN`'s `addr` (TLS when `use_https`,
  presenting the identity cert when `use_mtls`, plain TCP otherwise) carrying a `GET /api/v1/data` upgrade
  with the `OPEN`'s token, then splices it opaquely to the local server.

On `refresh` it forces a fresh `/issue` (rotating the identity + TLS keys and re-obtaining the public
cert) and hot-swaps the server cert. On `stop` it tears everything down. On `forget` (only while stopped) it
deletes the environment's saved identity and every key of that environment and writes a `forgotten` marker.
Status is reported via
app-internal files the test reads with `run-as` (the debug APK is debuggable): `info.json`
(`{name, tls_cert_sha256}`), a `ready` marker (the assigned name), or an `error` file on failure.

The tests drive it with `am start -n com.example.tunnelapp/.MainActivity -e command <enroll|refresh|stop|forget>`,
passing the edge port, the app nonce, the pushed Pebble-CA path (`caPath`), and the enroll/control hosts +
tunnel domain as string extras; `forget` takes only the hosts and the tunnel domain. Each test forgets the
saved identity before it enrolls, and `TestE2E_ReferenceTunnelAppResumesAfterRestart` checks that a
restarted app resumes its identity without a new enrollment.

## Building and publishing the fixtures

```
make tunnel-app
```

This assembles the **debug**-signed APK with the **local** Android SDK — Gradle finds the SDK via
`support/tunnel-app/local.properties` (gitignored; `sdk.dir=…`) or `ANDROID_HOME` — and needs the
build-tools `apksigner`. It then publishes three committed fixtures under `fixtures/tunnel-app/`:

- `tunnel-app.apk` — the debug-signed app the test installs.
- `tunnel-app.apk.sha256` — its SHA-256; the test refuses to install an APK that does not match.
- `signers.allow` — the debug signing-cert SHA-256 (one lowercase-hex line), the attestation-gate
  allowlist for the app's signer.

The digest in `signers.allow` is tied to whichever debug keystore signed the APK, so a rebuild on a
different machine's debug key must re-run `make tunnel-app` to refresh the allowlist.

## Scope

`TestE2E_ReferenceTunnelApp` is a **local-only developer gate**: it needs a connected phone and live
Google attestation reachability, so it SKIPS (never fails) when no single adb device is connected, and
it is **never** wired into CI-with-device. The Gradle build outputs (`build/`, `.gradle/`, `.kotlin/`) and the
machine-specific `local.properties` are gitignored; only the three fixtures above are committed.
