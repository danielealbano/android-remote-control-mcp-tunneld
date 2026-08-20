# tunnel-app

A complete **reference tunnel client** — a faithful Kotlin implementation of the phone side of
`docs/PROTOCOL.md` — for the adb-gated e2e test `TestE2E_ReferenceTunnelApp`
(`e2e/tunnel_app_test.go`). It is **not** the Android client (which lives with the app — see
`docs/PROJECT.md` Non-goals); it exists to exercise the real endpoints end to end from a real device:
real hardware-attested enrollment, a phone-terminated TLS server reached *through the tunnel*, and cert
renewal.

## What it does

The app is driven over adb (no launcher activity — an exported `CommandReceiver` forwards
`am broadcast` commands to a foreground `TunnelService`). On `enroll` it:

- generates two **non-exportable, TEE-backed EC P-256** AndroidKeyStore keys — an **identity** key
  hardware-attested over the server enroll nonce, and a **TLS** key for the local server;
- runs **two-phase attested enrollment** (`POST /enroll` → `POST /issue`) with PKCS#10 CSRs signed by
  those keys (BouncyCastle), presenting the identity key over client-mTLS on the `/issue` exchange;
- starts a local **Ktor (Netty engine) `sslConnector`** HTTPS server on a fixed loopback port,
  terminating TLS with the non-exportable TLS key + the Pebble-issued `<name>.<tunnel-domain>` cert, and
  serving `GET /info` (echoes the app nonce + the current cert digest) and `GET /wait` (a paced,
  hash-trailed stream for throughput checks);
- opens the **duplex HTTP/2 `/control`** connection (OkHttp), answering `PING`/`OPEN`/`RENEW_NUDGE`, and
  splices each `OPEN` to a fresh `POST /data` dial-back opaquely to the local server.

On `refresh` it forces a fresh `/issue` (rotating the identity + TLS keys and re-obtaining the public
cert) and hot-swaps the server cert. On `stop` it tears everything down. Status is reported via
app-internal files the test reads with `run-as` (the debug APK is debuggable): `info.json`
(`{name, tls_cert_sha256}`), a `ready` marker (the assigned name), or an `error` file on failure.

The test drives it with `am broadcast -a com.example.tunnelapp.<enroll|refresh|stop> -n
com.example.tunnelapp/.CommandReceiver` (with `-f 0x00000020` so the freshly-installed, stopped app's
receiver is reached), passing the edge port, the app nonce, the pushed Pebble-CA path, and the enroll/
control hosts + tunnel domain as string extras.

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
it is **never** wired into CI-with-device. The Gradle build outputs (`build/`, `.gradle/`) and the
machine-specific `local.properties` are gitignored; only the three fixtures above are committed.
