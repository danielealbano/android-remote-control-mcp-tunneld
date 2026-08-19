# attest-probe

A minimal on-device **attestation test probe** for the adb-gated e2e test
`TestE2E_DeviceAttestation` (`e2e/device_attestation_test.go`). It is **not** the Android client (which
lives with the app — see `docs/PROJECT.md` Non-goals); it exists only to produce a *real* hardware
attestation chain the production `internal/attest` verifier can check end to end.

## What it does

A single `MainActivity`, launched over adb with a server nonce, generates an **EC P-256** key
(`SIGN`, `SHA-256`, TEE-backed, not auth-bound) with `setAttestationChallenge(<nonce>)`, reads back
`getCertificateChain()`, and writes the leaf-first PEM to `getFilesDir()/chain.pem` followed by a
`done` marker (or an `error` file with the message on failure). `setShowWhenLocked`/`setTurnScreenOn`
let it run headless over the keyguard. The test reads the result via `run-as` (the debug APK is
debuggable), verifies the chain against the live Google attestation roots/status + the committed
signer allowlist, and asserts a P-256 leaf key.

## Building and publishing the fixtures

```
make attest-probe
```

This assembles the **debug**-signed APK with the **local** Android SDK — Gradle finds the SDK via
`support/attest-probe/local.properties` (gitignored; `sdk.dir=…`) or `ANDROID_HOME` — and needs the
build-tools `apksigner`. It then publishes three committed fixtures under `fixtures/attest-probe/`:

- `attest-probe.apk` — the debug-signed probe app the test installs.
- `attest-probe.apk.sha256` — its SHA-256; the test refuses to install an APK that does not match.
- `signers.allow` — the debug signing-cert SHA-256 (one lowercase-hex line), the verifier's allowlist.

The digest in `signers.allow` is tied to whichever debug keystore signed the APK, so a rebuild on a
different machine's debug key must re-run `make attest-probe` to refresh the allowlist.

## Scope

`TestE2E_DeviceAttestation` is a **local-only developer gate**: it SKIPS (never fails) when no single
adb device is connected, and it is **never** wired into CI-with-device. The Gradle build outputs
(`build/`, `.gradle/`) and the machine-specific `local.properties` are gitignored; only the three
fixtures above are committed.

Placeholder namespace `com.example.attestprobe` only.
