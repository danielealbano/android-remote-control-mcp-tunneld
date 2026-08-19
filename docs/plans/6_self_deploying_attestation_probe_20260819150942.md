<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 6 — Self-Deploying Device-Attestation Probe

Replace the operator-supplied external probe of the adb-gated `TestE2E_DeviceAttestation` with a
committed, in-repo Android app that the test deploys, drives over adb, and removes. The test verifies
the resulting **real** hardware-attested chain with the **production** `attest.Verifier`.

## Context & key decisions (the decision record — not derivable from code)

- **Why:** today `e2e/device_attestation_test.go` skips unless the operator hand-provides
  `TUNNELD_ATTEST_PROBE` (a host executable) + `TUNNELD_ATTEST_SIGNER_FILE`. No probe exists anywhere in
  the repo. This plan commits a minimal probe app + its signed APK + signer allowlist so a connected
  device is the *only* prerequisite.
- **Probe form:** a **real launched Activity** (not instrumentation — instrumentation bypasses app
  layers). Triggered by `adb shell am start -n <pkg>/.MainActivity -e nonce <hex>`. It does the keystore
  work in `onCreate`, writes result files, and `finish()`es. `setShowWhenLocked(true)` +
  `setTurnScreenOn(true)` (both Android API 27; minSdk 31) make it run headless over the keyguard; the
  key is **not** auth-bound, so no unlock/PIN is needed.
- **Key params (must satisfy `internal/attest/verify.go`):** EC **P-256** (`secp256r1`), purpose
  `SIGN`, digest `SHA-256`, `setAttestationChallenge(<nonce bytes>)`, **TEE-backed** (StrongBox is
  explicitly NOT required — `verify.go` accepts `securityLevel ≥ TrustedEnvironment`). The verifier's
  boot-state / device-locked points are satisfied by a locked-bootloader, verified-boot device.
- **Signing:** the Android **debug keystore**. The verifier's point (3) checks that a signing-cert
  **SHA-256** digest (embedded by Android in `attestationApplicationId`) is in the allowlist; that digest
  equals `apksigner verify --print-certs`'s "certificate SHA-256 digest". A `make` target extracts it
  into the committed allowlist. The allowlist file format (`internal/attest/signers.go`): one
  lowercase-hex SHA-256 per line, `#` comments.
- **File transport:** the app writes to app-internal `getFilesDir()`; the test reads via
  `adb exec-out run-as <pkg> cat files/<f>` (works because a debug APK is debuggable). Success is a
  `done` marker written **strictly after** `chain.pem`; failure is an `error` file (message) and no
  `done`.
- **Build once, freeze:** artifacts (APK, its SHA-256, allowlist) are committed and regenerated only by
  `make attest-probe`; the test needs only `adb`, never the SDK. The target is NOT a default quality
  gate.
- **Toolchain / no downloads:** the build uses the **local** Android SDK already installed on the dev
  machine (Gradle finds it via `ANDROID_HOME`/`ANDROID_SDK_ROOT` or a gitignored `local.properties`).
  The AGP / Kotlin / `compileSdk` / build-tools versions and the exact Gradle files are **pinned during
  implementation to versions already present locally** to avoid any Android-SDK download; the chosen
  versions and any Gradle-syntax reconciliation MUST be logged in `## Deviations`.
- **Scope:** the gate stays **local-only** — it skips (never fails) when no single adb device is
  present, and is **never** wired to CI-with-device. It still hits the live Google attestation
  root/status endpoints (a genuine end-to-end check), exactly as today.

---

## User Story 1 — [x] Attestation probe app (Kotlin/Gradle sources)

A committed, buildable Android app that mints a real hardware-attested P-256 key bound to a server
nonce and writes the chain where the e2e test can read it.

**Acceptance criteria:**
- [x] `support/attest-probe/` is a self-contained Gradle **Kotlin** Android project (`minSdk 31`) that
  builds a debug APK with `./gradlew assembleDebug`, using only the local SDK (no new downloads).
- [x] Launched via `am start … -e nonce <hex>`, the app generates an EC P-256 / SIGN / SHA-256 /
  TEE-backed / non-auth-bound key with `setAttestationChallenge(<nonce bytes>)`, reads
  `getCertificateChain()`, writes leaf-first PEM to `getFilesDir()/chain.pem`, then an empty
  `getFilesDir()/done`; on ANY failure it writes `getFilesDir()/error` (the message) and NO `done`.
- [x] The Activity runs headless (`setShowWhenLocked(true)` + `setTurnScreenOn(true)`) and `finish()`es.
- [x] No unit/instrumentation tests and no dependencies beyond the framework (no AndroidX).

### Task 1.1 — [x] Gradle project scaffolding

**Actions:**
- [x] Create `support/attest-probe/settings.gradle.kts` (modify/create):
  ```kotlin
  pluginManagement {
      repositories { google(); mavenCentral(); gradlePluginPortal() }
  }
  dependencyResolutionManagement {
      repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
      repositories { google(); mavenCentral() }
  }
  rootProject.name = "attest-probe"
  include(":app")
  ```
- [x] Create `support/attest-probe/build.gradle.kts` (root):
  ```kotlin
  plugins {
      id("com.android.application") version "<AGP_VERSION_LOCAL>" apply false
      id("org.jetbrains.kotlin.android") version "<KOTLIN_VERSION_LOCAL>" apply false
  }
  ```
- [x] Create `support/attest-probe/gradle.properties`:
  ```properties
  org.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8
  android.useAndroidX=false
  kotlin.code.style=official
  ```
- [x] Create `support/attest-probe/app/build.gradle.kts`:
  ```kotlin
  plugins {
      id("com.android.application")
      id("org.jetbrains.kotlin.android")
  }
  android {
      namespace = "com.example.attestprobe"
      compileSdk = <COMPILE_SDK_LOCAL>
      defaultConfig {
          applicationId = "com.example.attestprobe"
          minSdk = 31
          targetSdk = <TARGET_SDK_LOCAL>
          versionCode = 1
          versionName = "1.0"
      }
      buildTypes { getByName("debug") { isDebuggable = true } }
      compileOptions {
          sourceCompatibility = JavaVersion.VERSION_17
          targetCompatibility = JavaVersion.VERSION_17
      }
      kotlinOptions { jvmTarget = "17" }
  }
  ```
  - Constraint: `<AGP_VERSION_LOCAL>`, `<KOTLIN_VERSION_LOCAL>`, `<COMPILE_SDK_LOCAL>`,
    `<TARGET_SDK_LOCAL>` MUST be pinned to versions already present in the local Android SDK / Gradle
    cache (no downloads). `sourceCompatibility`/`jvmTarget` MUST match the locally installed JDK if 17
    is unavailable. Record the chosen values in `## Deviations`.
- [x] Generate the Gradle wrapper (`gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`,
  `gradle/wrapper/gradle-wrapper.properties`) with the local `gradle wrapper` at a locally-available
  Gradle version; these wrapper files ARE committed.

**Definition of Done:**
- [x] `cd support/attest-probe && ./gradlew tasks` resolves the plugins from local caches with no SDK
  download.

### Task 1.2 — [x] Manifest

**Actions:**
- [x] Create `support/attest-probe/app/src/main/AndroidManifest.xml` (modify/create):
  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:label="attest-probe" android:allowBackup="false">
          <activity android:name=".MainActivity" android:exported="true" />
      </application>
  </manifest>
  ```
  - Note: no `<uses-permission>` (keystore attestation needs none); no launcher intent-filter — the app
    is started explicitly by component name over adb.

**Definition of Done:**
- [x] Manifest declares exactly one exported Activity and requests no permissions.

### Task 1.3 — [x] MainActivity (keystore attestation + file output)

**Actions:**
- [x] Create `support/attest-probe/app/src/main/java/com/example/attestprobe/MainActivity.kt`
  (modify/create):
  ```kotlin
  package com.example.attestprobe

  import android.app.Activity
  import android.os.Bundle
  import android.security.keystore.KeyGenParameterSpec
  import android.security.keystore.KeyProperties
  import android.util.Base64
  import java.io.File
  import java.security.KeyPairGenerator
  import java.security.KeyStore
  import java.security.spec.ECGenParameterSpec

  // A real, launched app (NOT instrumentation) that mints a hardware-attested P-256 key bound to the
  // server nonce and writes the attestation chain for the e2e gate to read. setShowWhenLocked /
  // setTurnScreenOn (API 27) let onCreate run headless over the keyguard; the key is not auth-bound.
  class MainActivity : Activity() {
      override fun onCreate(savedInstanceState: Bundle?) {
          super.onCreate(savedInstanceState)
          setShowWhenLocked(true)
          setTurnScreenOn(true)
          val dir = filesDir
          try {
              val nonceHex = intent.getStringExtra("nonce")
                  ?: error("missing '-e nonce <hex>' extra")
              val nonce = hexToBytes(nonceHex)
              val alias = "attest-probe"
              val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                  .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                  .setDigests(KeyProperties.DIGEST_SHA256)
                  .setAttestationChallenge(nonce)
                  .build()
              val kpg = KeyPairGenerator.getInstance(
                  KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
              kpg.initialize(spec)
              kpg.generateKeyPair()
              val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
              val chain = ks.getCertificateChain(alias)
                  ?: error("no attestation chain (hardware attestation unsupported?)")
              val pem = buildString {
                  for (c in chain) {
                      append("-----BEGIN CERTIFICATE-----\n")
                      append(Base64.encodeToString(c.encoded, Base64.NO_WRAP).chunked(64)
                          .joinToString("\n"))
                      append("\n-----END CERTIFICATE-----\n")
                  }
              }
              File(dir, "chain.pem").writeBytes(pem.toByteArray())
              File(dir, "done").writeBytes(ByteArray(0)) // marker LAST — chain.pem is complete
          } catch (t: Throwable) {
              File(dir, "error").writeText(t.toString())
          } finally {
              finish()
          }
      }

      private fun hexToBytes(s: String): ByteArray {
          require(s.length % 2 == 0 && s.isNotEmpty()) { "bad nonce hex" }
          return ByteArray(s.length / 2) {
              ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
          }
      }
  }
  ```
  - `KeyStore.getCertificateChain` returns the chain ordered leaf-first (the private-key cert out to the
    root) — matches `attest.Verify`'s `chain[0]==leaf` contract and the test's `parsePEMChain` order.

**Definition of Done:**
- [x] The app compiles; a manual run on the connected device produces a `done` marker and a leaf-first
  `chain.pem` whose leaf is an EC P-256 cert bound to the supplied nonce (verified via US3's gate).

---

## User Story 2 — [x] Build, sign, and commit the probe artifacts

One command regenerates the committed, integrity-checked debug-signed APK and its signer allowlist, so
the e2e test needs only `adb`.

**Acceptance criteria:**
- [x] `make attest-probe` builds the debug APK, copies it to `fixtures/attest-probe/attest-probe.apk`,
  writes `fixtures/attest-probe/attest-probe.apk.sha256`, and extracts the debug signing-cert SHA-256
  into `fixtures/attest-probe/signers.allow` (one lowercase-hex line + `#` header).
- [x] The three artifacts are committed; Gradle build outputs and `local.properties` are gitignored.
- [x] `make attest-probe` is NOT part of the default quality gates and is documented as needing the
  local Android SDK build-tools (`apksigner`) on PATH.

### Task 2.1 — [x] Makefile target

**Actions:**
- [x] Modify `Makefile`: add `attest-probe` to the `.PHONY` list, and add:
  ```make
  # Builds, signs (debug keystore), and publishes the on-device attestation probe used by the adb-gated
  # e2e test (see support/attest-probe/README.md). Requires the LOCAL Android SDK build-tools (apksigner)
  # + a Gradle-resolvable SDK; NOT a default quality gate. Regenerates the committed fixtures.
  APKSIGNER ?= apksigner
  attest-probe:
  	cd support/attest-probe && ./gradlew assembleDebug
  	mkdir -p fixtures/attest-probe
  	cp support/attest-probe/app/build/outputs/apk/debug/app-debug.apk \
  	    fixtures/attest-probe/attest-probe.apk
  	sha256sum fixtures/attest-probe/attest-probe.apk | awk '{print $$1}' \
  	    > fixtures/attest-probe/attest-probe.apk.sha256
  	{ echo "# Debug signing-cert SHA-256 for the attest-probe APK (regenerate via 'make attest-probe')."; \
  	  $(APKSIGNER) verify --print-certs fixtures/attest-probe/attest-probe.apk \
  	    | awk -F': ' '/certificate SHA-256 digest/ {print tolower($$2); exit}'; \
  	} > fixtures/attest-probe/signers.allow
  ```
  - Constraint: the exact APK output path (`app/build/outputs/apk/debug/app-debug.apk`) MUST be
    reconciled with what the pinned AGP actually emits; record any change in `## Deviations`.
- [x] Modify `Makefile`: update the now-stale `test-e2e` comment (currently "…the e2e tier also has an
  adb-gated real-attestation test that SKIPS unless a device + an operator probe are present (never
  wired to CI-with-device)") so it states that the attestation test now **self-deploys the committed
  probe APK** (`support/attest-probe/`, built via `make attest-probe`) and skips only when no single adb
  `device` is present — no operator probe.

**Definition of Done:**
- [x] `make attest-probe` runs end to end on the dev machine and (re)writes all three fixture files.
- [x] The `Makefile` `test-e2e` comment no longer references an operator probe.

### Task 2.2 — [x] Commit fixtures + gitignore build outputs

**Actions:**
- [x] Run `make attest-probe` to generate `fixtures/attest-probe/attest-probe.apk`,
  `…/attest-probe.apk.sha256`, `…/signers.allow`; commit all three (the APK is a binary test fixture).
- [x] Modify `.gitignore`: append (build outputs + machine-specific SDK pointer; the APK fixture is NOT
  ignored):
  ```gitignore
  /support/attest-probe/.gradle/
  /support/attest-probe/build/
  /support/attest-probe/app/build/
  /support/attest-probe/local.properties
  /support/attest-probe/.idea/
  ```

**Definition of Done:**
- [x] `git status` shows the three fixtures tracked and no Gradle build output staged;
  `git check-ignore support/attest-probe/build support/attest-probe/local.properties` matches both.

---

## User Story 3 — [x] Self-deploying e2e attestation gate

`TestE2E_DeviceAttestation` deploys the committed APK, drives it over adb, and verifies the chain with
the production verifier — no operator-supplied prerequisites.

**Acceptance criteria:**
- [x] The test no longer reads `TUNNELD_ATTEST_PROBE` / `TUNNELD_ATTEST_SIGNER_FILE`.
- [x] It verifies the committed APK matches `fixtures/attest-probe/attest-probe.apk.sha256` before
  installing, and fails (not skips) on mismatch.
- [x] It wakes the screen, `adb install -r`s the APK, `am start`s `.MainActivity` with a fresh 32-byte
  nonce, polls `done`/`error` via `run-as` within a bounded timeout, reads `chain.pem`, verifies with
  the production `attest.Verifier` (live Google root + status URLs + the committed
  `signers.allow`), asserts an ECDSA **P-256** leaf key, and `adb uninstall`s in `t.Cleanup`.
- [x] It skips (never fails) when there is not exactly one adb device in `device` state; it is never run
  in CI-with-device.

### Task 3.1 — [x] Rewrite `e2e/device_attestation_test.go`

**Actions:**
- [x] Modify `e2e/device_attestation_test.go` (keep `//go:build e2e`, `package e2e`): remove the two
  env-var gates and the host-executable probe invocation; keep `parsePEMChain`; replace `adbHasDevice`
  with a serial-returning form; add the adb-driver helpers and the install→drive→verify→uninstall flow.
  Test-helper contracts (bodies are test code — not reproduced here per plan rules):
  - `attestDeviceSerial(t) (serial string, ok bool)` — parses `adb devices`; returns the single
    `device`-state serial, or `ok=false` (test then `t.Skip`s). Replaces `adbHasDevice`.
  - `adb(t, serial string, args ...string) []byte` (`t.Helper()`) — runs `adb -s <serial> <args…>`
    under a per-call `context.WithTimeout`; `t.Fatalf` with combined output on error.
  - `runAsCat(t, serial, pkg, rel string) ([]byte, bool)` — `adb -s <serial> exec-out run-as <pkg> cat
    files/<rel>`; returns `(data, true)` when the file exists, `(nil, false)` when absent (distinguish
    the "No such file" case from real errors; `t.Fatalf` on a real adb failure).
  - `pollProbeResult(t, serial, pkg string, timeout time.Duration) []byte` — polls every 500ms until
    `done` (returns `chain.pem` bytes) or `error` (`t.Fatalf` with the message) appears, or the timeout
    elapses (`t.Fatalf`).
  - `apkSHA256(t, path) string` — hex SHA-256 of the committed APK file, compared to the trimmed
    contents of `…/attest-probe.apk.sha256`.
  - Fixture paths are relative to `e2e/`: `filepath.Join("..", "fixtures", "attest-probe", …)`.
  - Package/component: `pkg = "com.example.attestprobe"`, launched as `pkg/.MainActivity`.
  - Wake before launch: `adb -s <serial> shell input keyevent KEYCODE_WAKEUP`.
  - Verifier wiring is UNCHANGED from today: `attest.NewRootSet`/`NewStatusList` against
    `googleAttestRootURL`/`googleAttestStatusURL`, `attest.LoadSignerAllowlist(signersAllowPath, nil)`,
    `attest.NewVerifier(roots, status, signers, 24*time.Hour)`, `verifier.Verify(chain, nonce, time.Now())`.
  - Leaf assertion: `res.LeafPublicKey.(*ecdsa.PublicKey)` with `Curve == elliptic.P256()`.

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestE2E_DeviceAttestation` | A **real** hardware-attested P-256 chain from the committed probe APK, bound to a fresh server nonce, passes the production seven-point verifier; the attested leaf key is ECDSA P-256. | `t.Skip` unless exactly one adb `device`. Assert committed APK SHA-256 == committed `.sha256`. `input keyevent KEYCODE_WAKEUP`; `install -r`; `am start -n pkg/.MainActivity -e nonce <hex>`; `pollProbeResult` (bounded, e.g. 60s); `parsePEMChain`; production verifier against live Google URLs + committed `signers.allow`; assert P-256 leaf. `t.Cleanup`: `adb uninstall pkg`. Local-only; never CI-with-device. |

**Definition of Done:**
- [x] With the device connected the test PASSES (real attestation verifies); with no device it SKIPS;
  a tampered/stale committed APK (sha256 mismatch) FAILS with a clear message.

---

## User Story 4 — [x] Fix attestation root-set parsing (found during US3 verification)

US3's real-device gate is the FIRST test to fetch the LIVE Google attestation root endpoint, which
publishes a **bare JSON array of PEM strings**. `attest.NewRootSet` parsed only `{"roots":[…]}` or a raw
concatenated PEM bundle, so with the default `--attest-root-url` the server could not load the attestation
root at all (fail-closed → no attestation ever verifies). Parse ONLY the real format.

**Acceptance criteria:**
- [x] `NewRootSet.fetch` parses a top-level JSON array of PEM certificate strings and nothing else (the
  `{"roots":[…]}` and raw-PEM branches, and the `rootResponse` struct, are removed).
- [x] A non-array body or an empty array is a clear error; the existing fail-closed-on-fetch-error
  behavior (empty pool + returned error) is preserved.
- [x] The unit test's root-server fake serves the real bare-array format.

### Task 4.1 — [x] Parse the real Google root format

**Actions:**
- [x] Modify `internal/attest/refreshers.go`: replace `RootSet.fetch`'s dual JSON/raw-PEM parsing and
  delete the now-unused `rootResponse` struct — `json.Unmarshal(body, &[]string)` (error on a non-array
  body), error on an empty array, then `AppendCertsFromPEM` each PEM (error on a bad PEM).
- [x] Modify `internal/attest/refreshers_test.go`: `rootsJSON` marshals a bare `[]string` (not
  `{"roots":…}`); correct the `switchServer` doc comment to "a JSON array of PEM strings".

**Definition of Done:**
- [x] `TestRootRefresherSwapAndLastKnownGood` and `TestRootSetInitialFailureFailsClosed` pass against the
  bare-array format; the real-device gate (US3) gets past the root fetch.

## User Story 5 — [x] Documentation and ground-up verification

**Acceptance criteria:**
- [x] The Non-goals in `docs/PROJECT.md` and `.claude/rules/project.md` carve out this local test probe
  (the Android **client** stays out of scope; a minimal attestation **test probe** lives here).
- [x] `support/attest-probe/README.md` documents the build (`make attest-probe`), the local-SDK
  requirement, and the local-only gate.
- [x] Everything is verified from the ground up.

### Task 5.1 — [x] Documentation

**Actions:**
- [x] Modify `docs/PROJECT.md` §8 Non-goals — after "The Android (Kotlin) client lives with the app, not
  here.", add: "(The one exception is a minimal on-device **attestation test probe** under
  `support/attest-probe/`, built only to exercise the adb-gated `TestE2E_DeviceAttestation` gate — it is
  not the client.)"
- [x] Modify `.claude/rules/project.md` Non-goals — amend the "out of scope … lives with the app" bullet
  with the same carve-out (concise), referencing `support/attest-probe/`.
- [x] Create `support/attest-probe/README.md`: what the probe is (a real launched app minting a
  hardware-attested P-256 key bound to a server nonce), how to build/publish it (`make attest-probe`,
  needs the local Android SDK + build-tools `apksigner` on PATH, no downloads), the committed artifacts
  under `fixtures/attest-probe/`, and that `TestE2E_DeviceAttestation` is a local-only gate (skips
  without a device, never CI-with-device). Placeholder namespace `com.example.attestprobe` only.

**Definition of Done:**
- [x] Both Non-goals statements are truthful about the probe; the README builds a correct mental model.

### Task 5.2 — [x] Final ground-up verification (double-check EVERYTHING)

**Actions:**
- [x] Re-read this plan from the top and confirm every task/action + acceptance criterion is implemented.
- [x] Confirm the probe design satisfies EACH point of `internal/attest/verify.go` (P-256 leaf,
  challenge==nonce, signer digest in `signers.allow`, securityLevel ≥ TEE, verifiedBootState/deviceLocked
  from a real locked device, not revoked / status fresh).
- [x] Run `make attest-probe` and confirm it regenerates all three fixtures with no SDK download; confirm
  the committed `signers.allow` digest equals `apksigner verify --print-certs`'s certificate SHA-256.
- [x] Run the FULL quality gates (§ project.md Standard Commands): `make build vet lint govulncheck
  test-unit test-integration test-e2e test-scripts compose-config` + `make tidy` (zero go.mod drift).
  `test-e2e` MUST include the now-self-deploying `TestE2E_DeviceAttestation` PASSING with the device
  connected (capture the log per the tee rule).
- [x] Confirm the no-device path still SKIPS (temporarily reason about / exercise the skip branch) and
  that nothing wires this test into CI-with-device.
- [x] Confirm hygiene: no secrets/real domains/real values (placeholder namespace only), no AI
  attribution, no plan/finding IDs in code or commit messages, build outputs gitignored, the three
  fixtures committed, and NO out-of-scope files changed.
- [x] No Mermaid charts are added or modified by this plan; the Mermaid validation step (§9) therefore
  does NOT apply.

**Definition of Done:**
- [x] All gates pass on the final code; the device test passes with a device and skips without one; the
  ground-up re-read finds zero gaps.

---

## Deviations

- **Task 1.1 — toolchain versions pinned to the local cache.** The `<…_LOCAL>` placeholders resolved to
  AGP `8.13.2`, Kotlin `2.3.10`, `compileSdk = 36`, `targetSdk = 36`, Gradle wrapper `8.14.4` — mirrored
  from the machine's existing companion app, whose set is fully cached and mutually compatible, so the
  build pulls nothing new. `sourceCompatibility`/`targetCompatibility`/`jvmTarget` kept at 17 (the local
  JDK is 21, which emits 17 bytecode).
- **Task 1.1 — Kotlin jvmTarget DSL.** Used `kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }`
  (top-level) instead of the plan's deprecated `kotlinOptions { jvmTarget = "17" }`, matching the local
  Kotlin 2.3.10 toolchain.
- **Task 1.1 — Gradle wrapper reused.** No standalone `gradle` binary is on PATH to run `gradle wrapper`,
  so `gradlew`/`gradlew.bat`/`gradle-wrapper.jar`/`.properties` were copied from the local companion app
  (Gradle 8.14.4, already cached).
- **Task 1.1 — local.properties added.** Created a gitignored `support/attest-probe/local.properties`
  (`sdk.dir=…`) so Gradle finds the local SDK without relying on an exported `ANDROID_HOME`.
- **Task 2.1 — Makefile APKSIGNER resolution.** `apksigner` is not on PATH, so instead of
  `APKSIGNER ?= apksigner` the target derives `ANDROID_SDK` from `ANDROID_HOME`/`ANDROID_SDK_ROOT`/
  `$HOME/Android/Sdk` and picks the newest `build-tools/*/apksigner`, with a guard that fails clearly if
  none is found.
- **Task 2.1 — signer-digest awk field.** `apksigner verify --print-certs` prints
  `V2 Signer: certificate SHA-256 digest: <hex>`, so the digest is `$NF`, not `$2` as the recipe first
  assumed.
- **US4 added — attestation root-set parsing fix (production change, user-approved).** The plan had no
  production change. US3's device gate — the first test ever to fetch the LIVE Google `/attestation/root`
  — showed it publishes a **bare JSON array of PEM strings**, which `attest.NewRootSet` could not parse
  (it accepted only `{"roots":[…]}` or raw PEM), so the default `--attest-root-url` would fail-closed and
  no attestation could verify. With user approval, added US4 to parse ONLY the real bare-array format
  (removing the `{"roots":…}`/raw-PEM branches and the `rootResponse` struct) and fixed the unit-test
  root fake accordingly. The original "Documentation and ground-up verification" story was renumbered
  US4 → US5 so the ground-up verification stays the plan's last task.
- **US3 — adb remote-command quoting.** The `run-as sh -c <script>` calls send the whole remote command
  to `exec-out` as ONE pre-quoted argument (helper `adbRunAs`), because adb splits multiple args on
  spaces and corrupted the multi-word script (`rm`/status/`cat`).
- **Task 1.1 — gradle.properties `-Dfile.encoding=UTF-8`.** `org.gradle.jvmargs` carries an explicit
  `-Dfile.encoding=UTF-8` (matching the local companion app) for build reproducibility across locales,
  beyond the plan action's `-Xmx1536m` alone.
