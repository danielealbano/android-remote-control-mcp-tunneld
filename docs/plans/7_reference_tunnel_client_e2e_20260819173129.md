<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 7 — Reference Kotlin Tunnel Client + Real-Device End-to-End Test

Build a **complete, non-simplified reference phone client** in Kotlin under `support/tunnel-app/` and an
adb-gated e2e test that drives it on a real device through the FULL flow: real Google-attested two-phase
enrollment → Pebble-issued public cert → HTTP/2 mTLS control plane → opaque `/data` splice → a local
HTTP/2+HTTP/1.1 HTTPS server → server-nudged/manual renewal. The app is a genuine reference
implementation of the phone side of `docs/PROTOCOL.md` (not test glue), so it is built to production
quality.

## Context & key decisions (the decision record — not derivable from code)

- **Why:** the Go client (`client/`) drives enroll→issue→tunnel in the container e2e but with
  `--attestation-optional` + a *dummy* attestation and an in-process echo backend. No test exercises a
  REAL attested enrollment through the endpoints, and there is no reference phone client that terminates
  real TLS and serves through the tunnel. This plan adds both.
- **Both keys are TEE-resident and NON-EXPORTABLE** (AndroidKeyStore). The **identity key** is
  hardware-**attested** and bound to the server nonce (satisfies the seven-point predicate + key-binding,
  `docs/PROTOCOL.md` §1–§2). The **TLS/public key** is also a non-exportable AndroidKeyStore key; the
  local HTTPS server presents the Pebble-issued cert and signs the TLS handshakes with that key. Only
  CSRs ever leave the phone.
- **Real attestation, real Google roots.** The test configures tunneld with the REAL
  `--attest-root-url`/`--attest-status-url` (Google) and a committed `--attest-signer-digest-file` = the
  app's debug signing-cert SHA-256 (same mechanism as `fixtures/attest-probe/signers.allow`). Attestation
  is NOT optional. Identity CA (`--ca-*`) is a test-generated CA; public certs come from Pebble (the
  hermetic ACME test CA), exactly like the existing e2e.
- **Two distinct nonces:** the **server attestation nonce** (server-minted per `/enroll` + `/issue`,
  bound into the attestation challenge) and the **app-payload nonce** (test-supplied over adb, echoed by
  the `/info` endpoint to prove the tunnel reached this app instance). They are unrelated.
- **Local server** = **Ktor 3.4 on the Netty engine**, TLS wired via `sslConnector(...)` — the SAME server
  stack as `android-remote-control-mcp`'s `McpServer.kt`, so the reference client exercises the app's real
  webserver path. The non-exportable AndroidKeyStore TLS key drives the handshakes via an in-memory
  `KeyStore` built with `setKeyEntry(alias, <opaque keystore-key handle>, CharArray(0), <Pebble chain>)`:
  Ktor's Netty engine reads that `KeyStore` and builds a Netty `SslContext` whose `KeyManagerFactory` is
  initialized over it (Netty's `buildKeyManagerFactory`: `setKeyEntry` + `KeyManagerFactory.init`). The
  opaque key stays a reference through both `setKeyEntry` calls and the platform provider signs in the TEE,
  so no custom `KeyManagerFactory` SPI or `netty-tcnative` is needed. ALPN `h2`/`http/1.1` comes from the
  Netty engine; the platform Conscrypt
  provider terminates TLS (no explicit Netty or `conscrypt-android` dependency). Endpoints: `GET /info` and
  `GET /wait`.
- **Client transport** = **OkHttp** (HTTP/2). BOTH the **control** connection AND each **`/data`**
  dial-back use OkHttp's **duplex** `RequestBody` (`isDuplex()=true` — HTTP/2-only; OkHttp's
  `CallServerInterceptor` calls `writeTo(sink)` synchronously inside `execute()` BEFORE reading response
  headers, so `writeTo` must capture the sink and return — both directions are driven after `execute()`,
  see Task 3.2): on `/control` the request body streams phone→server `PONG` while the
  response body streams server→phone `OPEN`/`PING`/`RENEW_NUDGE`; on `/data` the request body streams the
  phone→client byte direction while the response body streams client→phone — the opaque bidirectional
  splice (mirroring `client/datastream.go`'s `io.Pipe` full-duplex over `http2.Transport`; a non-duplex
  `RequestBody` would buffer the request until the response, deadlocking the splice). `/enroll` and
  `/issue` are plain request/response OkHttp calls. mTLS uses a custom `X509ExtendedKeyManager` over the
  AndroidKeyStore identity key.
- **CSRs** are PKCS#10 built with **BouncyCastle** (`bcpkix`), signed by a `ContentSigner` backed by a
  `java.security.Signature` over the AndroidKeyStore key (the key never leaves the TEE).
- **Refresh** is exercised two ways, both wired: the app honors the server's `RENEW_NUDGE` frame AND a
  **test-triggered adb command** forces a fresh `/issue`. Renewal rotates the identity key + re-attests
  and re-obtains the public cert; the local server hot-swaps to the new cert.
- **Throughput/concurrency:** `GET /wait?seconds=X` streams `<total_bytes>\n` + an alphanumeric payload
  (~1 MiB/s for X s) + `\n<sha256-hex-of-payload>\n`. The test runs it concurrently over **HTTP/1.1 with
  N connections** (N tunnel streams) and **HTTP/2 with N streams** (one tunnel stream, multiplexed),
  hashing the received payload and comparing to the trailer to prove byte-exact delivery. tunneld is
  configured with **generous `--limit-*`** so pacing/caps do not interfere.
- **Connectivity:** tunneld runs on the host; the device reaches it via `adb reverse tcp:<edgePort>`
  (device-localhost → host edge). The app dials `localhost:<edgePort>` with SNI `enroll.`/`connect.` /
  `<name>.example.test` (SNI dispatch on the single edge port, per `docs/ARCHITECTURE.md`). The test
  `adb push`es Pebble's issuing CA to the device so the app trusts tunneld's enroll/control server certs;
  the test's own Go HTTPS client adds Pebble's issuing CA to its trusted roots to validate the phone's
  `<name>.example.test` cert.
- **Scope:** LOCAL-ONLY, device-gated (skips without a single adb device), **never CI-with-device**
  (needs the phone + real Google attestation reachability), mirroring `TestE2E_DeviceAttestation`.
- **Toolchain:** same as the probe — Kotlin/Gradle, AGP/Kotlin/Gradle/compileSdk pinned to the
  locally-cached versions (no Android-SDK downloads). **`minSdk 33`** (Ktor 3.4 pulls Netty 4.2, which
  needs API 33+ on Android). New libraries resolved from the local Gradle cache where present,
  else Maven Central (plugin/library jars only — never the Android SDK): **OkHttp 4.12.x** (5.x requires
  compileSdk 37, beyond the pinned toolchain), **BouncyCastle `bcpkix`+`bcprov`**, and **Ktor
  `ktor-server-core`+`ktor-server-netty` 3.4.x** (brings the Netty engine). NO explicit Netty or Conscrypt
  dependency. Placeholder namespace `com.example.tunnelapp`.
- The Go tunnel-client wire shapes to mirror are in `client/enroll.go` (enroll/issue JSON) and
  `internal/wire/frame_v2.go` (frames); the canonical contract is `docs/PROTOCOL.md`.

---

## User Story 1 — [ ] Reference app scaffolding + TEE keys, attestation, CSRs

A buildable Kotlin/Gradle app project with the crypto foundation: two non-exportable AndroidKeyStore EC
P-256 keys, a real hardware-attestation chain over the server nonce for the identity key, and PKCS#10
CSRs signed by the keystore keys.

**Acceptance criteria:**
- [ ] `support/tunnel-app/` is a self-contained Gradle **Kotlin** project (`minSdk 33`) that builds a
  debug APK with `./gradlew assembleDebug` using only the local SDK (no SDK downloads), with the
  dependencies OkHttp (4.12.x), BouncyCastle (`bcpkix`+`bcprov`), and Ktor
  (`ktor-server-core`+`ktor-server-netty` 3.4.x — Netty engine + platform Conscrypt; no explicit Netty or
  Conscrypt dependency).
- [ ] A crypto module generates an EC **P-256** identity key in AndroidKeyStore
  (`setAttestationChallenge(<server nonce>)`, non-exportable, purpose SIGN), and an EC **P-256** TLS key
  in AndroidKeyStore (non-exportable, purpose SIGN — server-side handshake signing), and returns the
  identity key's attestation chain (leaf-first) exactly as the enrollment expects.
- [ ] A CSR builder produces PKCS#10 CSRs (identity: CN `phone`; TLS: CN + DNS SAN =
  `<name>.<tunnel-domain>`) signed by the corresponding AndroidKeyStore key via a keystore-backed
  `ContentSigner` (the private key never leaves the TEE).

### Task 1.1 — [ ] Gradle project scaffolding

**Actions:**
- [ ] `support/tunnel-app/` already holds pre-existing sources that are NOT part of this reference client
  (which is service/receiver driven — no launcher activity). Delete them:
  `app/src/main/java/com/example/tunnelapp/{MainActivity.kt,TunnelReference.kt,KtorTlsProbe.kt,KeystoreProbe.kt}`.
  The pre-existing project files this task and US5 define below (`settings.gradle.kts`, `build.gradle.kts`,
  `gradle.properties`, `app/build.gradle.kts`, `AndroidManifest.xml`) are OVERWRITTEN with the content here.
- [ ] Create (overwrite) `support/tunnel-app/settings.gradle.kts`:

  ```kotlin
  pluginManagement {
      repositories { google(); mavenCentral(); gradlePluginPortal() }
  }
  dependencyResolutionManagement {
      repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
      repositories { google(); mavenCentral() }
  }
  rootProject.name = "tunnel-app"
  include(":app")
  ```

- [ ] Create `support/tunnel-app/build.gradle.kts` (AGP/Kotlin pinned to the locally-cached versions —
  record the exact versions in `## Deviations`):

  ```kotlin
  plugins {
      id("com.android.application") version "8.13.2" apply false
      id("org.jetbrains.kotlin.android") version "2.3.10" apply false
  }
  ```

- [ ] Create `support/tunnel-app/gradle.properties`:

  ```properties
  org.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8
  android.useAndroidX=true
  kotlin.code.style=official
  ```

- [ ] Copy the Gradle wrapper (`gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.{jar,properties}` —
  locally-cached Gradle 8.14.4) from `support/attest-probe/`. `local.properties` (`sdk.dir=…`) is
  machine-local and gitignored (Task 6.1).

- [ ] Create `support/tunnel-app/app/build.gradle.kts` (`compileSdk`/`targetSdk` pinned to the
  locally-available versions — record in `## Deviations`):

  ```kotlin
  plugins {
      id("com.android.application")
      id("org.jetbrains.kotlin.android")
  }

  android {
      namespace = "com.example.tunnelapp"
      compileSdk = 36
      defaultConfig {
          applicationId = "com.example.tunnelapp"
          minSdk = 33
          targetSdk = 36
          versionCode = 1
          versionName = "1.0"
      }
      buildTypes { getByName("debug") { isDebuggable = true } }
      compileOptions {
          sourceCompatibility = JavaVersion.VERSION_17
          targetCompatibility = JavaVersion.VERSION_17
      }
      packaging {
          // Netty + BouncyCastle jars collide on these META-INF resources.
          resources.excludes += setOf(
              "META-INF/versions/9/OSGI-INF/MANIFEST.MF", "META-INF/DEPENDENCIES",
              "META-INF/LICENSE.md", "META-INF/LICENSE-notice.md", "META-INF/NOTICE.md",
              "META-INF/INDEX.LIST", "META-INF/io.netty.versions.properties", "META-INF/{AL2.0,LGPL2.1}",
          )
          jniLibs { useLegacyPackaging = true }
      }
  }

  kotlin {
      compilerOptions {
          jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
      }
  }

  dependencies {
      implementation("com.squareup.okhttp3:okhttp:4.12.0") // 5.x requires compileSdk 37
      implementation("org.bouncycastle:bcpkix-jdk18on:1.85")
      implementation("org.bouncycastle:bcprov-jdk18on:1.85")
      implementation("io.ktor:ktor-server-core:3.4.0")  // Netty engine + platform Conscrypt terminate TLS;
      implementation("io.ktor:ktor-server-netty:3.4.0") // no explicit netty-* / conscrypt-android dep
  }
  ```
  - Constraint: the manifest's `INTERNET` + foreground-service permissions are Task 5.3's; declare nothing
    here that Task 5.3 owns.

**Definition of Done:**
- [ ] `cd support/tunnel-app && ./gradlew assembleDebug` produces a debug APK with all dependencies
  resolved and no Android-SDK download.

### Task 1.2 — [ ] Keystore keys + attestation (`Keys.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/Keys.kt`. The rotation is a **staged-alias** scheme: the live key stays under its
  alias for the in-flight `/issue` mTLS while the fresh key is minted under a distinct alias; the CALLER
  (Enroll/Identity) tracks which alias is live and deletes the old one only AFTER `/issue` installs the new
  certs (mirrors `client/enroll.go` keeping `bootKey` alive through `issueCerts`; `docs/PROTOCOL.md` §3).

  ```kotlin
  package com.example.tunnelapp

  import android.security.keystore.KeyGenParameterSpec
  import android.security.keystore.KeyProperties
  import android.util.Base64
  import java.security.KeyPairGenerator
  import java.security.KeyStore
  import java.security.PrivateKey
  import java.security.PublicKey
  import java.security.cert.X509Certificate
  import java.security.spec.ECGenParameterSpec

  // Keys owns the non-exportable AndroidKeyStore EC P-256 keys. Only CSRs + attestation chains leave the
  // TEE; PrivateKey handles are opaque (getEncoded()==null).
  object Keys {
      private const val KS = "AndroidKeyStore"

      private fun ks(): KeyStore = KeyStore.getInstance(KS).apply { load(null) }

      // generateEcKey mints a non-exportable EC P-256 key under alias. Conscrypt signs an AndroidKeyStore
      // EC key for TLS via Signature("NONEwithECDSA") (the TLS stack pre-hashes the transcript), so the key
      // MUST authorize DIGEST_NONE or keymaster rejects the CertificateVerify mid-handshake. PURPOSE_SIGN
      // suffices (ECDHE needs no key-decryption); SHA-256/384/512 are kept for the CSR. When challenge !=
      // null the key is hardware-attested over it.
      fun generateEcKey(alias: String, challenge: ByteArray? = null) {
          val ks = ks()
          ks.deleteEntry(alias)
          val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
              .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
              .setDigests(
                  KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                  KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512,
              )
          if (challenge != null) b.setAttestationChallenge(challenge)
          KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KS)
              .apply { initialize(b.build()); generateKeyPair() }
      }

      fun privateKey(alias: String): PrivateKey = ks().getKey(alias, null) as PrivateKey
      fun publicKey(alias: String): PublicKey = (ks().getCertificate(alias) as X509Certificate).publicKey
      fun deleteKey(alias: String) = ks().deleteEntry(alias)

      // attestationChainPem PEM-encodes the AndroidKeyStore cert chain for an attested key — the leaf
      // attestation cert → device/batch/factory roots tunneld's seven-point verifier checks.
      fun attestationChainPem(alias: String): String {
          val chain = ks().getCertificateChain(alias) ?: error("no attestation chain for $alias")
          return buildString { for (c in chain) append(pem("CERTIFICATE", c.encoded)) }
      }

      fun pem(type: String, der: ByteArray): String {
          val b64 = Base64.encodeToString(der, Base64.NO_WRAP).chunked(64).joinToString("\n")
          return "-----BEGIN $type-----\n$b64\n-----END $type-----\n"
      }

      fun hexToBytes(s: String): ByteArray {
          require(s.length % 2 == 0 && s.isNotEmpty()) { "bad hex" }
          return ByteArray(s.length / 2) {
              ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
          }
      }
  }
  ```

**Definition of Done:**
- [ ] Both keys generate as non-exportable P-256 (`getEncoded()==null`, `KeyInfo.securityLevel` = TEE); the
  identity chain verifies with the production `attest.Verifier` for a supplied nonce (exercised by US7).

### Task 1.3 — [ ] CSR builder (`Csr.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/Csr.kt` (matches `client/enroll.go`'s `csrPEM`/`tlsCSRForTunnel` shapes):

  ```kotlin
  package com.example.tunnelapp

  import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
  import org.bouncycastle.asn1.x500.X500Name
  import org.bouncycastle.asn1.x509.AlgorithmIdentifier
  import org.bouncycastle.asn1.x509.Extension
  import org.bouncycastle.asn1.x509.ExtensionsGenerator
  import org.bouncycastle.asn1.x509.GeneralName
  import org.bouncycastle.asn1.x509.GeneralNames
  import org.bouncycastle.operator.ContentSigner
  import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
  import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
  import java.io.ByteArrayOutputStream
  import java.io.OutputStream
  import java.security.PrivateKey
  import java.security.PublicKey
  import java.security.Signature

  // Csr builds PKCS#10 CSRs signed by an AndroidKeyStore EC key via a ContentSigner wrapping a
  // Signature("SHA256withECDSA") over the keystore PrivateKey — the private bytes never leave the TEE.
  object Csr {
      // identity: CN "phone" (the server ignores the CSR subject and assigns the name).
      fun identityCsr(key: PrivateKey, pub: PublicKey): String = build(key, pub, "phone", null)

      // tls: CN + one DNS SAN == <name>.<tunnelDomain> (PROTOCOL §2).
      fun tlsCsr(key: PrivateKey, pub: PublicKey, fqdn: String): String = build(key, pub, fqdn, fqdn)

      private fun build(key: PrivateKey, pub: PublicKey, cn: String, sanDns: String?): String {
          val algId: AlgorithmIdentifier = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHECDSA")
          val ksSig = Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
          val buf = ByteArrayOutputStream()
          val signer = object : ContentSigner {
              override fun getAlgorithmIdentifier(): AlgorithmIdentifier = algId
              override fun getOutputStream(): OutputStream = buf
              override fun getSignature(): ByteArray { ksSig.update(buf.toByteArray()); return ksSig.sign() }
          }
          val builder = JcaPKCS10CertificationRequestBuilder(X500Name("CN=$cn"), pub)
          if (sanDns != null) {
              val ext = ExtensionsGenerator()
              ext.addExtension(
                  Extension.subjectAlternativeName, false,
                  GeneralNames(GeneralName(GeneralName.dNSName, sanDns)),
              )
              builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate())
          }
          return Keys.pem("CERTIFICATE REQUEST", builder.build(signer).encoded)
      }
  }
  ```

**Definition of Done:**
- [ ] Both CSRs are valid PKCS#10, ECDSA-P256-signed by the keystore key, and parse server-side (proven
  by a successful enrollment in US7).

---

## User Story 2 — [ ] Two-phase attested enrollment client

The app performs the real two-phase enrollment over OkHttp with mTLS, mirroring the wire shapes in
`client/enroll.go` and `docs/PROTOCOL.md` §2–§3, but with a REAL attestation chain.

**Acceptance criteria:**
- [ ] Phase 1: `GET /enroll/nonce` → generate the attested identity key over that nonce → `POST /enroll`
  `{nonce, attestation_chain, identity_csr}` → parse `{name, identity_cert, issue_nonce}`.
- [ ] Phase 2 (mTLS): generate fresh identity + TLS keys, re-attest the identity key over `issue_nonce`,
  `POST /issue` `{nonce, attestation_chain, identity_csr, tls_csr}` → parse `{identity_cert, public_cert,
  ca}`.
- [ ] mTLS presents the Phase-1 identity cert + signs with the AndroidKeyStore identity key; the app
  trusts tunneld's server certs via the pushed Pebble CA. SNI overrides the dial target (dial
  `localhost:<edgePort>`, `ServerName = enroll.`/`connect.<tunnel-domain>`), exactly as
  `client/enroll.go`'s `serverTLSTransport`/`newMTLSTransport` do.
- [ ] Structured error handling per `docs/PROTOCOL.md` §2–§3 (`{reason, retryable, retry_after_seconds}`,
  the status taxonomy) and the retry path (fresh `GET /enroll/nonce` → wait → re-`POST /issue`).

### Task 2.1 — [ ] Trust + mTLS wiring (`Tls.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/Tls.kt`. SNI/dial split: `loopbackDns` forces every hostname to `127.0.0.1` (the
  adb-reversed edge port) while the URL host carries both the SNI AND the hostname the default verifier
  checks against the Pebble-signed server cert — so no `hostnameVerifier` override is needed. The custom
  `X509ExtendedKeyManager` drives mTLS with the non-exportable EC identity key (TLS 1.2/1.3, `ECDHE_ECDSA`;
  no software fallback).

  ```kotlin
  package com.example.tunnelapp

  import okhttp3.Dns
  import okhttp3.OkHttpClient
  import java.io.File
  import java.net.InetAddress
  import java.net.Socket
  import java.security.KeyStore
  import java.security.Principal
  import java.security.SecureRandom
  import java.security.cert.CertificateFactory
  import java.security.cert.X509Certificate
  import javax.net.ssl.SSLContext
  import javax.net.ssl.SSLEngine
  import javax.net.ssl.TrustManagerFactory
  import javax.net.ssl.X509ExtendedKeyManager
  import javax.net.ssl.X509TrustManager

  object Tls {
      // pebbleTrust: the pushed Pebble issuing-CA PEM is the sole trust anchor for tunneld's server certs.
      fun pebbleTrust(pebbleCaPemPath: String): X509TrustManager {
          val certs = CertificateFactory.getInstance("X.509")
              .generateCertificates(File(pebbleCaPemPath).inputStream())
          val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
          certs.forEachIndexed { i, c -> setCertificateEntryOn(ks, "pebble$i", c as X509Certificate) }
          val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
          return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
      }

      private fun setCertificateEntryOn(ks: KeyStore, alias: String, c: X509Certificate) = ks.setCertificateEntry(alias, c)

      val loopbackDns = object : Dns {
          override fun lookup(hostname: String): List<InetAddress> = listOf(InetAddress.getByName("127.0.0.1"))
      }

      // serverClient: server-TLS only (Phase-1 enroll — the phone has no identity yet).
      fun serverClient(trust: X509TrustManager): OkHttpClient = client(sslContext(null, trust), trust)

      // mtlsClient presents the CURRENT live identity cert + signs with the live AndroidKeyStore identity
      // key, resolved dynamically per handshake — so a renewal that rotates the identity is picked up on the
      // next handshake and reconnect (mirrors client/control.go's GetClientCertificate callback re-reading
      // the identity each handshake).
      fun mtlsClient(id: Identity, trust: X509TrustManager): OkHttpClient =
          client(sslContext(DynamicIdentityKeyManager(id), trust), trust)

      fun sslContext(km: X509ExtendedKeyManager?, trust: X509TrustManager): SSLContext =
          SSLContext.getInstance("TLS").apply { init(km?.let { arrayOf(it) }, arrayOf(trust), SecureRandom()) }

      private fun client(ctx: SSLContext, trust: X509TrustManager): OkHttpClient =
          OkHttpClient.Builder().dns(loopbackDns).sslSocketFactory(ctx.socketFactory, trust).build()

      // DynamicIdentityKeyManager resolves the CURRENT identity per handshake and returns a CONSISTENT cert+key
      // pair even across a concurrent renewal: chooseClientAlias captures ONE atomic Cred snapshot in a
      // thread-local that getCertificateChain/getPrivateKey then read (the Go client bundles both into one
      // *tls.Certificate under c.mu — client/control.go). Client auth only (the server uses ServerTls); the key
      // never leaves the TEE.
      class DynamicIdentityKeyManager(private val id: Identity) : X509ExtendedKeyManager() {
          private val selected = ThreadLocal<Cred>()
          private fun pick(): String = id.identityCred().also { selected.set(it) }.alias
          private fun cred(): Cred = selected.get() ?: id.identityCred().also { selected.set(it) }
          override fun getClientAliases(k: String?, i: Array<Principal>?) = arrayOf(pick())
          override fun chooseClientAlias(k: Array<out String>?, i: Array<Principal>?, s: Socket?) = pick()
          override fun chooseEngineClientAlias(k: Array<out String>?, i: Array<Principal>?, e: SSLEngine?) = pick()
          override fun getServerAliases(k: String?, i: Array<Principal>?): Array<String>? = null
          override fun chooseServerAlias(k: String?, i: Array<Principal>?, s: Socket?): String? = null
          override fun chooseEngineServerAlias(k: String?, i: Array<Principal>?, e: SSLEngine?): String? = null
          override fun getCertificateChain(a: String?) = cred().chain
          override fun getPrivateKey(a: String?) = cred().key
      }
  }
  ```

**Definition of Done:**
- [ ] An mTLS request to tunneld's `connect.<tunnel-domain>` succeeds using the keystore identity key,
  validated against the pushed Pebble CA.

### Task 2.2 — [ ] Enrollment exchange (`Enroll.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/Enroll.kt` (JSON shapes exactly per `client/enroll.go`
  `enrollRequestBody`/`enrollResponse`/`issueRequestBody`/`issueResponseBody`; `renew` mirrors
  `client/renew.go`). The `/issue` mTLS authenticates with the CURRENT live identity; a fresh attested
  identity key + TLS key are minted under a new alias generation and the old aliases dropped only AFTER the
  response installs the new certs. `Identity` guards ALL rotation-critical state behind a lock and serializes
  every issuance through `issueLock` (mirroring `client/control.go`'s `c.mu`), and the install is atomic; the
  superseded identity key is dropped one generation late so a concurrent handshake never loses its key.
  A non-200 parses the structured `{reason, retryable, retry_after_seconds}`
  body into `EnrollError`; `issue` follows the `docs/PROTOCOL.md` §3 retry path on a RETRYABLE error (fetch a
  FRESH nonce via `GET /enroll/nonce` → wait `retry_after` → re-`POST /issue`, bounded), and cleans up the
  staged keys before failing.

  ```kotlin
  package com.example.tunnelapp

  import okhttp3.MediaType.Companion.toMediaType
  import okhttp3.OkHttpClient
  import okhttp3.Request
  import okhttp3.RequestBody.Companion.toRequestBody
  import org.json.JSONObject
  import java.io.ByteArrayInputStream
  import java.security.PrivateKey
  import java.security.cert.CertificateFactory
  import java.security.cert.X509Certificate
  import javax.net.ssl.X509TrustManager

  // Cred is an atomic {alias, chain, key} snapshot of the live identity — the Kotlin analogue of the Go
  // client's *tls.Certificate bundle (client/control.go currentCert()), so an mTLS handshake reads a matching
  // cert+key pair even when a renewal swaps the identity mid-handshake.
  class Cred(val alias: String, val chain: Array<X509Certificate>, val key: PrivateKey)

  // Identity is an enrolled tunnel identity: the assigned name plus the rotation-critical live state (keystore
  // aliases + issued chains). ALL mutable state is guarded by `lock`, and every issuance is serialized by
  // `issueLock` (mirrors client/control.go's c.mu discipline), so overlapping renewals — a RENEW_NUDGE and a
  // manual refresh — can neither race the fields nor collide on the next generation's alias. The device dials
  // 127.0.0.1:<port> (adb-reverse) while the URL host is the SNI host.
  class Identity(
      val name: String,
      val port: Int,
      val enrollHost: String,
      val controlHost: String,
      val tunnelDomain: String,
      val trust: X509TrustManager,
      identityAlias: String,
      tlsAlias: String,
      identityChain: Array<X509Certificate>,
      publicChain: Array<X509Certificate>,
      caId: String,
      generation: Int,
  ) {
      private val lock = Any()
      val issueLock = Any() // serializes issuance so overlapping renewals cannot collide on the gen/alias
      private var identityAlias = identityAlias
      private var prevIdentityAlias = "" // retained one generation so a straddling handshake still resolves its key
      private var tlsAlias = tlsAlias
      private var prevTlsAlias = "" // retained one generation so the still-live old local server keeps its key
      private var identityChain = identityChain
      private var publicChain = publicChain
      private var caId = caId
      private var generation = generation

      fun mtlsClient(): OkHttpClient = Tls.mtlsClient(this, trust)

      // identityCred: an atomic mTLS snapshot — the current chain and its keystore key resolved together.
      fun identityCred(): Cred = synchronized(lock) { Cred(identityAlias, identityChain, Keys.privateKey(identityAlias)) }

      // tlsCredential: the current TLS-server key + issued public chain (read on the renewal/swap thread).
      fun tlsCredential(): Pair<PrivateKey, Array<X509Certificate>> = synchronized(lock) { Keys.privateKey(tlsAlias) to publicChain }

      // publicLeaf: the issued leaf cert, for the status file's tls_cert_sha256.
      fun publicLeaf(): X509Certificate = synchronized(lock) { publicChain[0] }

      // issueBase: the stable inputs to the next /issue (name, CA hint, current generation), read before the call.
      fun issueBase(): Triple<String, String, Int> = synchronized(lock) { Triple(name, caId, generation) }

      // install atomically swaps in the rotated certs/aliases and returns the two-generations-back
      // (staleIdentityAlias, staleTlsAlias) to delete — BOTH keys are dropped one generation late: the identity
      // key so a straddling mTLS handshake never loses it, the TLS key so the still-live old local server
      // (replaced only after the caller restarts it) never loses the key it is bound to.
      fun install(
          nextId: String, nextTls: String, idChain: Array<X509Certificate>,
          pubChain: Array<X509Certificate>, ca: String, gen: Int,
      ): Pair<String, String> = synchronized(lock) {
          val staleId = prevIdentityAlias
          val staleTls = prevTlsAlias
          prevIdentityAlias = identityAlias
          prevTlsAlias = tlsAlias
          identityAlias = nextId
          tlsAlias = nextTls
          identityChain = idChain
          publicChain = pubChain
          caId = ca
          generation = gen
          staleId to staleTls
      }
  }

  // EnrollError carries the structured server error (docs/PROTOCOL.md §2–§3): {reason, retryable, retry_after_seconds}.
  class EnrollError(val reason: String, val retryable: Boolean, val retryAfterSec: Long, val status: Int) :
      RuntimeException("enroll: $reason (status $status)")

  object Enroll {
      private const val MAX_ISSUE_RETRIES = 3

      // enroll: two-phase attested enrollment → a fully-issued Identity.
      fun enroll(port: Int, enrollHost: String, controlHost: String, tunnelDomain: String, trust: X509TrustManager): Identity {
          val server = Tls.serverClient(trust)
          val nonce = getJson(server, "https://$enrollHost:$port/enroll/nonce").getString("nonce")
          val idAlias = "tunnel-identity-0"
          Keys.generateEcKey(idAlias, Keys.hexToBytes(nonce)) // attested over the enroll nonce
          val body = JSONObject()
              .put("nonce", nonce)
              .put("attestation_chain", Keys.attestationChainPem(idAlias))
              .put("identity_csr", Csr.identityCsr(Keys.privateKey(idAlias), Keys.publicKey(idAlias)))
          val (status, resp) = postJson(server, "https://$enrollHost:$port/enroll", body.toString())
          if (status != 200) fail(status, resp)
          val r = JSONObject(resp)
          val id = Identity(
              r.getString("name"), port, enrollHost, controlHost, tunnelDomain, trust,
              idAlias, "", parseChain(r.getString("identity_cert")), emptyArray(), "", 0,
          )
          issue(id, r.getString("issue_nonce"))
          return id
      }

      // issue: Phase 2 / every renewal, serialized by id.issueLock so two overlapping renewals cannot collide
      // on the next generation's alias. On a RETRYABLE server error it follows the documented retry path
      // (docs/PROTOCOL.md §3): fetch a FRESH nonce from GET /enroll/nonce, wait retry_after, then re-issue (bounded).
      fun issue(id: Identity, nonce: String) {
          synchronized(id.issueLock) {
              var attempt = 0
              var n = nonce
              while (true) {
                  try { issueOnce(id, n); return } catch (e: EnrollError) {
                      if (!e.retryable || attempt++ >= MAX_ISSUE_RETRIES) throw e
                      n = getJson(Tls.serverClient(id.trust), "https://${id.enrollHost}:${id.port}/enroll/nonce").getString("nonce")
                      Thread.sleep(e.retryAfterSec.coerceAtLeast(1) * 1000)
                  }
              }
          }
      }

      // issueOnce: one /issue attempt (holds id.issueLock via issue). Fresh attested identity key (over nonce) +
      // fresh TLS key, mTLS-auth'd with the current live identity; on 200 install the rotated certs/aliases
      // ATOMICALLY, then drop the superseded keys — BOTH the identity and TLS keys one generation late so
      // neither a concurrent mTLS handshake nor the still-live old local server loses its key.
      private fun issueOnce(id: Identity, nonce: String) {
          val base = id.issueBase() // (name, caId, generation)
          val gen = base.third + 1
          val nextId = "tunnel-identity-$gen"
          val nextTls = "tunnel-tls-$gen"
          Keys.generateEcKey(nextId, Keys.hexToBytes(nonce))
          Keys.generateEcKey(nextTls) // TLS key: proof-of-possession only, no attestation
          // Any failure BEFORE install (HTTP error, network throw, malformed response/cert) drops the staged
          // keys and rethrows; AFTER install they are the live keys and MUST NOT be dropped here.
          val (idChain, pubChain, ca) = try {
              val fqdn = "${id.name}.${id.tunnelDomain}"
              val body = JSONObject()
                  .put("nonce", nonce)
                  .put("attestation_chain", Keys.attestationChainPem(nextId))
                  .put("identity_csr", Csr.identityCsr(Keys.privateKey(nextId), Keys.publicKey(nextId)))
                  .put("tls_csr", Csr.tlsCsr(Keys.privateKey(nextTls), Keys.publicKey(nextTls), fqdn))
              val (status, resp) = postJson(id.mtlsClient(), "https://${id.controlHost}:${id.port}/issue", body.toString())
              if (status != 200) fail(status, resp)
              val r = JSONObject(resp)
              Triple(parseChain(r.getString("identity_cert")), parseChain(r.getString("public_cert")), r.optString("ca", base.second))
          } catch (t: Throwable) {
              Keys.deleteKey(nextId); Keys.deleteKey(nextTls); throw t
          }
          val (staleId, staleTls) = id.install(nextId, nextTls, idChain, pubChain, ca, gen)
          if (staleId.isNotEmpty() && staleId != nextId) Keys.deleteKey(staleId)
          if (staleTls.isNotEmpty() && staleTls != nextTls) Keys.deleteKey(staleTls)
      }

      // renew: the MANUAL refresh path (no RENEW_NUDGE frame to carry a nonce) mints a fresh nonce, then
      // issues. A RENEW_NUDGE passes its frame's nonce straight to issue().
      fun renew(id: Identity) {
          val nonce = getJson(Tls.serverClient(id.trust), "https://${id.enrollHost}:${id.port}/enroll/nonce").getString("nonce")
          issue(id, nonce)
      }

      private fun fail(status: Int, resp: String): Nothing {
          val r = try { JSONObject(resp) } catch (_: Throwable) { JSONObject() }
          throw EnrollError(
              r.optString("reason", "http_$status"), r.optBoolean("retryable", false),
              r.optLong("retry_after_seconds", 0), status,
          )
      }

      private fun getJson(client: OkHttpClient, url: String): JSONObject {
          client.newCall(Request.Builder().url(url).get().build()).execute().use { resp ->
              val b = resp.body?.string().orEmpty()
              require(resp.code == 200) { "GET $url -> ${resp.code} $b" }
              return JSONObject(b)
          }
      }

      private fun postJson(client: OkHttpClient, url: String, json: String): Pair<Int, String> {
          val req = Request.Builder().url(url).post(json.toRequestBody("application/json".toMediaType())).build()
          client.newCall(req).execute().use { resp -> return resp.code to resp.body?.string().orEmpty() }
      }

      private fun parseChain(pem: String): Array<X509Certificate> =
          CertificateFactory.getInstance("X.509").generateCertificates(ByteArrayInputStream(pem.toByteArray()))
              .map { it as X509Certificate }.toTypedArray()
  }
  ```

**Definition of Done:**
- [ ] A full enrollment against tunneld (attestation ON) yields the assigned name + a Pebble-issued
  `<name>.<tunnel-domain>` public cert (proven in US7).

---

## User Story 3 — [ ] HTTP/2 control plane + opaque data splice

The app maintains the outbound mTLS HTTP/2 control connection and services dial-backs, mirroring
`docs/PROTOCOL.md` §3–§4 and `internal/wire/frame_v2.go`.

**Acceptance criteria:**
- [ ] The control-frame codec encodes/decodes `[type:1][payloadLen:4 BE][payload JSON]` with the FROZEN
  types `OPEN=0x01`, `PING=0x02`, `PONG=0x03`, `RENEW_NUDGE=0x04` and payloads `{stream_id}` /
  `{nonce, ari_window}`.
- [ ] The control connection is a **duplex** `POST /control` (OkHttp `isDuplex()=true`): the response
  body is read as the server→phone frame stream; the request body writes `PONG` in reply to `PING`; the
  stream stays open for the connection lifetime.
- [ ] On `OPEN{stream_id}` the app opens a `POST /data` dial-back with header `X-Stream-Id`, and splices
  its request body (phone→client) / response body (client→phone) to a fresh TCP connection to the local
  HTTPS server (US4) — an OPAQUE byte copy, no framing.
- [ ] On `RENEW_NUDGE{nonce}` the app calls `Enroll.issue(id, nonce)` and hot-swaps the local server's
  identity/cert (US4/US5), keeping the connection up on the old certs until the swap.

### Task 3.1 — [ ] Frame codec (`Frames.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/Frames.kt` (layout per `internal/wire/frame_v2.go`):

  ```kotlin
  package com.example.tunnelapp

  import okio.BufferedSource
  import java.io.IOException

  // Frames is the v2 control-frame codec: [type:1][payloadLen:4 BE][payload JSON], 1 MiB cap. The data
  // stream is opaque (no framing). Payloads: OPEN {stream_id}, RENEW_NUDGE {nonce, ari_window}.
  object Frames {
      const val OPEN = 1
      const val PING = 2
      const val PONG = 3
      const val RENEW_NUDGE = 4
      private const val MAX = 1 shl 20

      val PONG_FRAME = byteArrayOf(PONG.toByte(), 0, 0, 0, 0)

      // read parses one frame from source (blocking); returns (type, payloadJsonBytes) or null on EOF.
      fun read(source: BufferedSource): Pair<Int, ByteArray>? = try {
          val type = source.readByte().toInt() and 0xff
          val len = source.readInt() // big-endian
          if (len < 0 || len > MAX) throw IOException("control frame too large: $len")
          type to (if (len == 0) ByteArray(0) else source.readByteArray(len.toLong()))
      } catch (_: Throwable) {
          null
      }
  }
  ```

**Definition of Done:**
- [ ] Round-trip decode matches `internal/wire`'s layout byte-for-byte (verified against the server in US7).

### Task 3.2 — [ ] Control + data client (`Tunnel.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/Tunnel.kt` (mirrors `client/control.go`/`client/datastream.go`; `docs/PROTOCOL.md`
  §3–§4). **Duplex constraint:** OkHttp's `CallServerInterceptor` calls `RequestBody.writeTo(sink)`
  synchronously inside `execute()` BEFORE reading response headers, so for a duplex body `writeTo` MUST
  capture the sink and return immediately — blocking there deadlocks the control connection; both stream
  directions are driven AFTER `execute()`.

  ```kotlin
  package com.example.tunnelapp

  import okhttp3.MediaType
  import okhttp3.OkHttpClient
  import okhttp3.Request
  import okhttp3.RequestBody
  import okio.BufferedSink
  import org.json.JSONObject
  import java.net.Socket
  import java.util.concurrent.atomic.AtomicBoolean

  // Tunnel maintains the outbound mTLS HTTP/2 control connection and services /data dial-backs. Both streams
  // are OkHttp DUPLEX (isDuplex()=true).
  class Tunnel(
      private val client: OkHttpClient,   // the identity-mTLS client (Identity.mtlsClient())
      private val controlHost: String,
      private val port: Int,
      private val localServerPort: () -> Int, // lambda defers reading the server's fixed loopback port
      private val onRenewNudge: (String) -> Unit,
  ) {
      private val running = AtomicBoolean(true)
      fun stop() = running.set(false)

      // run opens /control and services it until stopped; a torn stream reconnects with backoff.
      fun run() {
          var backoff = 200L
          while (running.get()) {
              try { serveControlOnce(); backoff = 200L } catch (_: Throwable) {}
              if (!running.get()) break
              Thread.sleep(backoff); backoff = (backoff * 2).coerceAtMost(5_000L)
          }
      }

      private fun serveControlOnce() {
          var sink: BufferedSink? = null
          val body = duplexBody { sink = it }
          client.newCall(Request.Builder().url("https://$controlHost:$port/control").post(body).build())
              .execute().use { resp ->
                  if (resp.code != 200) return
                  val s = sink ?: return
                  val source = resp.body!!.source()
                  while (running.get()) {
                      val frame = Frames.read(source) ?: break
                      when (frame.first) {
                          Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                          Frames.OPEN -> JSONObject(String(frame.second)).optString("stream_id")
                              .takeIf { it.isNotEmpty() }
                              ?.let { id -> Thread { handleOpen(id) }.apply { isDaemon = true }.start() }
                          Frames.RENEW_NUDGE -> JSONObject(String(frame.second)).optString("nonce")
                              .takeIf { it.isNotEmpty() }
                              ?.let { n -> Thread { onRenewNudge(n) }.apply { isDaemon = true }.start() }
                      }
                  }
                  try { s.close() } catch (_: Throwable) {}
              }
      }

      // handleOpen: duplex /data dial-back spliced OPAQUELY to a fresh socket to the local server. Request
      // body = phone→client (local→sink), response body = client→phone (resp→local). No framing.
      private fun handleOpen(streamId: String) {
          val local = try { Socket("127.0.0.1", localServerPort()) } catch (_: Throwable) { return }
          try {
              var sink: BufferedSink? = null
              val body = duplexBody { sink = it }
              client.newCall(
                  Request.Builder().url("https://$controlHost:$port/data")
                      .addHeader("X-Stream-Id", streamId).post(body).build(),
              ).execute().use { resp ->
                  if (resp.code != 200) return
                  val s = sink ?: return
                  val up = Thread {
                      try {
                          val buf = ByteArray(16384); val ins = local.getInputStream()
                          while (true) { val n = ins.read(buf); if (n < 0) break; s.write(buf, 0, n); s.flush() }
                      } catch (_: Throwable) {} finally { try { s.close() } catch (_: Throwable) {} }
                  }.apply { isDaemon = true }
                  up.start()
                  val out = local.getOutputStream(); val src = resp.body!!.byteStream(); val buf = ByteArray(16384)
                  while (true) { val n = src.read(buf); if (n < 0) break; out.write(buf, 0, n); out.flush() }
                  up.join(5000)
              }
          } catch (_: Throwable) {
          } finally {
              try { local.close() } catch (_: Throwable) {}
          }
      }

      private fun duplexBody(capture: (BufferedSink) -> Unit): RequestBody = object : RequestBody() {
          override fun contentType(): MediaType? = null
          override fun isDuplex(): Boolean = true
          override fun writeTo(sink: BufferedSink) { capture(sink) } // capture + return; drive after execute()
      }
  }
  ```

**Definition of Done:**
- [ ] A public connection through the edge reaches the local server and round-trips (proven in US7);
  `PING`/`PONG` liveness holds the connection; `RENEW_NUDGE` triggers a renewal.

---

## User Story 4 — [ ] Local HTTP/2 + HTTP/1.1 HTTPS server on the non-exportable TLS key

A **Ktor (Netty engine)** server bound to device-loopback that terminates client TLS with the
Pebble-issued cert and the non-exportable AndroidKeyStore TLS key — the SAME `sslConnector` stack as the
`android-remote-control-mcp` app — negotiating `h2`/`http/1.1` via ALPN, serving `/info` and `/wait`.

**Acceptance criteria:**
- [ ] The server presents the Pebble-issued `<name>.<tunnel-domain>` cert chain and signs handshakes with
  the AndroidKeyStore TLS key (non-exportable); ALPN offers `h2` and `http/1.1`.
- [ ] `GET /info` → JSON `{nonce, tls_cert_sha256, not_before, not_after, name, san, issuer}` (the
  app-payload nonce; the SHA-256 of the presented leaf cert DER; the cert validity window; the assigned
  name; the SAN; the issuer DN).
- [ ] `GET /wait?seconds=X` streams `<total_bytes>\n` then an alphanumeric payload at ~1 MiB/s for X
  seconds, then `\n<sha256-hex-of-payload>\n`; identical behavior over h2 and http/1.1.
- [ ] The cert/key are **swappable on renewal**: the in-memory keystore is rebuilt with the new TLS key +
  Pebble chain and the embedded server restarts on the SAME fixed loopback port. Transparent because
  `/data` dial-backs are per-connection (US3), so no persistent listener connection is dropped.

### Task 4.1 — [ ] TLS key material for Ktor `sslConnector` (`ServerTls.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/ServerTls.kt`. The opaque keystore key stays a reference through `setKeyEntry` +
  `KeyManagerFactory.init` (Netty's `buildKeyManagerFactory`) and the platform provider signs in the TEE —
  no custom `KeyManagerFactory` SPI, no `netty-tcnative`, no pipeline surgery. Empty password everywhere.

  ```kotlin
  package com.example.tunnelapp

  import java.security.KeyStore
  import java.security.PrivateKey
  import java.security.cert.X509Certificate

  // ServerTls builds the in-memory KeyStore Ktor's sslConnector consumes for the local HTTPS server: it
  // holds the OPAQUE AndroidKeyStore TLS key + the issued Pebble cert chain.
  object ServerTls {
      const val ALIAS = "tls"
      val PASSWORD: CharArray = CharArray(0)

      fun keyStore(tlsKey: PrivateKey, chain: Array<X509Certificate>): KeyStore =
          KeyStore.getInstance(KeyStore.getDefaultType()).apply {
              load(null, null)
              setKeyEntry(ALIAS, tlsKey, PASSWORD, chain)
          }
  }
  ```

**Definition of Done:**
- [ ] A Ktor (Netty) server configured via `sslConnector` with this in-memory keystore completes an `h2`
  TLS 1.3 handshake using the non-exportable key (proven by the US7 test through the tunnel).

### Task 4.2 — [ ] The server (`Server.kt`) + endpoints

**Actions:**
- [ ] Create `…/tunnelapp/Server.kt` (fixed loopback port shared with the Tunnel, US3; the Netty engine
  negotiates `h2`/`http/1.1` via ALPN, so both routes serve identically over h2 and h1):

  ```kotlin
  package com.example.tunnelapp

  import io.ktor.http.ContentType
  import io.ktor.server.engine.EmbeddedServer
  import io.ktor.server.engine.embeddedServer
  import io.ktor.server.engine.sslConnector
  import io.ktor.server.netty.Netty
  import io.ktor.server.netty.NettyApplicationEngine
  import io.ktor.server.response.respondBytesWriter
  import io.ktor.server.response.respondText
  import io.ktor.server.routing.get
  import io.ktor.server.routing.routing
  import io.ktor.utils.io.writeFully
  import io.ktor.utils.io.writeStringUtf8
  import kotlinx.coroutines.delay
  import org.json.JSONObject
  import java.security.MessageDigest
  import java.security.PrivateKey
  import java.security.cert.X509Certificate
  import java.util.concurrent.atomic.AtomicReference

  // Server is the phone's local HTTPS edge: Ktor on the Netty engine, TLS via sslConnector backed by the
  // non-exportable TLS TEE key + issued cert (ServerTls). Fixed loopback port so a renewal restart is
  // transparent (the tunnel splices to it per dial-back).
  class Server(private val port: Int, private val appNonce: String, private val name: String) {
      private class Material(val key: PrivateKey, val chain: Array<X509Certificate>)
      private val material = AtomicReference<Material>()
      // engine is mutated by start/swapIdentity/stop from different threads; @Synchronized serializes them (so
      // two restarts can never double-bind the fixed port) and publishes engine safely. `stopped` prevents a
      // late renewal from resurrecting a torn-down server.
      private var engine: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>? = null
      private var stopped = false

      fun localPort() = port

      @Synchronized
      fun start(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
          if (stopped) return
          material.set(Material(tlsKey, chain)); engine = buildEngine().also { it.start(wait = false) }
      }

      // swapIdentity restarts the embedded server on the SAME fixed port with the new key/chain. Transparent
      // because /data dial-backs are per-connection (no persistent listener connection to preserve).
      @Synchronized
      fun swapIdentity(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
          if (stopped) return
          material.set(Material(tlsKey, chain)); engine?.stop(100, 500)
          engine = buildEngine().also { it.start(wait = false) }
      }

      @Synchronized
      fun stop() { stopped = true; engine?.stop(100, 500); engine = null }

      private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

      private fun buildEngine(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
          val ks = ServerTls.keyStore(material.get().key, material.get().chain)
          return embeddedServer(
              factory = Netty,
              configure = {
                  sslConnector(
                      keyStore = ks, keyAlias = ServerTls.ALIAS,
                      keyStorePassword = { ServerTls.PASSWORD }, privateKeyPassword = { ServerTls.PASSWORD },
                  ) { host = "127.0.0.1"; port = this@Server.port }
              },
              module = {
                  routing {
                      get("/info") {
                          val leaf = material.get().chain[0]
                          val sha = MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
                          call.respondText(
                              JSONObject()
                                  .put("nonce", appNonce)
                                  .put("tls_cert_sha256", hex(sha))
                                  .put("not_before", leaf.notBefore.time)
                                  .put("not_after", leaf.notAfter.time)
                                  .put("name", name)
                                  .put("san", leaf.subjectAlternativeNames?.joinToString(",") { it[1].toString() } ?: "")
                                  .put("issuer", leaf.issuerX500Principal.name)
                                  .toString(),
                              ContentType.Application.Json,
                          )
                      }
                      get("/wait") {
                          val seconds = call.request.queryParameters["seconds"]?.toIntOrNull() ?: 1
                          val rate = 1 shl 20 // ~1 MiB/s
                          val chunk = ByteArray(rate)
                          val alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArray()
                          for (i in chunk.indices) chunk[i] = alpha[i % alpha.size]
                          val md = MessageDigest.getInstance("SHA-256")
                          call.respondBytesWriter {
                              writeStringUtf8("${rate.toLong() * seconds}\n")
                              repeat(seconds) {
                                  md.update(chunk); writeFully(chunk); flush(); delay(1000) // pace ~1 MiB/s
                              }
                              writeStringUtf8("\n" + hex(md.digest()) + "\n")
                          }
                      }
                  }
              },
          )
      }
  }
  ```

**Definition of Done:**
- [ ] Through the tunnel, `/info` returns the expected JSON and `/wait` delivers a byte-exact,
  hash-matching stream over both h2 and h1 (proven in US7).

---

## User Story 5 — [ ] Foreground service, adb command surface, status files, manifest

The app is orchestrated by a long-running foreground service driven over adb and reporting via
app-internal files the test reads with `run-as`.

**Acceptance criteria:**
- [ ] An `enroll` command (adb) carrying `{edgePort, appNonce, pebbleCaPath, enrollHost, controlHost,
  tunnelDomain}` runs enrollment → starts the local server → opens the control connection, then writes the
  status files — `info.json` (`{name, tls_cert_sha256}`) plus a `ready` marker (the assigned name) — or an
  `error` file on failure.
- [ ] A `refresh` command (adb) calls `Enroll.renew(id)` — the manual path has no `RENEW_NUDGE` frame to
  carry a nonce, so `renew` itself mints a fresh nonce via `GET /enroll/nonce` (server-TLS, mirroring
  `client.FetchIssueNonce`) before issuing — and hot-swaps the server cert, then updates the status file
  (new `tls_cert_sha256`), same app-nonce.
- [ ] The service survives between commands; a `stop` command tears everything down.
- [ ] Result/status files are app-internal (`getFilesDir()`), read by the test via `run-as` (debug APK).

### Task 5.1 — [ ] Command receiver (`CommandReceiver.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/CommandReceiver.kt`. The Pebble CA is delivered as an adb-pushed file path (extra
  `pebbleCaPath`); large/binary inputs travel as files, not intent extras.

  ```kotlin
  package com.example.tunnelapp

  import android.content.BroadcastReceiver
  import android.content.Context
  import android.content.Intent
  import android.os.Build

  // CommandReceiver maps `am broadcast -a com.example.tunnelapp.<cmd>` intents (+ string extras) to
  // TunnelService commands, forwarding the extras.
  class CommandReceiver : BroadcastReceiver() {
      override fun onReceive(context: Context, intent: Intent) {
          val command = when (intent.action) {
              "$PKG.enroll" -> "enroll"
              "$PKG.refresh" -> "refresh"
              "$PKG.stop" -> "stop"
              else -> return
          }
          val svc = Intent(context, TunnelService::class.java).apply {
              putExtra("command", command)
              intent.extras?.let { putExtras(it) }
          }
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(svc)
          else context.startService(svc)
      }

      companion object { const val PKG = "com.example.tunnelapp" }
  }
  ```

**Definition of Done:**
- [ ] `am broadcast -a com.example.tunnelapp.<cmd> -n <pkg>/.CommandReceiver -e …` reliably reaches the
  service (the `-f 0x00000020` include-stopped-packages flag is used if a cold receiver needs it; record in
  `## Deviations`).

### Task 5.2 — [ ] Orchestration service (`TunnelService.kt`)

**Actions:**
- [ ] Create `…/tunnelapp/TunnelService.kt`. The `ready` marker is written strictly AFTER the tunnel is
  serving (so the test never races a half-started app). The local server binds a FIXED loopback port
  (shared with the Tunnel). The FGS type (`dataSync`/`specialUse`) is API-dependent — record the chosen
  type + any start-restriction handling in `## Deviations`.

  ```kotlin
  package com.example.tunnelapp

  import android.app.Notification
  import android.app.NotificationChannel
  import android.app.NotificationManager
  import android.app.Service
  import android.content.Intent
  import android.content.pm.ServiceInfo
  import android.os.Build
  import android.os.IBinder
  import org.json.JSONObject
  import java.io.File
  import java.security.MessageDigest

  // TunnelService owns the enrolled Identity, the local Server, and the Tunnel control loop; it is driven by
  // CommandReceiver (adb am broadcast) and reports via app-internal files the test reads with run-as.
  class TunnelService : Service() {
      private val fixedLocalPort = 18080
      private val renewLock = Any() // serializes the two renewal drivers (RENEW_NUDGE + refresh) end to end
      @Volatile private var identity: Identity? = null
      @Volatile private var server: Server? = null
      @Volatile private var tunnel: Tunnel? = null

      override fun onBind(intent: Intent?): IBinder? = null

      override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
          if (Build.VERSION.SDK_INT >= 29) {
              startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
          } else {
              startForeground(1, notification())
          }
          when (intent?.getStringExtra("command")) {
              "enroll" -> Thread { doEnroll(intent) }.start()
              "refresh" -> Thread { doRefresh() }.start()
              "stop" -> Thread { doStop() }.start()
          }
          return START_NOT_STICKY
      }

      private fun doEnroll(intent: Intent) = guarded("enroll") {
          val port = intent.getStringExtra("edgePort")!!.toInt()
          val appNonce = intent.getStringExtra("appNonce")!!
          val trust = Tls.pebbleTrust(intent.getStringExtra("pebbleCaPath")!!)
          val enrollHost = intent.getStringExtra("enrollHost")!!
          val controlHost = intent.getStringExtra("controlHost")!!
          val tunnelDomain = intent.getStringExtra("tunnelDomain")!!
          val id = Enroll.enroll(port, enrollHost, controlHost, tunnelDomain, trust)
          val (tlsKey, tlsChain) = id.tlsCredential()
          val srv = Server(fixedLocalPort, appNonce, id.name).also { it.start(tlsKey, tlsChain) }
          val tun = Tunnel(id.mtlsClient(), controlHost, port, srv::localPort) { nonce ->
              synchronized(renewLock) {
                  Enroll.issue(id, nonce); id.tlsCredential().let { (k, c) -> srv.swapIdentity(k, c) }
              }
          }
          Thread { tun.run() }.apply { isDaemon = true }.start()
          identity = id; server = srv; tunnel = tun
          writeReady(id) // AFTER serving
      }

      private fun doRefresh() = guarded("refresh") {
          val id = identity ?: error("not enrolled")
          synchronized(renewLock) {
              Enroll.renew(id)
              id.tlsCredential().let { (k, c) -> server!!.swapIdentity(k, c) }
          }
          writeReady(id)
      }

      private fun doStop() {
          tunnel?.stop(); server?.stop()
          stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
      }

      private fun guarded(label: String, block: () -> Unit) = try {
          block()
      } catch (t: Throwable) {
          File(filesDir, "error").writeText("$label: $t\n${t.stackTraceToString()}")
      }

      private fun writeReady(id: Identity) {
          val sha = MessageDigest.getInstance("SHA-256").digest(id.publicLeaf().encoded).joinToString("") { "%02x".format(it) }
          File(filesDir, "info.json").writeText(JSONObject().put("name", id.name).put("tls_cert_sha256", sha).toString())
          File(filesDir, "ready").writeText(id.name)
      }

      private fun notification(): Notification {
          val ch = "tunnel"
          (getSystemService(NotificationManager::class.java))
              .createNotificationChannel(NotificationChannel(ch, "tunnel", NotificationManager.IMPORTANCE_LOW))
          return Notification.Builder(this, ch).setContentTitle("tunnel-app")
              .setSmallIcon(android.R.drawable.stat_sys_upload).build()
      }
  }
  ```

**Definition of Done:**
- [ ] The service completes enroll→serve→refresh→stop driven purely over adb, with truthful status files.

### Task 5.3 — [ ] Manifest + permissions

**Actions:**
- [ ] Create `support/tunnel-app/app/src/main/AndroidManifest.xml`. No `usesCleartextTraffic`: the
  `/data`→local-server splice is a raw `Socket` to `127.0.0.1` carrying opaque TLS bytes (not cleartext
  HTTP, so the policy does not apply). The FGS type mirrors `TunnelService` (Task 5.2).

  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.INTERNET" />
      <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
      <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
      <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
      <application android:label="tunnel-app" android:allowBackup="false">
          <service
              android:name=".TunnelService"
              android:exported="false"
              android:foregroundServiceType="dataSync" />
          <receiver android:name=".CommandReceiver" android:exported="true">
              <intent-filter>
                  <action android:name="com.example.tunnelapp.enroll" />
                  <action android:name="com.example.tunnelapp.refresh" />
                  <action android:name="com.example.tunnelapp.stop" />
              </intent-filter>
          </receiver>
      </application>
  </manifest>
  ```

**Definition of Done:**
- [ ] The app installs and the service starts as a foreground service on the device API level without a
  permission/type error.

---

## User Story 6 — [ ] Build tooling + committed fixtures

`make` builds/sign/publishes the app APK + its signer digest, as committed fixtures, alongside (not
replacing) the probe's.

**Acceptance criteria:**
- [ ] `make tunnel-app` builds the debug APK with the local SDK, copies it to
  `fixtures/tunnel-app/tunnel-app.apk`, records `…/tunnel-app.apk.sha256`, and extracts the debug
  signing-cert SHA-256 into `fixtures/tunnel-app/signers.allow`.
- [ ] The three fixtures are committed; the app's Gradle build outputs + `local.properties` are
  gitignored. The existing `attest-probe` target/fixtures are untouched.

### Task 6.1 — [ ] Makefile target + gitignore

**Actions:**
- [ ] Modify `Makefile`: append `tunnel-app` to the `.PHONY` list, and add the target below (reusing the
  `ANDROID_SDK`/`APKSIGNER` vars already defined for `attest-probe`):

  ```make
  tunnel-app:
  	@test -n "$(APKSIGNER)" || { echo "apksigner not found under $(ANDROID_SDK)/build-tools; set ANDROID_HOME"; exit 1; }
  	cd support/tunnel-app && ./gradlew assembleDebug
  	mkdir -p fixtures/tunnel-app
  	cp support/tunnel-app/app/build/outputs/apk/debug/app-debug.apk \
  	    fixtures/tunnel-app/tunnel-app.apk
  	sha256sum fixtures/tunnel-app/tunnel-app.apk | awk '{print $$1}' \
  	    > fixtures/tunnel-app/tunnel-app.apk.sha256
  	{ echo "# Debug signing-cert SHA-256 for the tunnel-app APK (regenerate via 'make tunnel-app')."; \
  	  $(APKSIGNER) verify --print-certs fixtures/tunnel-app/tunnel-app.apk \
  	    | awk -F': ' '/certificate SHA-256 digest/ {print tolower($$NF); exit}'; \
  	} > fixtures/tunnel-app/signers.allow
  ```

- [ ] Modify `.gitignore`: add the block below (ONE entry per line — git has no brace expansion; the three
  `fixtures/tunnel-app/` files ARE committed):

  ```gitignore
  # tunnel-app Gradle build outputs & machine-specific SDK pointer (the built APK fixture under
  # fixtures/tunnel-app/ IS committed — only these are ignored).
  /support/tunnel-app/.gradle/
  /support/tunnel-app/build/
  /support/tunnel-app/app/build/
  /support/tunnel-app/local.properties
  /support/tunnel-app/.idea/
  ```

**Definition of Done:**
- [ ] `make tunnel-app` regenerates all three fixtures; `git status` shows them tracked and no Gradle
  build output staged.

### Task 6.2 — [ ] Build + commit the fixtures

**Actions:**
- [ ] Run `make tunnel-app`; commit `fixtures/tunnel-app/{tunnel-app.apk,tunnel-app.apk.sha256,signers.allow}`.

**Definition of Done:**
- [ ] The committed APK's SHA-256 matches the committed digest, and `signers.allow` is a `#` comment
  header line plus a single lowercase-hex SHA-256 digest (the `attest-probe` format).

---

## User Story 7 — [ ] Real-device end-to-end tunnel test

A `//go:build e2e` test drives the committed app on a real device through the full flow with attestation
ON, asserting the tunnel, the certificate, renewal, and throughput/concurrency over h1 and h2.

**Acceptance criteria:**
- [ ] tunneld is assembled like the existing e2e harness but **attestation ON**: real Google
  `--attest-root-url`/`--attest-status-url`, `--attest-signer-digest-file` = committed
  `fixtures/tunnel-app/signers.allow`, a test identity CA (`--ca-*`, existing `writeCA`), Pebble public
  certs, and **generous `--limit-*`** (`--limit-concurrent` ≥ the test's stream count,
  `--limit-bandwidth` high enough for ~1 MiB/s streams, `--limit-conn-rate` high) so caps/pacing do not
  interfere.
- [ ] The test skips unless exactly one adb device; it `adb reverse`s the edge port, `adb push`es
  Pebble's issuing CA, installs the committed APK (sha256-checked first, generous Play-Protect-aware
  install timeout), and drives enroll → info → refresh → info → `/wait` load, then uninstalls in cleanup.
  It is never wired to CI-with-device.
- [ ] Assertions: `/info` returns the supplied app-nonce; the phone's `<name>.<tunnel-domain>` cert
  validates against Pebble's CA with SAN == `<name>.<tunnel-domain>`, issuer == Pebble, and a sane
  validity window; after `refresh` the nonce is unchanged and `tls_cert_sha256` changed; `/wait` delivers
  a byte-exact, hash-matching stream concurrently over **4 HTTP/1.1 connections** and **4 HTTP/2 streams**.

### Task 7.1 — [ ] Harness config + adb plumbing helpers

**Actions:**
- [ ] Add a new `e2e/tunnel_app_test.go` (`//go:build e2e`). Reuse `startE2EInfra` for the shared containers +
  CA. Start the replica attestation-ON via the EXISTING `startReplica(t, replicaOpts{…})`: `runReplicaOnce`
  already flips `attestOptional = false` and uses the supplied `attestRootURL`/`attestStatusURL`/`attestSignerFile`
  whenever `attestRootURL != ""`, so pass the real Google `attestRootURL`/`attestStatusURL` (the
  `googleAttest*URL` constants already in `device_attestation_test.go`) and `attestSignerFile =
  fixtures/tunnel-app/signers.allow`. `replicaOpts` also needs a `--limit-bandwidth` override so the shared
  per-tunnel `bw:{name}:{dir}` token bucket does not pace the concurrent ~1 MiB/s `/wait` streams — add one
  `bandwidth string` field (mirroring the existing `trafficDay`/`concurrent` overrides; diff below) and pass
  `bandwidth: "100mbit"` (12.5 MB/s ≈ 11.9 MiB/s, above the ≤8 concurrent streams' ~8 MiB/s) with `concurrent: 32` (≥ that
  stream count). No separate replica-start function is added — only the one `replicaOpts` field.

  ```diff
   type replicaOpts struct {
   	acmeDirLE  string
   	trafficDay string
   	concurrent int
  +	bandwidth  string // override --limit-bandwidth; empty = 10mbit
   	attestRootURL    string
   	attestStatusURL  string
   	attestSignerFile string
   }
  ```

  ```diff
   	concurrent := 8
   	if opts.concurrent != 0 {
   		concurrent = opts.concurrent
   	}
  +	bandwidth := "10mbit"
  +	if opts.bandwidth != "" {
  +		bandwidth = opts.bandwidth
  +	}
   	cfg := config.ServeCmd{
   		// ...
  -		LimitConnMinRate: "1kb", LimitConnProtectRate: "1mb", LimitBandwidth: "10mbit",
  +		LimitConnMinRate: "1kb", LimitConnProtectRate: "1mb", LimitBandwidth: bandwidth,
   		// ...
   	}
  ```
  Add helpers: single-device serial (reuse `attestDeviceSerial`), `adb reverse` / `adb reverse --remove`,
  `adb push` the Pebble CA, install (sha256-checked, `adbInstallTimeout`), `am broadcast` command driver,
  and `run-as` status-file readers (reuse the patterns from `device_attestation_test.go`).
- [ ] Modify `internal/tunneltest/containers.go` (shared harness infra — `IssuingRoots *x509.CertPool`
  cannot be serialized back to PEM, so capture the bytes at fetch time; existing callers unaffected):

  ```diff
   type PebbleEnv struct {
   	// ...
   	IssuingRoots *x509.CertPool
  +	// IssuingRootsPEM is the raw PEM of IssuingRoots, adb-pushed to the device so the reference client
  +	// trusts tunneld's enroll/control server certs.
  +	IssuingRootsPEM []byte
   	// ...
   }

   func StartPebble(t *testing.T) *PebbleEnv {
   	// ...
  -	issuingRoots := fetchIssuingRoots(t, minica, mgmtEndpoint)
  +	issuingRoots, issuingRootsPEM := fetchIssuingRoots(t, minica, mgmtEndpoint)
   	return &PebbleEnv{
   		// ...
   		IssuingRoots: issuingRoots,
  +		IssuingRootsPEM: issuingRootsPEM,
   		// ...
   	}
   }

  -func fetchIssuingRoots(t *testing.T, minica []byte, mgmtEndpoint string) *x509.CertPool {
  +func fetchIssuingRoots(t *testing.T, minica []byte, mgmtEndpoint string) (*x509.CertPool, []byte) {
   	// ...
   	rootPEM := httpGet(t, client, "https://"+mgmtEndpoint+"/roots/0")
   	pool := x509.NewCertPool()
   	if !pool.AppendCertsFromPEM(rootPEM) {
   		t.Fatal("pebble: issuing root PEM did not parse")
   	}
  -	return pool
  +	return pool, rootPEM
   }
  ```
- [ ] The `e2e/tunnel_app_test.go` harness (attestation-ON replica-start path, adb-driving helpers, and the
  h1/h2 throughput clients) is TEST code — its shape is the compressed table in Task 7.2 (§3: plans carry no
  full test-function code).
- [ ] Write `inf.pebble.IssuingRootsPEM` to a temp file and `adb push` it to the device as the app's
  trust anchor for tunneld's enroll/control server certs.

**Definition of Done:**
- [ ] The harness boots two-in-process replicas (or one, as needed), reverses the edge port, and installs
  + drives the app over adb.

### Task 7.2 — [ ] The test + throughput clients

**Actions:**
- [ ] Implement the frontend clients that dial `localhost:<edgePort>` with SNI `<name>.<tunnel-domain>`
  and trust the Pebble issuing CA: an **HTTP/1.1** client (multiple connections) and an **HTTP/2** client
  (`golang.org/x/net/http2` `Transport` over one TLS conn, multiple concurrent streams), both via a
  custom `DialTLSContext` (mirror `dialTunnelTLS`).
- [ ] `/wait` verifier: read `<total>\n`, read exactly `total` payload bytes while updating SHA-256, read
  the trailing `\n<hash>\n`, assert the computed hash == the trailer. Run it concurrently (4 conns / 4
  streams, modest `seconds` so total volume stays small) and assert all succeed.

**Test (compressed):**

| Test | Verifies | Setup / notes |
|---|---|---|
| `TestE2E_ReferenceTunnelApp` | A real-device app completes **real Google-attested** two-phase enrollment, serves a Pebble-cert HTTPS endpoint **through the tunnel**, and renews the cert; the tunnel carries byte-exact h1-multi-connection and h2-multi-stream traffic. | Skip unless one adb device. attestation ON (real Google root + committed `signers.allow`), test CA, Pebble, generous limits. `adb reverse` edge port; `adb push` Pebble CA; install committed APK (sha256-checked). Drive `enroll(appNonce,…)` → poll `ready`; frontend `GET /info` (SNI `<name>.example.test`, trust Pebble CA) asserts nonce==appNonce, SAN/issuer/validity, capture F1; drive `refresh` → poll; `GET /info` asserts same nonce, `tls_cert_sha256` != F1; run `/wait` concurrently over 4 h1 conns + 4 h2 streams, assert hash match. `t.Cleanup`: `adb uninstall` + `adb reverse --remove`. Local-only; never CI-with-device. |

**Definition of Done:**
- [ ] With the device connected the test PASSES end-to-end; with no device it SKIPS; a tampered committed
  APK (sha256 mismatch) FAILS clearly.

---

## User Story 8 — [ ] Documentation and ground-up verification

**Acceptance criteria:**
- [ ] `docs/PROJECT.md` + `.claude/rules/project.md` Non-goals note the second on-device app
  (`support/tunnel-app/`) as a **reference phone-client** used by the adb-gated e2e test (the production
  client still lives with the app).
- [ ] `support/tunnel-app/README.md` documents what it is (a complete reference phone client), the build
  (`make tunnel-app`, local SDK + `apksigner`), the driving commands, and the local-only gate — prose only,
  no diagrams.
- [ ] Everything verified from the ground up.

### Task 8.1 — [ ] Documentation

**Actions:**
- [ ] Update the two Non-goals sections (carve-out for the reference client, distinct from the
  attestation probe) and add `support/tunnel-app/README.md`. Keep `docs/PROTOCOL.md` accurate — if the
  reference client clarifies any wire detail, update the doc, do not duplicate it.

**Definition of Done:**
- [ ] Docs are truthful about the reference client and the gate.

### Task 8.2 — [ ] Final ground-up verification (double-check EVERYTHING)

**Actions:**
- [ ] Re-read this plan top to bottom; confirm every task/action + acceptance criterion is implemented.
- [ ] Confirm the app satisfies EACH point of `internal/attest/verify.go` and the full `docs/PROTOCOL.md`
  §2–§4 contract (both CSRs P-256; identity==attested key; TLS CSR == `<name>.<tunnel-domain>`; frames;
  opaque `/data` splice).
- [ ] Run `make tunnel-app` (regenerates fixtures, no SDK download) and confirm the committed digest +
  signer allowlist match.
- [ ] Run the FULL quality gates (`make build vet lint govulncheck test-unit test-integration test-e2e
  test-scripts compose-config` + `make tidy`), capturing logs per the tee rule; `test-e2e` MUST include
  `TestE2E_ReferenceTunnelApp` PASSING with the device connected, AND the existing
  `TestE2E_DeviceAttestation` still passing.
- [ ] Confirm the no-device path SKIPS and nothing wires either device test into CI-with-device.
- [ ] Confirm hygiene: placeholder namespace only, no secrets/real domains/real values, no AI
  attribution, no plan/finding IDs in code or commit messages, Gradle build outputs gitignored, the three
  new fixtures committed, the `attest-probe` app/fixtures untouched, and NO out-of-scope files changed.
- [ ] Confirm every `.kt` under `support/tunnel-app/app/src/main/java/com/example/tunnelapp/` is a production
  class defined by this plan — the four pre-existing files removed in US1 (`MainActivity.kt`,
  `TunnelReference.kt`, `KtorTlsProbe.kt`, `KeystoreProbe.kt`) are gone and nothing else lingers.

**Definition of Done:**
- [ ] All gates pass on the final code; the device test passes with a device and skips without one; the
  ground-up re-read finds zero gaps.

---

## Deviations

- **Task 1.1 versions:** the locally-cached toolchain matched the plan exactly — AGP `8.13.2`, Kotlin
  `2.3.10`, Gradle `8.14.4` (wrapper), `compileSdk`/`targetSdk` `36`, `minSdk 33`. No version substitution
  was needed.
- **Task 6.1 (Makefile):** the `tunnel-app` target carries a descriptive comment header (mirroring the
  existing `attest-probe` target's) — a doc-only addition not shown in the plan's recipe block.
- **Task 7.1 (`e2e/e2e_test.go`):** `replicaOpts`'s attestation fields (`attestRootURL`/`attestStatusURL`/
  `attestSignerFile`) and `runReplicaOnce`'s conditional real-attestation wiring already existed in the
  working tree (uncommitted from earlier exploration); this work committed them and added the planned
  `bandwidth` override on top.
- **Task 7.1 (spike test removed):** a pre-existing untracked `e2e/tunnel_mtls_spike_test.go` (the
  exploration harness) was removed — it is superseded by `e2e/tunnel_app_test.go` and would otherwise
  collide on shared package symbols. The plan assumed a clean tree, so this removal was not a listed action.
- **Task 7.2 (Pebble CA delivery):** the CA is written into the app's OWN internal storage via
  `run-as … base64 -d > files/pebble-ca.pem` (then the enroll broadcast passes that absolute path), rather
  than a bare `adb push`: SELinux blocks an `untrusted_app` from reading `/data/local/tmp`, so a pushed
  file there is unreadable by the app. The `am broadcast` uses `-f 0x00000020`
  (`FLAG_INCLUDE_STOPPED_PACKAGES`) so the freshly-installed (stopped) app's receiver is reached.
- **Task 7.2 (refresh detection):** the test clears `files/ready`+`files/error` before the `refresh`
  broadcast and re-polls `ready`, then asserts the through-tunnel `/info` `tls_cert_sha256` changed — a
  harness detail consistent with US5's status-file design (the plan left test code to the compressed table).
- **Task 5.2 (FGS type):** the foreground service uses `FOREGROUND_SERVICE_TYPE_DATA_SYNC` (`dataSync`) with
  the matching `FOREGROUND_SERVICE_DATA_SYNC` permission, exactly as the plan's code specified.
- **Task 7.2 (FGS background-start):** on Android 12+ a background broadcast receiver may not call
  `startForegroundService()` (`ForegroundServiceStartNotAllowedException`), so the test puts the app on the
  power allowlist (`cmd deviceidle whitelist +<pkg>`, removed in cleanup) before broadcasting — a
  user-installed tunnel app would hold the same battery-optimization exemption. The app code is unchanged;
  the validated exploration used an Activity (implicit foreground grant), which does not hit this.
- **Task 7.2 (client ALPN):** the phone's Ktor/Netty `sslConnector` server closes a just-handshaked
  connection whose client negotiated NO ALPN protocol, so the public Go test clients offer ALPN
  (`http/1.1` for the h1 client, `h2` for the h2 client) — as every real client (browser, OkHttp, curl)
  does. The app/server code is unchanged.
