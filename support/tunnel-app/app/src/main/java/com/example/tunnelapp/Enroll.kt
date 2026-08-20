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
