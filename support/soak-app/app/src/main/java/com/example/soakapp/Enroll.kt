package com.example.soakapp

import android.util.Log
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

class Cred(val alias: String, val chain: Array<X509Certificate>, val key: PrivateKey)

class Identity(
    val net: Net,
    val phone: Int,
    val name: String,
    val enrollHost: String,
    val controlHost: String,
    val tunnelDomain: String,
    identityAlias: String,
    tlsAlias: String,
    identityChain: Array<X509Certificate>,
    publicChain: Array<X509Certificate>,
    caId: String,
    generation: Int,
) {
    private val lock = Any()
    val issueLock = Any()
    private var identityAlias = identityAlias
    private var prevIdentityAlias = ""
    private var tlsAlias = tlsAlias
    private var prevTlsAlias = ""
    private var identityChain = identityChain
    private var publicChain = publicChain
    private var caId = caId
    private var generation = generation

    fun mtlsClient(): OkHttpClient = net.mtlsClient(this)

    fun identityCred(): Cred = synchronized(lock) { Cred(identityAlias, identityChain, Keys.privateKey(identityAlias)) }

    fun tlsCredential(): Pair<PrivateKey, Array<X509Certificate>> = synchronized(lock) { Keys.privateKey(tlsAlias) to publicChain }

    fun issueBase(): Triple<String, String, Int> = synchronized(lock) { Triple(name, caId, generation) }

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

class EnrollError(val reason: String, val retryable: Boolean, val retryAfterSec: Long, val status: Int) :
    RuntimeException("enroll: $reason (status $status)")

object Enroll {
    private const val MAX_ISSUE_RETRIES = 3
    private const val MAX_ENROLL_RETRIES = 10

    fun aliasPrefix(phone: Int) = "soak-$phone-"

    fun enroll(net: Net, phone: Int, enrollHost: String, controlHost: String, tunnelDomain: String): Identity {
        var attempt = 0
        while (true) {
            try {
                return enrollOnce(net, phone, enrollHost, controlHost, tunnelDomain)
            } catch (e: EnrollError) {
                if (!e.retryable || attempt++ >= MAX_ENROLL_RETRIES) throw e
                Log.w(TAG, "phone $phone: enrollment refused (${e.reason}), retrying in ${e.retryAfterSec}s")
                Thread.sleep(e.retryAfterSec.coerceAtLeast(1) * 1000)
            } catch (e: IOException) {
                if (attempt++ >= MAX_ENROLL_RETRIES) throw e
                Log.w(TAG, "phone $phone: enrollment network error, retrying in 2s", e)
                Thread.sleep(2000)
            }
        }
    }

    private fun enrollOnce(net: Net, phone: Int, enrollHost: String, controlHost: String, tunnelDomain: String): Identity {
        val server = net.serverClient()
        val nonce = getJson(server, net.url(enrollHost, "/api/v1/enroll/nonce")).getString("nonce")
        val idAlias = "${aliasPrefix(phone)}identity-0"
        Keys.generateEcKey(idAlias, Keys.hexToBytes(nonce))
        val body = JSONObject()
            .put("nonce", nonce)
            .put("attestation_chain", Keys.attestationChainPem(idAlias))
            .put("identity_csr", Csr.identityCsr(Keys.privateKey(idAlias), Keys.publicKey(idAlias)))
        val (status, resp) = postJson(server, net.url(enrollHost, "/api/v1/enroll"), body.toString())
        if (status != 200) fail(status, resp)
        val r = JSONObject(resp)
        val id = Identity(
            net, phone, r.getString("name"), enrollHost, controlHost, tunnelDomain,
            idAlias, "", parseChain(r.getString("identity_cert")), emptyArray(), "", 0,
        )
        issue(id, r.getString("issue_nonce"))
        return id
    }

    fun issue(id: Identity, nonce: String) {
        synchronized(id.issueLock) {
            var attempt = 0
            var n = nonce
            while (true) {
                try { issueOnce(id, n); return } catch (e: EnrollError) {
                    if (!e.retryable || attempt++ >= MAX_ISSUE_RETRIES) throw e
                    Thread.sleep(e.retryAfterSec.coerceAtLeast(1) * 1000)
                    n = getJson(id.net.serverClient(), id.net.url(id.enrollHost, "/api/v1/enroll/nonce")).getString("nonce")
                }
            }
        }
    }

    private fun issueOnce(id: Identity, nonce: String) {
        val base = id.issueBase()
        val gen = base.third + 1
        val nextId = "${aliasPrefix(id.phone)}identity-$gen"
        val nextTls = "${aliasPrefix(id.phone)}tls-$gen"
        Keys.generateEcKey(nextId, Keys.hexToBytes(nonce))
        Keys.generateEcKey(nextTls)
        val (idChain, pubChain, ca) = try {
            val fqdn = "${id.name}.${id.tunnelDomain}"
            val body = JSONObject()
                .put("nonce", nonce)
                .put("attestation_chain", Keys.attestationChainPem(nextId))
                .put("identity_csr", Csr.identityCsr(Keys.privateKey(nextId), Keys.publicKey(nextId)))
                .put("tls_csr", Csr.tlsCsr(Keys.privateKey(nextTls), Keys.publicKey(nextTls), fqdn))
            val (status, resp) = postJson(id.mtlsClient(), id.net.url(id.controlHost, "/api/v1/issue"), body.toString())
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

    private fun fail(status: Int, resp: String): Nothing {
        val r = try {
            JSONObject(resp)
        } catch (t: Throwable) {
            Log.w(TAG, "undecodable error body (status $status)", t)
            JSONObject()
        }
        throw EnrollError(
            r.optString("reason", "http_$status"), r.optBoolean("retryable", false),
            r.optLong("retry_after_seconds", 0), status,
        )
    }

    private fun getJson(client: OkHttpClient, url: String): JSONObject {
        client.newCall(Request.Builder().url(url).get().build()).execute().use { resp ->
            val b = resp.body.string()
            if (resp.code != 200) fail(resp.code, b)
            return JSONObject(b)
        }
    }

    private fun postJson(client: OkHttpClient, url: String, json: String): Pair<Int, String> {
        val req = Request.Builder().url(url).post(json.toRequestBody("application/json".toMediaType())).build()
        client.newBuilder().readTimeout(60, TimeUnit.SECONDS).build()
            .newCall(req).execute().use { resp -> return resp.code to resp.body.string() }
    }

    private fun parseChain(pem: String): Array<X509Certificate> =
        CertificateFactory.getInstance("X.509").generateCertificates(ByteArrayInputStream(pem.toByteArray()))
            .map { it as X509Certificate }.toTypedArray()
}
