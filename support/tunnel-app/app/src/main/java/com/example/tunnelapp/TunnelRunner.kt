package com.example.tunnelapp

import android.content.Intent
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger

object TunnelRunner {
    private const val FIXED_LOCAL_PORT = 18080
    val stats = Stats()
    private val renewLock = Any() // serializes the two renewal drivers (RENEW_NUDGE + refresh) end to end
    @Volatile private var identity: Identity? = null
    @Volatile private var server: Server? = null
    @Volatile private var tunnel: Tunnel? = null
    private val busy = AtomicInteger()

    fun active(): Boolean = tunnel != null || busy.get() > 0

    fun command(filesDir: File, intent: Intent) {
        val work: () -> Unit = when (intent.getStringExtra("command")) {
            "enroll" -> { { doEnroll(filesDir, intent) } }
            "refresh" -> { { doRefresh(filesDir) } }
            "stop" -> { { guarded(filesDir, "stop") { doStop() } } }
            else -> return
        }
        busy.incrementAndGet()
        Thread { try { work() } finally { busy.decrementAndGet() } }.start()
    }

    private fun doEnroll(filesDir: File, intent: Intent) = guarded(filesDir, "enroll") {
        val port = intent.getStringExtra("edgePort")!!.toInt()
        val appNonce = intent.getStringExtra("appNonce")!!
        val trust = Tls.pebbleTrust(intent.getStringExtra("pebbleCaPath")!!)
        val enrollHost = intent.getStringExtra("enrollHost")!!
        val controlHost = intent.getStringExtra("controlHost")!!
        val tunnelDomain = intent.getStringExtra("tunnelDomain")!!
        val (id, issueNonce) = try {
            Enroll.enroll(port, enrollHost, controlHost, tunnelDomain, trust)
        } catch (t: Throwable) {
            stats.enrollFailed("enroll: $t")
            throw t
        }
        try {
            Enroll.issue(id, issueNonce)
        } catch (t: Throwable) {
            stats.issueFailed("issue: $t")
            throw t
        }
        installed(id)
        val (tlsKey, tlsChain) = id.tlsCredential()
        val srv = Server(FIXED_LOCAL_PORT, appNonce, id.name, stats).also { it.start(tlsKey, tlsChain) }
        val dialBack = DialBack(controlHost, Tls.sslContext(Tls.DynamicIdentityKeyManager(id), trust), Tls.sslContext(null, trust))
        val tun = Tunnel(id.mtlsClient(), controlHost, port, dialBack, srv::localPort, stats) { nonce ->
            synchronized(renewLock) {
                Enroll.issue(id, nonce); id.tlsCredential().let { (k, c) -> srv.swapIdentity(k, c) }
                stats.renewed()
                installed(id)
            }
        }
        Thread { tun.run() }.apply { isDaemon = true }.start()
        identity = id; server = srv; tunnel = tun
        check(tun.awaitBound(60)) { "control stream not bound within 60s" }
        writeReady(filesDir, id) // AFTER serving
    }

    private fun doRefresh(filesDir: File) = guarded(filesDir, "refresh") {
        val id = identity ?: error("not enrolled")
        synchronized(renewLock) {
            try {
                Enroll.renew(id)
            } catch (t: Throwable) {
                stats.issueFailed("refresh: $t")
                throw t
            }
            id.tlsCredential().let { (k, c) -> server!!.swapIdentity(k, c) }
            stats.renewed()
            installed(id)
        }
        writeReady(filesDir, id)
    }

    private fun doStop() {
        tunnel?.stop(); server?.stop()
        tunnel = null; server = null
        stats.stopped()
    }

    private fun installed(id: Identity) {
        stats.certificate(id.name, id.issueBase().second, id.publicLeaf().notAfter.time)
    }

    private fun guarded(filesDir: File, label: String, block: () -> Unit) = try {
        block()
    } catch (t: Throwable) {
        Log.e(TAG, "$label failed", t)
        stats.commandFailed("$label: $t")
        File(filesDir, "error").writeText("$label: $t\n${t.stackTraceToString()}")
    }

    private fun writeReady(filesDir: File, id: Identity) {
        val sha = MessageDigest.getInstance("SHA-256").digest(id.publicLeaf().encoded).joinToString("") { "%02x".format(it) }
        File(filesDir, "info.json").writeText(JSONObject().put("name", id.name).put("tls_cert_sha256", sha).toString())
        File(filesDir, "ready").writeText(id.name)
    }
}
