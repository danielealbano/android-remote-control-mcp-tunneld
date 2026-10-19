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
    private val gate = RenewGate()
    @Volatile private var identity: Identity? = null
    @Volatile private var store: IdentityStore? = null
    @Volatile private var server: Server? = null
    @Volatile private var tunnel: Tunnel? = null
    private val busy = AtomicInteger()

    fun active(): Boolean = tunnel != null || busy.get() > 0

    fun command(filesDir: File, intent: Intent) {
        val work: () -> Unit = when (intent.getStringExtra("command")) {
            "enroll" -> { { doEnroll(filesDir, intent) } }
            "refresh" -> { { doRefresh(filesDir) } }
            "forget" -> { { guarded(filesDir, "forget") { doForget(filesDir, intent) } } }
            "stop" -> { { guarded(filesDir, "stop") { doStop() } } }
            else -> return
        }
        busy.incrementAndGet()
        Thread { try { work() } finally { busy.decrementAndGet() } }.start()
    }

    private fun env(intent: Intent) = Env(
        intent.getStringExtra("enrollHost")!!,
        intent.getStringExtra("controlHost")!!,
        intent.getStringExtra("tunnelDomain")!!,
    )

    private fun doEnroll(filesDir: File, intent: Intent) = guarded(filesDir, "enroll") {
        check(tunnel == null) { "the tunnel is already running; stop it first" }
        val appNonce = intent.getStringExtra("appNonce")!!
        val env = env(intent)
        val net = Net(intent.getStringExtra("caPath"), intent.getStringExtra("edgePort")?.toInt())
        val st = IdentityStore(File(filesDir, "identity"), env)
        val saved = st.load()
        val id = if (saved != null) {
            restore(net, saved)
        } else {
            Keys.deleteAll(Enroll.envAliasPrefix(env))
            val (fresh, issueNonce) = try {
                Enroll.enroll(net, env.enrollHost, env.controlHost, env.tunnelDomain)
            } catch (t: Throwable) {
                stats.enrollFailed("enroll: $t")
                throw t
            }
            st.save(fresh)
            issueAndSave(st, fresh, issueNonce)
            fresh
        }
        if (id.state().tlsAlias.isEmpty()) {
            Log.i(TAG, "saved identity ${id.name} has no public cert; issuing only, never re-enrolling")
            issueAndSave(st, id, null)
        }
        installed(id)
        val (tlsKey, tlsChain) = id.tlsCredential()
        val srv = Server(FIXED_LOCAL_PORT, appNonce, id.name, stats).also { it.start(tlsKey, tlsChain) }
        val tun = Tunnel(id.mtlsClient(), net, env.controlHost, net.dialBack(env.controlHost, id), srv::localPort, stats) { nonce ->
            synchronized(renewLock) {
                try {
                    gate.renewal(id.name, { st.holds(id) }, { attempt -> Enroll.issue(id, nonce, attempt) }) {
                        st.save(id)
                        id.tlsCredential().let { (k, c) -> srv.swapIdentity(k, c) }
                        stats.renewed()
                        installed(id)
                    }
                } catch (f: ForgottenIdentity) {
                    Log.i(TAG, "${f.message}; renewal skipped")
                }
            }
        }
        Thread { tun.run() }.apply { isDaemon = true }.start()
        identity = id; store = st; server = srv; tunnel = tun
        check(tun.awaitBound(60)) { "control stream not bound within 60s" }
        writeReady(filesDir, id) // AFTER serving
    }

    private fun issueAndSave(st: IdentityStore, id: Identity, nonce: String?) {
        try {
            Enroll.issue(id, nonce)
        } catch (t: Throwable) {
            stats.issueFailed("issue: $t")
            throw t
        }
        st.save(id)
    }

    private fun restore(net: Net, saved: IdentityStore.Saved): Identity {
        val s = saved.state
        try {
            Keys.privateKey(s.identityAlias)
            if (s.tlsAlias.isNotEmpty()) Keys.privateKey(s.tlsAlias)
        } catch (t: Throwable) {
            throw IllegalStateException("saved identity ${saved.name} has no usable keys; it is kept, not replaced", t)
        }
        Log.i(TAG, "resuming saved identity ${saved.name}")
        return Identity(
            net, saved.name, saved.enrollHost, saved.controlHost, saved.tunnelDomain,
            s.identityAlias, s.tlsAlias, s.identityChain, s.publicChain, s.caId, s.generation,
            s.prevIdentityAlias, s.prevTlsAlias,
        )
    }

    private fun doRefresh(filesDir: File) = guarded(filesDir, "refresh") {
        val id = identity ?: error("not enrolled")
        val st = store ?: error("not enrolled")
        val srv = server ?: error("not enrolled")
        synchronized(renewLock) {
            gate.renewal(id.name, { st.holds(id) }, { attempt ->
                try {
                    Enroll.renew(id, attempt)
                } catch (t: Throwable) {
                    if (t !is ForgottenIdentity) stats.issueFailed("refresh: $t")
                    throw t
                }
            }) {
                st.save(id)
                id.tlsCredential().let { (k, c) -> srv.swapIdentity(k, c) }
                stats.renewed()
                installed(id)
                writeReady(filesDir, id)
            }
        }
    }

    private fun doStop() {
        tunnel?.stop(); server?.stop()
        tunnel = null; server = null; identity = null; store = null
        stats.stopped()
    }

    private fun doForget(filesDir: File, intent: Intent) {
        File(filesDir, "forgotten").delete()
        check(tunnel == null) { "the tunnel is running; stop it before forgetting its identity" }
        val env = env(intent)
        val forgotten = gate.forget { IdentityStore(File(filesDir, "identity"), env).forget().also { Keys.deleteAll(Enroll.envAliasPrefix(env)) } }
        Log.i(TAG, "forgot the saved identity of environment ${env.key}: $forgotten")
        File(filesDir, "forgotten").writeText(if (forgotten) "1\n" else "0\n")
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
