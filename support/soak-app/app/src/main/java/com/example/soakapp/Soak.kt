package com.example.soakapp

import android.content.Intent
import android.util.Log
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

object Soak {
    private class Phone(val name: String, val tunnel: Tunnel)

    val stats = Stats()
    private val phones = ConcurrentHashMap<Int, Phone>()
    private val lifecycle = Any()
    private val startLock = Any()
    private val starting = AtomicInteger()
    private val gate = RenewGate()
    @Volatile private var running = false
    private var runningEnv: String? = null

    fun active(): Boolean = phones.isNotEmpty() || starting.get() > 0

    fun state(): String = when {
        starting.get() > 0 -> "starting"
        phones.isNotEmpty() -> "running"
        else -> "stopped"
    }

    fun phoneCount(): Int = phones.size

    fun command(filesDir: File, intent: Intent) {
        when (intent.getStringExtra("command")) {
            "start" -> {
                starting.incrementAndGet()
                Thread { try { guarded(filesDir, "start") { doStart(filesDir, intent) } } finally { starting.decrementAndGet() } }.start()
            }
            "stop" -> Thread { guarded(filesDir, "stop") { doStop() } }.start()
            "forget" -> Thread { guarded(filesDir, "forget") { doForget(filesDir, intent) } }.start()
        }
    }

    private fun env(intent: Intent) = Env(
        intent.getStringExtra("enrollHost")!!,
        intent.getStringExtra("controlHost")!!,
        intent.getStringExtra("tunnelDomain")!!,
    )

    private fun doStart(filesDir: File, intent: Intent) {
        val count = intent.getStringExtra("count")!!.toInt()
        require(count >= 1) { "count must be >= 1, got $count" }
        val spacingSeconds = intent.getStringExtra("spacingSeconds")?.toLong() ?: 65L
        require(spacingSeconds >= 0) { "spacingSeconds must be >= 0" }
        val parallel = intent.getStringExtra("parallel") == "true"
        val env = env(intent)
        val net = Net(intent.getStringExtra("caPath"), intent.getStringExtra("edgePort")?.toInt())
        val root = File(filesDir, "phones")
        synchronized(startLock) {
            listOf("ready", "error", "failures.txt").forEach { File(filesDir, it).delete() }
            PhoneStore.migrateLegacy(root)
            val store = PhoneStore(root, env)
            synchronized(lifecycle) {
                check(phones.isEmpty() || runningEnv == env.key) {
                    "phones of environment $runningEnv are running; stop them before starting ${env.key}"
                }
                running = true
                runningEnv = env.key
            }
            val todo = (0 until count).filter { !phones.containsKey(it) }
            val failures = CopyOnWriteArrayList<String>()
            val bring = { i: Int, jitter: Boolean ->
                try {
                    bringUp(net, store, env, i, jitter)
                } catch (t: Throwable) {
                    Log.e(TAG, "phone $i failed", t)
                    failures.add("phone $i: $t")
                }
            }
            if (parallel) {
                todo.map { i -> Thread { bring(i, true) }.apply { start() } }.forEach { it.join() }
            } else {
                todo.forEachIndexed { n, i ->
                    if (!running) return
                    if (n > 0) Thread.sleep(spacingSeconds * 1000)
                    bring(i, false)
                }
            }
            if (failures.isNotEmpty()) File(filesDir, "failures.txt").writeText(failures.joinToString("\n", postfix = "\n"))
            writeNames(filesDir)
            File(filesDir, "ready").writeText("${phones.size}\n")
        }
    }

    private fun bringUp(net: Net, store: PhoneStore, env: Env, i: Int, jitter: Boolean) {
        val saved = store.load(i)
        val id = if (saved != null) {
            restore(net, i, saved).also { stats.resumed() }
        } else {
            if (jitter) Thread.sleep(Random.nextLong(0, 5001))
            Keys.deleteAll(Enroll.aliasPrefix(env, i))
            val (fresh, issueNonce) = failing(i, stats::enrollFailed) { Enroll.enroll(net, i, env.enrollHost, env.controlHost, env.tunnelDomain) }
            stats.enrolled()
            store.save(i, fresh)
            failing(i, stats::issueFailed) { Enroll.issue(fresh, issueNonce) }
            stats.issued(fresh.state().caId)
            store.save(i, fresh)
            fresh
        }
        if (id.state().tlsAlias.isEmpty()) {
            Log.i(TAG, "phone $i (${id.name}): saved without a public cert; issuing only, never re-enrolling")
            failing(i, stats::issueFailed) { Enroll.issue(id, null) }
            stats.issued(id.state().caId)
            store.save(i, id)
        }
        val (key, chain) = id.tlsCredential()
        val responder = Responder(i, stats).also { it.install(key, chain) }
        val renewLock = Any()
        val tunnel = Tunnel(i, net, id.mtlsClient(), env.controlHost, net.dialBack(env.controlHost, id), responder, stats) { nonce ->
            synchronized(renewLock) {
                try {
                    gate.renewal(id.name, { store.holds(i, id) }, { attempt -> Enroll.issue(id, nonce, attempt) }) {
                        stats.renewed(id.state().caId)
                        store.save(i, id)
                        id.tlsCredential().let { (k, c) -> responder.install(k, c) }
                    }
                } catch (f: ForgottenIdentity) {
                    Log.i(TAG, "phone $i: ${f.message}; renewal skipped")
                }
            }
        }
        Thread { tunnel.run() }.apply { isDaemon = true }.start()
        if (!tunnel.awaitBound(60)) {
            tunnel.stop()
            stats.removed(i)
            error("phone $i (${id.name}): control stream not bound within 60s")
        }
        phones[i] = Phone(id.name, tunnel)
        Log.i(TAG, "phone $i bound as ${id.name}${if (saved != null) " (resumed)" else ""}")
    }

    private fun <T> failing(phone: Int, record: (String) -> Unit, block: () -> T): T = try {
        block()
    } catch (t: Throwable) {
        record("phone $phone: $t")
        throw t
    }

    private fun restore(net: Net, i: Int, saved: PhoneStore.Saved): Identity {
        val s = saved.state
        try {
            Keys.privateKey(s.identityAlias)
            if (s.tlsAlias.isNotEmpty()) Keys.privateKey(s.tlsAlias)
        } catch (t: Throwable) {
            throw IllegalStateException("phone $i: saved identity ${saved.name} has no usable keys; it is kept, not replaced", t)
        }
        return Identity(
            net, i, saved.name, saved.enrollHost, saved.controlHost, saved.tunnelDomain,
            s.identityAlias, s.tlsAlias, s.identityChain, s.publicChain, s.caId, s.generation,
            s.prevIdentityAlias, s.prevTlsAlias,
        )
    }

    private fun doForget(filesDir: File, intent: Intent) {
        val env = env(intent)
        val root = File(filesDir, "phones")
        synchronized(startLock) {
            listOf("forgotten", "error").forEach { File(filesDir, it).delete() }
            PhoneStore.migrateLegacy(root)
            synchronized(lifecycle) {
                check(phones.isEmpty() || runningEnv != env.key) { "environment ${env.key} is running; stop it before forgetting it" }
            }
            val forgotten = gate.forget { PhoneStore(root, env).forgetAll().also { Keys.deleteAll(Enroll.envAliasPrefix(env)) } }
            Log.i(TAG, "forgot $forgotten saved phones of environment ${env.key}")
            File(filesDir, "forgotten").writeText("$forgotten\n")
        }
    }

    private fun writeNames(filesDir: File) {
        val tmp = File(filesDir, "names.txt.tmp")
        tmp.writeText(phones.toSortedMap().values.joinToString("") { it.name + "\n" })
        check(tmp.renameTo(File(filesDir, "names.txt"))) { "could not move names.txt into place" }
    }

    private fun doStop() {
        synchronized(lifecycle) {
            running = false
            phones.forEach { (i, p) ->
                p.tunnel.stop()
                stats.removed(i)
            }
            phones.clear()
            runningEnv = null
        }
    }

    private fun guarded(filesDir: File, label: String, block: () -> Unit) = try {
        block()
    } catch (t: Throwable) {
        Log.e(TAG, "$label failed", t)
        stats.commandFailed("$label: $t")
        File(filesDir, "error").writeText("$label: $t\n${t.stackTraceToString()}")
    }
}
