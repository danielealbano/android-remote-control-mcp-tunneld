package com.example.soakapp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.random.Random

class SoakService : Service() {
    private class Phone(val name: String, val tunnel: Tunnel)

    private val phones = ConcurrentHashMap<Int, Phone>()
    private val lifecycle = Any()
    private val startLock = Any()
    @Volatile private var running = false
    private var runningEnv: String? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        when (intent?.getStringExtra("command")) {
            "start" -> Thread { guarded("start") { doStart(intent) } }.start()
            "stop" -> Thread { guarded("stop") { doStop() } }.start()
            "forget" -> Thread { guarded("forget") { doForget(intent) } }.start()
        }
        return START_NOT_STICKY
    }

    private fun env(intent: Intent) = Env(
        intent.getStringExtra("enrollHost")!!,
        intent.getStringExtra("controlHost")!!,
        intent.getStringExtra("tunnelDomain")!!,
    )

    private fun doStart(intent: Intent) {
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
                if (wakeLock == null) {
                    wakeLock = getSystemService(PowerManager::class.java)
                        .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "soakapp:run")
                        .also { it.acquire() }
                }
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
            writeNames()
            File(filesDir, "ready").writeText("${phones.size}\n")
        }
    }

    private fun bringUp(net: Net, store: PhoneStore, env: Env, i: Int, jitter: Boolean) {
        val saved = store.load(i)
        val id = if (saved != null) {
            restore(net, i, saved)
        } else {
            if (jitter) Thread.sleep(Random.nextLong(0, 5001))
            Keys.deleteAll(Enroll.aliasPrefix(env, i))
            val (fresh, issueNonce) = Enroll.enroll(net, i, env.enrollHost, env.controlHost, env.tunnelDomain)
            store.save(i, fresh)
            Enroll.issue(fresh, issueNonce)
            store.save(i, fresh)
            fresh
        }
        if (id.state().tlsAlias.isEmpty()) {
            Log.i(TAG, "phone $i (${id.name}): saved without a public cert; issuing only, never re-enrolling")
            Enroll.issue(id, null)
            store.save(i, id)
        }
        val (key, chain) = id.tlsCredential()
        val responder = Responder(i).also { it.install(key, chain) }
        val renewLock = Any()
        val tunnel = Tunnel(i, net, id.mtlsClient(), env.controlHost, net.dialBack(env.controlHost, id), responder) { nonce ->
            synchronized(renewLock) {
                Enroll.issue(id, nonce)
                store.save(i, id)
                id.tlsCredential().let { (k, c) -> responder.install(k, c) }
            }
        }
        Thread { tunnel.run() }.apply { isDaemon = true }.start()
        if (!tunnel.awaitBound(60)) {
            tunnel.stop()
            error("phone $i (${id.name}): control stream not bound within 60s")
        }
        phones[i] = Phone(id.name, tunnel)
        Log.i(TAG, "phone $i bound as ${id.name}${if (saved != null) " (resumed)" else ""}")
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

    private fun doForget(intent: Intent) {
        val env = env(intent)
        val root = File(filesDir, "phones")
        synchronized(startLock) {
            listOf("forgotten", "error").forEach { File(filesDir, it).delete() }
            PhoneStore.migrateLegacy(root)
            synchronized(lifecycle) {
                check(phones.isEmpty() || runningEnv != env.key) { "environment ${env.key} is running; stop it before forgetting it" }
            }
            val forgotten = PhoneStore(root, env).forgetAll()
            Keys.deleteAll(Enroll.envAliasPrefix(env))
            Log.i(TAG, "forgot $forgotten saved phones of environment ${env.key}")
            File(filesDir, "forgotten").writeText("$forgotten\n")
        }
    }

    private fun writeNames() {
        val tmp = File(filesDir, "names.txt.tmp")
        tmp.writeText(phones.toSortedMap().values.joinToString("") { it.name + "\n" })
        check(tmp.renameTo(File(filesDir, "names.txt"))) { "could not move names.txt into place" }
    }

    private fun doStop() {
        synchronized(lifecycle) {
            running = false
            phones.values.forEach { it.tunnel.stop() }
            phones.clear()
            runningEnv = null
            wakeLock?.let { if (it.isHeld) it.release() }
            wakeLock = null
        }
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    }

    private fun guarded(label: String, block: () -> Unit) = try {
        block()
    } catch (t: Throwable) {
        Log.e(TAG, "$label failed", t)
        File(filesDir, "error").writeText("$label: $t\n${t.stackTraceToString()}")
    }

    private fun notification(): Notification {
        val ch = "soak"
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(ch, "soak", NotificationManager.IMPORTANCE_LOW))
        return Notification.Builder(this, ch).setContentTitle("soak-app")
            .setSmallIcon(android.R.drawable.stat_sys_upload).build()
    }
}
