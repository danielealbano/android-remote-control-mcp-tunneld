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
import java.util.concurrent.CopyOnWriteArrayList

class SoakService : Service() {
    private class Phone(val server: Server, val tunnel: Tunnel)

    private val basePort = 18100
    private val phones = CopyOnWriteArrayList<Phone>()
    private val lifecycle = Any()
    private val namesLock = Any()
    @Volatile private var running = false
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        when (intent?.getStringExtra("command")) {
            "start" -> Thread { guarded("start") { doStart(intent) } }.start()
            "stop" -> Thread { guarded("stop") { doStop() } }.start()
        }
        return START_NOT_STICKY
    }

    private fun doStart(intent: Intent) {
        val count = intent.getStringExtra("count")!!.toInt()
        require(count in 1..50) { "count must be 1..50, got $count" }
        val spacingSeconds = intent.getStringExtra("spacingSeconds")?.toLong() ?: 65L
        require(spacingSeconds >= 0) { "spacingSeconds must be >= 0" }
        val parallel = intent.getStringExtra("parallel") == "true"
        val enrollHost = intent.getStringExtra("enrollHost")!!
        val controlHost = intent.getStringExtra("controlHost")!!
        val tunnelDomain = intent.getStringExtra("tunnelDomain")!!
        val net = Net(intent.getStringExtra("caPath"), intent.getStringExtra("edgePort")?.toInt())
        synchronized(lifecycle) {
            check(!running) { "already running" }
            running = true
            wakeLock = getSystemService(PowerManager::class.java)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "soakapp:run")
                .also { it.acquire() }
        }
        listOf("names.txt", "ready", "error", "failures.txt").forEach { File(filesDir, it).delete() }
        Keys.deleteAll("soak-")
        if (parallel) {
            val failures = CopyOnWriteArrayList<String>()
            (0 until count).map { i ->
                Thread {
                    try {
                        startPhone(net, i, enrollHost, controlHost, tunnelDomain)
                    } catch (t: Throwable) {
                        Log.e(TAG, "phone $i failed", t)
                        failures.add("phone $i: $t")
                    }
                }.apply { start() }
            }.forEach { it.join() }
            if (failures.isNotEmpty()) File(filesDir, "failures.txt").writeText(failures.joinToString("\n", postfix = "\n"))
        } else {
            for (i in 0 until count) {
                if (!running) return
                if (i > 0) Thread.sleep(spacingSeconds * 1000)
                startPhone(net, i, enrollHost, controlHost, tunnelDomain)
            }
        }
        File(filesDir, "ready").writeText("${phones.size}\n")
    }

    private fun startPhone(net: Net, i: Int, enrollHost: String, controlHost: String, tunnelDomain: String) {
        val id = Enroll.enroll(net, i, enrollHost, controlHost, tunnelDomain)
        val (key, chain) = id.tlsCredential()
        val server = Server(basePort + i).also { it.start(key, chain) }
        val renewLock = Any()
        val tunnel = Tunnel(i, net, id.mtlsClient(), controlHost, server::localPort) { nonce ->
            synchronized(renewLock) {
                Enroll.issue(id, nonce)
                id.tlsCredential().let { (k, c) -> server.swapIdentity(k, c) }
            }
        }
        phones.add(Phone(server, tunnel))
        Thread { tunnel.run() }.apply { isDaemon = true }.start()
        check(tunnel.awaitBound(60)) { "phone $i (${id.name}): control stream not bound within 60s" }
        synchronized(namesLock) { File(filesDir, "names.txt").appendText(id.name + "\n") }
        Log.i(TAG, "phone $i enrolled and bound as ${id.name}")
    }

    private fun doStop() {
        synchronized(lifecycle) {
            running = false
            phones.forEach { it.tunnel.stop(); it.server.stop() }
            phones.clear()
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
