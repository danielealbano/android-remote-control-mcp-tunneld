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
