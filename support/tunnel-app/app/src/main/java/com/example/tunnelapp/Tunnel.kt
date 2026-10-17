package com.example.tunnelapp

import android.util.Log
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

internal const val TAG = "TunnelApp"

// Tunnel maintains the outbound mTLS HTTP/2 control connection.
class Tunnel(
    client: OkHttpClient,   // the identity-mTLS client (Identity.mtlsClient())
    private val controlHost: String,
    private val port: Int,
    private val dialBack: DialBack,
    private val localServerPort: () -> Int, // lambda defers reading the server's fixed loopback port
    private val stats: Stats,
    private val onRenewNudge: (String) -> Unit,
) {
    private val running = AtomicBoolean(true)
    private val bound = CountDownLatch(1)
    private val renewals = SingleFlight()
    private val node = AtomicReference("unknown")
    private var everBound = false
    private val client = client.newBuilder().addNetworkInterceptor { chain ->
        chain.connection()?.route()?.socketAddress?.address?.hostAddress?.let { node.set(it) }
        chain.proceed(chain.request())
    }.build()

    fun awaitBound(seconds: Long): Boolean = bound.await(seconds, TimeUnit.SECONDS)
    fun stop() = running.set(false)

    // run opens /api/v1/control and services it until stopped; a torn stream reconnects with backoff.
    fun run() {
        var backoff = 200L
        while (running.get()) {
            try { serveControlOnce(); backoff = 200L } catch (t: Throwable) { Log.w(TAG, "control connection ended", t) }
            if (!running.get()) break
            stats.disconnected()
            Thread.sleep(backoff); backoff = (backoff * 2).coerceAtMost(5_000L)
        }
    }

    private fun serveControlOnce() {
        var sink: BufferedSink? = null
        val body = duplexBody { sink = it }
        val call = client.newCall(Request.Builder().url("https://$controlHost:$port/api/v1/control").post(body).build())
        val lastFrameAt = AtomicLong(System.nanoTime())
        val silent = AtomicBoolean(false)
        val watch = ControlWatchdog.watch("control", call, lastFrameAt, silent)
        try {
            call.execute().use { resp ->
                if (resp.code != 200) {
                    Log.w(TAG, "control connect rejected: ${resp.code}")
                    return
                }
                val s = sink ?: run {
                    Log.w(TAG, "control request body was not opened")
                    return
                }
                bound.countDown()
                if (running.get()) stats.connected(node.get(), everBound)
                everBound = true
                val source = resp.body.source()
                try {
                    while (running.get()) {
                        val frame = Frames.read(source) ?: break
                        lastFrameAt.set(System.nanoTime())
                        when (frame.first) {
                            Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                            Frames.OPEN -> JSONObject(String(frame.second)).let { o ->
                                Thread {
                                    try { handleOpen(o) } catch (t: Throwable) { Log.w(TAG, "dial-back handling failed", t) }
                                }.apply { isDaemon = true }.start()
                            }
                            Frames.RENEW_NUDGE -> JSONObject(String(frame.second)).optString("nonce")
                                .takeIf { it.isNotEmpty() }
                                ?.let { n ->
                                    val started = renewals.launch("renewal") {
                                        try {
                                            onRenewNudge(n)
                                        } catch (t: Throwable) {
                                            Log.w(TAG, "renewal failed; keeping the current certs", t)
                                            stats.issueFailed("renewal failed: $t")
                                        }
                                    }
                                    if (!started) Log.i(TAG, "renewal already in progress; RENEW_NUDGE ignored")
                                }
                                ?: Log.w(TAG, "RENEW_NUDGE without a nonce ignored")
                        }
                    }
                } finally {
                    try { s.close() } catch (t: Throwable) { Log.d(TAG, "control request body close failed", t) }
                }
            }
        } finally {
            watch.cancel(false)
            if (silent.get()) client.connectionPool.evictAll()
        }
    }

    private fun handleOpen(open: JSONObject) {
        val token = open.optString("token")
        val addr = open.optString("addr")
        val useHttps = open.optBoolean("use_https")
        val useMtls = open.optBoolean("use_mtls")
        if (token.isEmpty() || addr.isEmpty() || (useMtls && !useHttps)) {
            Log.w(TAG, "invalid OPEN ignored: addr=$addr use_https=$useHttps use_mtls=$useMtls")
            return
        }
        val local = try {
            LocalConnect.open(localServerPort())
        } catch (t: Throwable) {
            Log.w(TAG, "local server unreachable for a dial-back to $addr", t)
            stats.error("local server unreachable for a dial-back to $addr: $t")
            return
        }
        val remote = try {
            dialBack.open(token, addr, useHttps, useMtls)
        } catch (t: Throwable) {
            Log.w(TAG, "dial-back to $addr failed", t)
            stats.error("dial-back to $addr failed: $t")
            try { local.close() } catch (c: Throwable) { Log.d(TAG, "local socket close failed", c) }
            return
        }
        stats.connection()
        splice(local, remote)
    }

    private fun splice(local: Socket, remote: DialBack.Conn) {
        val closed = AtomicBoolean(false)
        val closeBoth = {
            if (closed.compareAndSet(false, true)) {
                try { local.close() } catch (t: Throwable) { Log.d(TAG, "local socket close failed", t) }
                try { remote.socket.close() } catch (t: Throwable) { Log.d(TAG, "dial-back socket close failed", t) }
            }
        }
        val up = Thread { copy({ local.getInputStream() }, { remote.socket.getOutputStream() }, "upstream", stats::bytesOut); closeBoth() }
            .apply { isDaemon = true; start() }
        copy({ remote.input }, { local.getOutputStream() }, "downstream", stats::bytesIn)
        closeBoth()
        up.join()
    }

    private fun copy(source: () -> InputStream, sink: () -> OutputStream, dir: String, counted: (Int) -> Unit) {
        try {
            val src = source()
            val dst = sink()
            val buf = ByteArray(16384)
            while (true) {
                val n = src.read(buf)
                if (n < 0) break
                dst.write(buf, 0, n)
                dst.flush()
                counted(n)
            }
        } catch (t: Throwable) {
            Log.d(TAG, "$dir copy ended", t)
        }
    }

    private fun duplexBody(capture: (BufferedSink) -> Unit): RequestBody = object : RequestBody() {
        override fun contentType(): MediaType? = null
        override fun isDuplex(): Boolean = true
        override fun writeTo(sink: BufferedSink) { capture(sink) } // capture + return; drive after execute()
    }
}
