package com.example.soakapp

import android.util.Log
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

internal const val TAG = "SoakApp"

class Tunnel(
    private val phone: Int,
    private val net: Net,
    private val client: OkHttpClient,
    private val controlHost: String,
    private val dialBack: DialBack,
    private val responder: Responder,
    private val onRenewNudge: (String) -> Unit,
) {
    private val running = AtomicBoolean(true)
    private val bound = CountDownLatch(1)
    private val renewals = SingleFlight()

    fun awaitBound(seconds: Long): Boolean = bound.await(seconds, TimeUnit.SECONDS)
    fun stop() = running.set(false)

    fun run() {
        var backoff = 200L
        while (running.get()) {
            try { serveControlOnce(); backoff = 200L } catch (t: Throwable) { Log.w(TAG, "phone $phone: control connection ended", t) }
            if (!running.get()) break
            Thread.sleep(backoff); backoff = (backoff * 2).coerceAtMost(5_000L)
        }
    }

    private fun serveControlOnce() {
        var sink: BufferedSink? = null
        val body = duplexBody { sink = it }
        val call = client.newCall(Request.Builder().url(net.url(controlHost, "/api/v1/control")).post(body).build())
        val lastFrameAt = AtomicLong(System.nanoTime())
        val silent = AtomicBoolean(false)
        val watch = ControlWatchdog.watch("phone $phone", call, lastFrameAt, silent)
        try {
            call.execute().use { resp ->
                if (resp.code != 200) {
                    Log.w(TAG, "phone $phone: control connect rejected: ${resp.code}")
                    return
                }
                val s = sink ?: run {
                    Log.w(TAG, "phone $phone: control request body was not opened")
                    return
                }
                bound.countDown()
                val source = resp.body.source()
                try {
                    while (running.get()) {
                        val frame = Frames.read(source) ?: break
                        lastFrameAt.set(System.nanoTime())
                        when (frame.first) {
                            Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                            Frames.OPEN -> JSONObject(String(frame.second)).let { o ->
                                Thread {
                                    try { handleOpen(o) } catch (t: Throwable) { Log.w(TAG, "phone $phone: dial-back handling failed", t) }
                                }.apply { isDaemon = true }.start()
                            }
                            Frames.RENEW_NUDGE -> JSONObject(String(frame.second)).optString("nonce")
                                .takeIf { it.isNotEmpty() }
                                ?.let { n ->
                                    val started = renewals.launch("renewal") {
                                        try { onRenewNudge(n) } catch (t: Throwable) { Log.w(TAG, "phone $phone: renewal failed; keeping the current certs", t) }
                                    }
                                    if (!started) Log.i(TAG, "phone $phone: renewal already in progress; RENEW_NUDGE ignored")
                                }
                                ?: Log.w(TAG, "phone $phone: RENEW_NUDGE without a nonce ignored")
                        }
                    }
                } finally {
                    try { s.close() } catch (t: Throwable) { Log.d(TAG, "phone $phone: control request body close failed", t) }
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
            Log.w(TAG, "phone $phone: invalid OPEN ignored: addr=$addr use_https=$useHttps use_mtls=$useMtls")
            return
        }
        val remote = try {
            dialBack.open(token, addr, useHttps, useMtls)
        } catch (t: Throwable) {
            Log.w(TAG, "phone $phone: dial-back to $addr failed", t)
            return
        }
        try {
            responder.serve(remote, controlHost)
        } catch (t: Throwable) {
            Log.d(TAG, "phone $phone: dial-back session from $addr ended", t)
        }
    }

    private fun duplexBody(capture: (BufferedSink) -> Unit): RequestBody = object : RequestBody() {
        override fun contentType(): MediaType? = null
        override fun isDuplex(): Boolean = true
        override fun writeTo(sink: BufferedSink) { capture(sink) }
    }
}
