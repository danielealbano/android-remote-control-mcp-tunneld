package com.example.soakapp

import android.util.Log
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import org.json.JSONObject
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal const val TAG = "SoakApp"

class Tunnel(
    private val phone: Int,
    private val net: Net,
    private val client: OkHttpClient,
    private val controlHost: String,
    private val localServerPort: () -> Int,
    private val onRenewNudge: (String) -> Unit,
) {
    private val running = AtomicBoolean(true)
    private val bound = CountDownLatch(1)

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
        client.newCall(Request.Builder().url(net.url(controlHost, "/api/v1/control")).post(body).build())
            .execute().use { resp ->
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
                        when (frame.first) {
                            Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                            Frames.OPEN -> JSONObject(String(frame.second)).optString("stream_id")
                                .takeIf { it.isNotEmpty() }
                                ?.let { id -> Thread { handleOpen(id) }.apply { isDaemon = true }.start() }
                                ?: Log.w(TAG, "phone $phone: OPEN without a stream_id ignored")
                            Frames.RENEW_NUDGE -> JSONObject(String(frame.second)).optString("nonce")
                                .takeIf { it.isNotEmpty() }
                                ?.let { n ->
                                    Thread {
                                        try { onRenewNudge(n) } catch (t: Throwable) { Log.w(TAG, "phone $phone: renewal failed; keeping the current certs", t) }
                                    }.apply { isDaemon = true }.start()
                                }
                                ?: Log.w(TAG, "phone $phone: RENEW_NUDGE without a nonce ignored")
                        }
                    }
                } finally {
                    try { s.close() } catch (t: Throwable) { Log.d(TAG, "phone $phone: control request body close failed", t) }
                }
            }
    }

    private fun handleOpen(streamId: String) {
        val local = try {
            Socket("127.0.0.1", localServerPort())
        } catch (t: Throwable) {
            Log.w(TAG, "phone $phone: local server unreachable for stream $streamId", t)
            return
        }
        try {
            var sink: BufferedSink? = null
            val body = duplexBody { sink = it }
            client.newCall(
                Request.Builder().url(net.url(controlHost, "/api/v1/data"))
                    .addHeader("X-Stream-Id", streamId).post(body).build(),
            ).execute().use { resp ->
                if (resp.code != 200) {
                    Log.w(TAG, "phone $phone: dial-back for stream $streamId refused: ${resp.code}")
                    return
                }
                val s = sink ?: run {
                    Log.w(TAG, "phone $phone: data request body was not opened for stream $streamId")
                    return
                }
                val up = Thread {
                    try {
                        val buf = ByteArray(16384); val ins = local.getInputStream()
                        while (true) { val n = ins.read(buf); if (n < 0) break; s.write(buf, 0, n); s.flush() }
                    } catch (t: Throwable) {
                        Log.d(TAG, "phone $phone: stream $streamId upstream copy ended", t)
                    } finally {
                        try { s.close() } catch (t: Throwable) { Log.d(TAG, "phone $phone: stream $streamId body close failed", t) }
                    }
                }.apply { isDaemon = true }
                up.start()
                val out = local.getOutputStream(); val src = resp.body.byteStream(); val buf = ByteArray(16384)
                while (true) { val n = src.read(buf); if (n < 0) break; out.write(buf, 0, n); out.flush() }
                up.join(5000)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "phone $phone: stream $streamId ended with an error", t)
        } finally {
            try { local.close() } catch (t: Throwable) { Log.d(TAG, "phone $phone: stream $streamId local close failed", t) }
        }
    }

    private fun duplexBody(capture: (BufferedSink) -> Unit): RequestBody = object : RequestBody() {
        override fun contentType(): MediaType? = null
        override fun isDuplex(): Boolean = true
        override fun writeTo(sink: BufferedSink) { capture(sink) }
    }
}
