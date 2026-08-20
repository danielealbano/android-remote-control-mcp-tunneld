package com.example.tunnelapp

import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import org.json.JSONObject
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

// Tunnel maintains the outbound mTLS HTTP/2 control connection and services /api/v1/data dial-backs. Both streams
// are OkHttp DUPLEX (isDuplex()=true).
class Tunnel(
    private val client: OkHttpClient,   // the identity-mTLS client (Identity.mtlsClient())
    private val controlHost: String,
    private val port: Int,
    private val localServerPort: () -> Int, // lambda defers reading the server's fixed loopback port
    private val onRenewNudge: (String) -> Unit,
) {
    private val running = AtomicBoolean(true)
    fun stop() = running.set(false)

    // run opens /api/v1/control and services it until stopped; a torn stream reconnects with backoff.
    fun run() {
        var backoff = 200L
        while (running.get()) {
            try { serveControlOnce(); backoff = 200L } catch (_: Throwable) {}
            if (!running.get()) break
            Thread.sleep(backoff); backoff = (backoff * 2).coerceAtMost(5_000L)
        }
    }

    private fun serveControlOnce() {
        var sink: BufferedSink? = null
        val body = duplexBody { sink = it }
        client.newCall(Request.Builder().url("https://$controlHost:$port/api/v1/control").post(body).build())
            .execute().use { resp ->
                if (resp.code != 200) return
                val s = sink ?: return
                val source = resp.body!!.source()
                while (running.get()) {
                    val frame = Frames.read(source) ?: break
                    when (frame.first) {
                        Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                        Frames.OPEN -> JSONObject(String(frame.second)).optString("stream_id")
                            .takeIf { it.isNotEmpty() }
                            ?.let { id -> Thread { handleOpen(id) }.apply { isDaemon = true }.start() }
                        Frames.RENEW_NUDGE -> JSONObject(String(frame.second)).optString("nonce")
                            .takeIf { it.isNotEmpty() }
                            ?.let { n -> Thread { onRenewNudge(n) }.apply { isDaemon = true }.start() }
                    }
                }
                try { s.close() } catch (_: Throwable) {}
            }
    }

    // handleOpen: duplex /api/v1/data dial-back spliced OPAQUELY to a fresh socket to the local server. Request
    // body = phone→client (local→sink), response body = client→phone (resp→local). No framing.
    private fun handleOpen(streamId: String) {
        val local = try { Socket("127.0.0.1", localServerPort()) } catch (_: Throwable) { return }
        try {
            var sink: BufferedSink? = null
            val body = duplexBody { sink = it }
            client.newCall(
                Request.Builder().url("https://$controlHost:$port/api/v1/data")
                    .addHeader("X-Stream-Id", streamId).post(body).build(),
            ).execute().use { resp ->
                if (resp.code != 200) return
                val s = sink ?: return
                val up = Thread {
                    try {
                        val buf = ByteArray(16384); val ins = local.getInputStream()
                        while (true) { val n = ins.read(buf); if (n < 0) break; s.write(buf, 0, n); s.flush() }
                    } catch (_: Throwable) {} finally { try { s.close() } catch (_: Throwable) {} }
                }.apply { isDaemon = true }
                up.start()
                val out = local.getOutputStream(); val src = resp.body!!.byteStream(); val buf = ByteArray(16384)
                while (true) { val n = src.read(buf); if (n < 0) break; out.write(buf, 0, n); out.flush() }
                up.join(5000)
            }
        } catch (_: Throwable) {
        } finally {
            try { local.close() } catch (_: Throwable) {}
        }
    }

    private fun duplexBody(capture: (BufferedSink) -> Unit): RequestBody = object : RequestBody() {
        override fun contentType(): MediaType? = null
        override fun isDuplex(): Boolean = true
        override fun writeTo(sink: BufferedSink) { capture(sink) } // capture + return; drive after execute()
    }
}
