package com.example.tunnelapp

import android.util.Log
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.MediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import okio.BufferedSource
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

internal const val TAG = "TunnelApp"

internal fun parseMoveTarget(a: String): Pair<InetAddress, Int>? = try {
    val u = URI("tcp://$a")
    require(u.host != null && u.port in 1..65535) { "not host:port" }
    InetAddress.getByName(u.host.removeSurrounding("[", "]")) to u.port
} catch (t: Throwable) {
    Log.w(TAG, "invalid MOVE address ignored: $a", t)
    null
}

// Tunnel maintains the outbound mTLS HTTP/2 control connection.
class Tunnel(
    client: OkHttpClient,   // the identity-mTLS client (Identity.mtlsClient())
    private val net: Net,
    private val controlHost: String,
    private val dialBack: DialBack,
    private val localServerPort: () -> Int, // lambda defers reading the server's fixed loopback port
    private val stats: Stats,
    private val clientAddrs: ConcurrentHashMap<Int, String>,
    private val onRenewNudge: (String) -> Unit,
) {
    private val running = AtomicBoolean(true)
    private val calls: MutableSet<Call> = ConcurrentHashMap.newKeySet()
    private val bound = CountDownLatch(1)
    private val renewals = SingleFlight()
    private val node = AtomicReference("unknown")
    private var everBound = false
    private val client = client.newBuilder().addNetworkInterceptor { chain ->
        chain.connection()?.route()?.socketAddress?.address?.hostAddress?.let { node.set(it) }
        chain.proceed(chain.request())
    }.build()

    fun awaitBound(seconds: Long): Boolean = bound.await(seconds, TimeUnit.SECONDS)
    fun stop() {
        running.set(false)
        for (c in calls) c.cancel()
    }

    // run opens /api/v1/control and services it until stopped; a torn stream reconnects with backoff.
    fun run() {
        var backoff = 200L
        var moveTo: List<String>? = null
        while (running.get()) {
            val targets = moveTo
            moveTo = null
            var pause = false
            try {
                if (targets == null) {
                    moveTo = serveControlOnce(dedicated(), net.url(controlHost, "/api/v1/control")).moveTo
                } else {
                    val moved = serveMoved(targets)
                    moveTo = moved.moveTo
                    pause = moved.viaFallback && moveTo != null
                }
                if (!pause) backoff = 200L
            } catch (t: Throwable) { Log.w(TAG, "control connection ended", t) }
            if (!running.get()) break
            if (moveTo != null && !pause) continue
            if (moveTo == null) stats.disconnected()
            Thread.sleep(backoff); backoff = (backoff * 2).coerceAtMost(5_000L)
        }
    }

    private class Served(val bound: Boolean, val moveTo: List<String>?)

    private class Moved(val moveTo: List<String>?, val viaFallback: Boolean)

    private class BoundConnectionLost(cause: Throwable) : Exception("bound control connection lost", cause)

    private fun dedicated(ip: InetAddress? = null): OkHttpClient =
        client.newBuilder().connectionPool(ConnectionPool()).apply { ip?.let { a -> dns { listOf(a) } } }.build()

    private fun serveMoved(addrs: List<String>): Moved {
        for (a in addrs) {
            val target = parseMoveTarget(a) ?: continue
            val served = try {
                serveControlOnce(dedicated(target.first), "https://$controlHost:${target.second}/api/v1/control")
            } catch (b: BoundConnectionLost) {
                throw b
            } catch (t: Throwable) {
                Log.w(TAG, "control connection to MOVE target $a failed", t)
                null
            }
            if (served?.bound == true) return Moved(served.moveTo, false)
            if (!running.get()) return Moved(null, false)
        }
        return Moved(serveControlOnce(dedicated(), net.url(controlHost, "/api/v1/control")).moveTo, true)
    }

    private fun serveControlOnce(callClient: OkHttpClient, url: String): Served {
        var sink: BufferedSink? = null
        val body = duplexBody { sink = it }
        val call = callClient.newCall(Request.Builder().url(url).post(body).build())
        calls.add(call)
        if (!running.get()) call.cancel()
        val sessions = Sessions { Log.d(TAG, "dial-back session close failed", it) }
        val lastFrameAt = AtomicLong(System.nanoTime())
        val watch = ControlWatchdog.watch("control", call, lastFrameAt)
        var resp: Response? = null
        var handedOff = false
        val cleanup = {
            sessions.closeAll()
            sink?.let { try { it.close() } catch (t: Throwable) { Log.d(TAG, "control request body close failed", t) } }
            resp?.close()
            watch.cancel(false)
            calls.remove(call)
            callClient.connectionPool.evictAll()
        }
        try {
            val r = call.execute()
            resp = r
            if (r.code != 200) {
                Log.w(TAG, "control connect rejected: ${r.code}")
                return Served(false, null)
            }
            val s = sink ?: run {
                Log.w(TAG, "control request body was not opened")
                return Served(false, null)
            }
            bound.countDown()
            if (running.get()) stats.connected(node.get(), everBound)
            everBound = true
            val source = r.body.source()
            val moveTo = try {
                pump(source, s, sessions, lastFrameAt, true)
            } catch (t: Throwable) {
                throw BoundConnectionLost(t)
            }
            if (moveTo != null) {
                handedOff = true
                Thread {
                    try {
                        pump(source, s, sessions, lastFrameAt, false)
                    } catch (t: Throwable) {
                        Log.w(TAG, "moved-away control connection ended", t)
                    } finally {
                        cleanup()
                    }
                }.apply { isDaemon = true }.start()
            }
            return Served(true, moveTo)
        } finally {
            if (!handedOff) cleanup()
        }
    }

    private fun pump(source: BufferedSource, s: BufferedSink, sessions: Sessions, lastFrameAt: AtomicLong, canMove: Boolean): List<String>? {
        while (running.get()) {
            val frame = Frames.read(source) ?: break
            if (!running.get()) break
            lastFrameAt.set(System.nanoTime())
            when (frame.first) {
                Frames.PING -> { s.write(Frames.PONG_FRAME); s.flush() }
                Frames.OPEN -> JSONObject(String(frame.second)).let { o ->
                    Thread {
                        try { handleOpen(o, sessions) } catch (t: Throwable) { Log.w(TAG, "dial-back handling failed", t) }
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
                Frames.MOVE -> {
                    val addrs = try {
                        JSONObject(String(frame.second)).getJSONArray("addrs").let { a -> List(a.length()) { a.getString(it) } }
                            .also { require(it.isNotEmpty()) { "no address" } }
                    } catch (t: Throwable) {
                        Log.w(TAG, "malformed MOVE ignored", t)
                        null
                    }
                    if (addrs != null) {
                        if (canMove) return addrs
                        Log.i(TAG, "MOVE on a connection that already moved ignored")
                    }
                }
            }
        }
        return null
    }

    private fun handleOpen(open: JSONObject, sessions: Sessions) {
        val token = open.optString("token")
        val addr = open.optString("addr")
        val useHttps = open.optBoolean("use_https")
        val useMtls = open.optBoolean("use_mtls")
        val clientAddr = open.optString("client_addr")
        if (token.isEmpty() || addr.isEmpty() || clientAddr.isEmpty() || (useMtls && !useHttps)) {
            Log.w(TAG, "invalid OPEN ignored: addr=$addr use_https=$useHttps use_mtls=$useMtls has_client_addr=${clientAddr.isNotEmpty()}")
            return
        }
        val local = try {
            LocalConnect.open(localServerPort())
        } catch (t: Throwable) {
            Log.w(TAG, "local server unreachable for a dial-back to $addr", t)
            stats.error("local server unreachable for a dial-back to $addr: $t")
            return
        }
        if (!sessions.add(local)) return
        val localPort = local.localPort
        clientAddrs[localPort] = clientAddr
        try {
            val remote = try {
                dialBack.open(token, addr, useHttps, useMtls)
            } catch (t: Throwable) {
                Log.w(TAG, "dial-back to $addr failed", t)
                stats.error("dial-back to $addr failed: $t")
                sessions.release(local)
                try { local.close() } catch (c: Throwable) { Log.d(TAG, "local socket close failed", c) }
                return
            }
            if (!sessions.add(remote.socket)) {
                sessions.release(local)
                try { local.close() } catch (c: Throwable) { Log.d(TAG, "local socket close failed", c) }
                return
            }
            stats.connection()
            try {
                splice(local, remote)
            } finally {
                sessions.release(local)
                sessions.release(remote.socket)
            }
        } finally {
            clientAddrs.remove(localPort, clientAddr)
        }
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
