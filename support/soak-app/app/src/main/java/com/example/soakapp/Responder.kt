package com.example.soakapp

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class Responder(private val phone: Int) {
    private class Head(val method: String, val target: String, val length: Long, val close: Boolean)

    private val context = AtomicReference<SSLContext>()

    fun install(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ServerTls.keyStore(tlsKey, chain), ServerTls.PASSWORD)
        context.set(SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) })
    }

    fun serve(conn: Socket, host: String) {
        val tls = try {
            (context.get().socketFactory.createSocket(conn, host, conn.port, true) as SSLSocket).apply {
                useClientMode = false
                sslParameters = sslParameters.apply { applicationProtocols = arrayOf("http/1.1") }
            }
        } catch (t: Throwable) {
            try { conn.close() } catch (c: Throwable) { t.addSuppressed(c) }
            throw t
        }
        tls.use { s ->
            s.startHandshake()
            val input = BufferedInputStream(s.inputStream)
            val output = BufferedOutputStream(s.outputStream)
            while (true) {
                val head = readHead(input) ?: return
                discard(input, head.length)
                val path = head.target.substringBefore('?')
                val size = head.target.substringAfter('?', "").split('&')
                    .firstOrNull { it.startsWith("resp=") }?.removePrefix("resp=")?.toIntOrNull()
                    ?.takeIf { it in 0..MAX_RESPONSE }
                when {
                    head.method != "POST" || path != "/op" -> { respond(output, 404, 0, true); return }
                    size == null -> { respond(output, 400, 0, true); return }
                    else -> respond(output, 200, size, head.close)
                }
                if (head.close) return
            }
        }
    }

    private fun readHead(input: InputStream): Head? {
        val start = readLine(input) ?: return null
        val parts = start.split(' ')
        if (parts.size != 3 || !parts[2].startsWith("HTTP/1.")) throw IOException("phone $phone: malformed request line")
        var length = 0L
        var close = parts[2] == "HTTP/1.0"
        repeat(MAX_HEADERS + 1) {
            val line = readLine(input) ?: throw IOException("phone $phone: connection closed inside the request head")
            if (line.isEmpty()) return Head(parts[0], parts[1], length, close)
            val sep = line.indexOf(':')
            if (sep <= 0) throw IOException("phone $phone: malformed header line")
            val value = line.substring(sep + 1).trim()
            when (line.substring(0, sep).trim().lowercase()) {
                "content-length" -> length = value.toLongOrNull()?.takeIf { it in 0..MAX_BODY }
                    ?: throw IOException("phone $phone: bad Content-Length $value")
                "transfer-encoding" -> throw IOException("phone $phone: chunked request bodies are not supported")
                "connection" -> if (value.equals("close", ignoreCase = true)) close = true
            }
        }
        throw IOException("phone $phone: too many request headers")
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) {
                if (sb.isEmpty()) return null
                throw IOException("phone $phone: connection closed inside a line")
            }
            if (b == '\n'.code) return sb.toString().removeSuffix("\r")
            if (sb.length >= MAX_LINE) throw IOException("phone $phone: request line too long")
            sb.append(b.toChar())
        }
    }

    private fun discard(input: InputStream, length: Long) {
        var left = length
        val buf = ByteArray(16384)
        while (left > 0) {
            val n = input.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
            if (n < 0) throw IOException("phone $phone: connection closed inside the request body")
            left -= n
        }
    }

    private fun respond(out: OutputStream, status: Int, size: Int, close: Boolean) {
        val reason = when (status) {
            200 -> "OK"
            400 -> "Bad Request"
            else -> "Not Found"
        }
        val head = "HTTP/1.1 $status $reason\r\nContent-Type: application/octet-stream\r\nContent-Length: $size\r\n" +
            (if (close) "Connection: close\r\n" else "") + "\r\n"
        out.write(head.toByteArray(Charsets.US_ASCII))
        out.write(PATTERN, 0, size)
        out.flush()
    }

    companion object {
        private const val MAX_RESPONSE = 65536
        private const val MAX_BODY = 1L shl 20
        private const val MAX_HEADERS = 64
        private const val MAX_LINE = 8192
        private val PATTERN = ByteArray(MAX_RESPONSE) { (it % 251).toByte() }
    }
}
