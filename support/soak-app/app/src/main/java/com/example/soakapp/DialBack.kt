package com.example.soakapp

import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class DialBack(
    private val controlHost: String,
    private val mtls: SSLContext,
    private val serverTls: SSLContext,
) {
    fun open(token: String, addr: String, useHttps: Boolean, useMtls: Boolean): Socket {
        val sep = addr.lastIndexOf(':')
        require(sep > 0) { "bad dial-back address $addr" }
        val host = addr.substring(0, sep).removePrefix("[").removeSuffix("]")
        val port = addr.substring(sep + 1).toInt()
        val raw = Socket()
        try {
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(host, port), TIMEOUT_MS)
            raw.soTimeout = TIMEOUT_MS
            val s = if (useHttps) tls(raw, port, if (useMtls) mtls else serverTls) else raw
            s.getOutputStream().apply {
                write(
                    ("GET /api/v1/data HTTP/1.1\r\nHost: $controlHost\r\nConnection: Upgrade\r\n" +
                        "Upgrade: tunneld-dial\r\nX-Dial-Token: $token\r\n\r\n").toByteArray(Charsets.US_ASCII),
                )
                flush()
            }
            val status = readStatus(s.getInputStream())
            check(status == 101) { "dial-back refused: $status" }
            s.soTimeout = 0
            return s
        } catch (t: Throwable) {
            try { raw.close() } catch (c: Throwable) { t.addSuppressed(c) }
            throw t
        }
    }

    private fun tls(raw: Socket, port: Int, ctx: SSLContext): Socket {
        val s = ctx.socketFactory.createSocket(raw, controlHost, port, true) as SSLSocket
        s.sslParameters = s.sslParameters.apply {
            serverNames = listOf(SNIHostName(controlHost))
            applicationProtocols = arrayOf("http/1.1")
        }
        s.startHandshake()
        check(HttpsURLConnection.getDefaultHostnameVerifier().verify(controlHost, s.session)) {
            "dial-back peer certificate does not cover $controlHost"
        }
        return s
    }

    private fun readStatus(input: InputStream): Int {
        val statusLine = readLine(input)
        while (true) {
            if (readLine(input).isEmpty()) break
        }
        val parts = statusLine.split(' ')
        check(parts.size >= 2 && parts[0].startsWith("HTTP/1.")) { "bad dial-back response: $statusLine" }
        return parts[1].toInt()
    }

    private fun readLine(input: InputStream): String {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            check(b >= 0) { "dial-back connection closed during the upgrade" }
            if (b == '\n'.code) return sb.toString().removeSuffix("\r")
            check(sb.length < MAX_LINE) { "dial-back response line too long" }
            sb.append(b.toChar())
        }
    }

    private companion object {
        const val TIMEOUT_MS = 10_000
        const val MAX_LINE = 8192
    }
}
