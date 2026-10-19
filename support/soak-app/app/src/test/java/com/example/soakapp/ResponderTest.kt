package com.example.soakapp

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

class ResponderTest {
    companion object {
        private const val HOST = "phone.example.test"
        private lateinit var key: PrivateKey
        private lateinit var cert: X509Certificate

        @BeforeClass
        @JvmStatic
        fun makeCert() {
            val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            val name = X500Name("CN=$HOST")
            val now = System.currentTimeMillis()
            val holder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, Date(now - 60_000), Date(now + 3_600_000), name, kp.public)
                .build(JcaContentSignerBuilder("SHA256withECDSA").build(kp.private))
            key = kp.private
            cert = JcaX509CertificateConverter().getCertificate(holder)
        }
    }

    private val listener = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    private val stats = Stats()

    @After
    fun closeListener() = listener.close()

    private class Session(val client: SSLSocket, val input: InputStream, val done: CountDownLatch, val error: AtomicReference<Throwable?>)

    private class Response(val status: Int, val headers: Map<String, String>, val body: ByteArray)

    private fun serveNext(responder: Responder, accepted: AtomicReference<Socket>? = null): Pair<CountDownLatch, AtomicReference<Throwable?>> {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        Thread {
            try {
                val conn = listener.accept()
                accepted?.set(conn)
                responder.serve(conn, HOST)
            } catch (t: Throwable) {
                error.set(t)
            } finally {
                done.countDown()
            }
        }.apply { isDaemon = true; start() }
        return done to error
    }

    private fun session(): Session {
        val responder = Responder(1, stats).also { it.install(key, arrayOf(cert)) }
        val (done, error) = serveNext(responder)
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null); setCertificateEntry("phone", cert) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
        val ctx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
        val raw = Socket(InetAddress.getLoopbackAddress(), listener.localPort)
        val client = (ctx.socketFactory.createSocket(raw, HOST, listener.localPort, true) as SSLSocket).apply {
            soTimeout = 5_000
            startHandshake()
        }
        return Session(client, BufferedInputStream(client.inputStream), done, error)
    }

    private fun Session.send(request: String) {
        client.outputStream.apply { write(request.toByteArray(Charsets.US_ASCII)); flush() }
    }

    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else throw IOException("EOF inside a line")
            if (b == '\n'.code) return sb.toString().removeSuffix("\r")
            sb.append(b.toChar())
        }
    }

    private fun Session.response(): Response {
        val status = readLine(input)!!.split(' ')[1].toInt()
        val headers = mutableMapOf<String, String>()
        while (true) {
            val line = readLine(input)!!
            if (line.isEmpty()) break
            val sep = line.indexOf(':')
            headers[line.substring(0, sep).lowercase()] = line.substring(sep + 1).trim()
        }
        val body = ByteArray(headers.getValue("content-length").toInt())
        var off = 0
        while (off < body.size) {
            val n = input.read(body, off, body.size - off)
            check(n >= 0) { "EOF inside the body" }
            off += n
        }
        return Response(status, headers, body)
    }

    private fun Session.assertEof() {
        assertEquals(-1, input.read())
        assertTrue(done.await(5, TimeUnit.SECONDS))
        client.close()
    }

    private fun post(path: String, body: String = "", extra: String = "", version: String = "HTTP/1.1") =
        "POST $path $version\r\nHost: $HOST\r\nContent-Length: ${body.length}\r\n$extra\r\n$body"

    @Test
    fun okResponseSizedByResp() {
        val s = session()
        s.send(post("/op?resp=100", "0123456789"))
        val r = s.response()
        assertEquals(200, r.status)
        assertEquals("100", r.headers["content-length"])
        assertArrayEquals(ByteArray(100) { (it % 251).toByte() }, r.body)
        s.client.close()
        assertTrue(s.done.await(5, TimeUnit.SECONDS))
    }

    @Test
    fun keepAliveServesSeveral() {
        val s = session()
        repeat(2) {
            s.send(post("/op?resp=3", "abc"))
            val r = s.response()
            assertEquals(200, r.status)
            assertNull(r.headers["connection"])
        }
        assertFalse("the connection must stay open after keep-alive requests", s.done.await(100, TimeUnit.MILLISECONDS))
        s.client.close()
        assertTrue(s.done.await(5, TimeUnit.SECONDS))
        assertNull(s.error.get())
        val snap = stats.snapshot("running", 1)
        assertEquals(2L, snap.served)
        assertEquals(6L, snap.bytesIn)
        assertEquals(6L, snap.bytesOut)
        assertEquals(0L, snap.errors)
    }

    @Test
    fun wrongMethodOrPath404() {
        for (req in listOf("GET /op?resp=1 HTTP/1.1\r\nHost: $HOST\r\n\r\n", post("/x?resp=1"))) {
            val s = session()
            s.send(req)
            val r = s.response()
            assertEquals(404, r.status)
            assertEquals("close", r.headers["connection"])
            s.assertEof()
        }
        val snap = stats.snapshot("running", 1)
        assertEquals(2L, snap.errors)
        assertEquals(0L, snap.served)
        assertTrue(snap.lastError!!.text.contains("answered 404"))
    }

    @Test
    fun badResp400() {
        for (path in listOf("/op", "/op?resp=abc", "/op?resp=-1", "/op?resp=65537")) {
            val s = session()
            s.send(post(path))
            val r = s.response()
            assertEquals("$path must be refused", 400, r.status)
            assertEquals("close", r.headers["connection"])
            s.assertEof()
        }
    }

    @Test
    fun http10AndConnectionClose() {
        for (req in listOf(post("/op?resp=5", version = "HTTP/1.0"), post("/op?resp=5", extra = "Connection: close\r\n"))) {
            val s = session()
            s.send(req)
            val r = s.response()
            assertEquals(200, r.status)
            assertEquals(5, r.body.size)
            s.assertEof()
        }
    }

    @Test
    fun refusedHeadsCloseWithoutResponse() {
        val heads = listOf(
            "BAD\r\n\r\n",
            "POST /op?resp=1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /op?resp=1 HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
            "POST /op?resp=1 HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n",
            "POST /op?resp=1 HTTP/1.1\r\n" + (1..65).joinToString("") { "X-H$it: v\r\n" } + "\r\n",
            "POST /op?resp=1 HTTP/1.1\r\nX: " + "a".repeat(8190) + "\r\n\r\n",
        )
        for (head in heads) {
            val s = session()
            s.send(head)
            s.assertEof()
            assertTrue("a refused head must make serve throw an IOException, got ${s.error.get()}", s.error.get() is IOException)
        }
    }

    @Test
    fun sixtyFourHeadersAccepted() {
        val s = session()
        s.send(post("/op?resp=1", extra = (1..62).joinToString("") { "X-H$it: v\r\n" }))
        assertEquals(200, s.response().status)
        s.client.close()
        assertTrue(s.done.await(5, TimeUnit.SECONDS))
        assertNull(s.error.get())
    }

    @Test
    fun setupFailureClosesSocket() {
        val accepted = AtomicReference<Socket>()
        val (done, error) = serveNext(Responder(1, stats), accepted)
        Socket(InetAddress.getLoopbackAddress(), listener.localPort).use {
            assertTrue(done.await(5, TimeUnit.SECONDS))
        }
        assertTrue("serve before install must throw", error.get() != null)
        assertTrue("the raw socket must be closed", accepted.get().isClosed)
    }
}
