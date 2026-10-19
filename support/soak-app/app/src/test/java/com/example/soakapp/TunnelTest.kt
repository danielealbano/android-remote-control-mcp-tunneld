package com.example.soakapp

import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okio.buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext

class TunnelTest {
    private val server: MockWebServer = ControlServer.start()
    private val stats = Stats()
    private val nudges = AtomicInteger()
    private val dial = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    @After
    fun close() {
        dial.close()
        server.close()
    }

    private fun tunnel(): Tunnel {
        val responder = Responder(0, stats).also { it.install(ControlServer.held.keyPair.private, arrayOf(ControlServer.held.certificate)) }
        return Tunnel(
            0, Net(null, server.port), ControlServer.client(), ControlServer.HOST,
            DialBack(ControlServer.HOST, SSLContext.getDefault(), SSLContext.getDefault()), responder, stats,
        ) { nudges.incrementAndGet() }
    }

    private fun run(t: Tunnel): Thread = Thread { t.run() }.apply { isDaemon = true; start() }

    private fun hold(): MockResponse = ControlServer.answer(200) { s ->
        try {
            s.source.buffer().readByteArray()
        } catch (e: IOException) {
            System.err.println("held control stream ended: $e")
        }
    }

    private fun openFrame() = ControlServer.frame(
        Frames.OPEN, """{"token":"t","addr":"127.0.0.1:${dial.localPort}","use_https":false,"use_mtls":false}""",
    )

    private fun acceptUpgrade(accepted: AtomicReference<Socket>, upgraded: CountDownLatch) {
        Thread {
            try {
                val c = dial.accept()
                accepted.set(c)
                val input = c.getInputStream()
                var tail = 0
                while (tail != 0x0d0a0d0a) {
                    val b = input.read()
                    if (b < 0) break
                    tail = (tail shl 8) or b
                }
                c.getOutputStream().apply { write("HTTP/1.1 101 Switching Protocols\r\n\r\n".toByteArray()); flush() }
                upgraded.countDown()
            } catch (e: IOException) {
                System.err.println("dial-back peer ended: $e")
            }
        }.apply { isDaemon = true; start() }
    }

    private fun assertClosedByPeer(s: Socket) {
        s.soTimeout = 2_000
        val read = try {
            s.getInputStream().read()
        } catch (e: SocketTimeoutException) {
            throw AssertionError("the session was not closed within 2 s", e)
        } catch (e: IOException) {
            -1
        }
        assertEquals(-1, read)
    }

    @Test
    fun nonOkAnswerClosesTheRequestBody() {
        val ended = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        server.enqueue(ControlServer.answer(503) { s ->
            try {
                s.sink.close()
                s.source.buffer().readByteArray()
            } catch (t: Throwable) {
                failure.set(t)
            } finally {
                ended.countDown()
            }
        })
        server.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue("the request body must end", ended.await(5, TimeUnit.SECONDS))
            assertNull("the request body must end cleanly, not with a reset", failure.get())
        } finally {
            t.stop()
        }
    }

    @Test
    fun stopCancelsTheControlCallAtOnce() {
        val ended = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("control stream reset: $e")
            } finally {
                ended.countDown()
            }
        })
        val t = tunnel()
        val runner = run(t)
        assertTrue(t.awaitBound(5))
        t.stop()
        runner.join(2_000)
        assertFalse("run must return at once after stop", runner.isAlive)
        assertTrue("the control stream must end at once after stop", ended.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun framesAfterStopAreIgnored() {
        val stopped = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            stopped.await(5, TimeUnit.SECONDS)
            try {
                val out = s.sink.buffer()
                out.write(ControlServer.frame(Frames.RENEW_NUDGE, """{"nonce":"00"}"""))
                out.write(openFrame())
                out.flush()
            } catch (e: IOException) {
                System.err.println("frames after stop not delivered: $e")
            }
        })
        val t = tunnel()
        run(t)
        assertTrue(t.awaitBound(5))
        t.stop()
        stopped.countDown()
        dial.soTimeout = 1_000
        assertThrows(SocketTimeoutException::class.java) { dial.accept() }
        assertEquals(0, nudges.get())
    }

    @Test
    fun controlEndClosesItsSessions() {
        val accepted = AtomicReference<Socket>()
        val upgraded = CountDownLatch(1)
        acceptUpgrade(accepted, upgraded)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(openFrame())
                out.flush()
                upgraded.await(5, TimeUnit.SECONDS)
                out.close()
            } catch (e: IOException) {
                System.err.println("control stream write failed: $e")
            }
        })
        server.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue(upgraded.await(5, TimeUnit.SECONDS))
            assertClosedByPeer(accepted.get())
            Thread.sleep(1_000)
            assertEquals(0L, stats.snapshot("test", 1).errors)
        } finally {
            t.stop()
            accepted.get()?.close()
        }
    }

    @Test
    fun stopClosesItsSessions() {
        val accepted = AtomicReference<Socket>()
        val upgraded = CountDownLatch(1)
        acceptUpgrade(accepted, upgraded)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(openFrame())
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("control stream ended: $e")
            }
        })
        val t = tunnel()
        run(t)
        try {
            assertTrue(upgraded.await(5, TimeUnit.SECONDS))
            t.stop()
            assertClosedByPeer(accepted.get())
            Thread.sleep(1_000)
            assertEquals(0L, stats.snapshot("test", 1).errors)
        } finally {
            t.stop()
            accepted.get()?.close()
        }
    }
}
