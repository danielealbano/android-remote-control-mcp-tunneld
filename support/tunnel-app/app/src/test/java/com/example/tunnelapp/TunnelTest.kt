package com.example.tunnelapp

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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext

class TunnelTest {
    private val server: MockWebServer = ControlServer.start()
    private val stats = Stats()
    private val clientAddrs = ConcurrentHashMap<Int, String>()
    private val nudges = AtomicInteger()
    private val dial = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    private val local = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    @After
    fun close() {
        dial.close()
        local.close()
        server.close()
    }

    private fun tunnel(): Tunnel = Tunnel(
        ControlServer.client(), Net(null, server.port), ControlServer.HOST,
        DialBack(ControlServer.HOST, SSLContext.getDefault(), SSLContext.getDefault()), { local.localPort }, stats, clientAddrs,
    ) { nudges.incrementAndGet() }

    private fun acceptLocal(accepted: AtomicReference<Socket>, done: CountDownLatch) {
        Thread {
            try {
                accepted.set(local.accept())
                done.countDown()
            } catch (e: IOException) {
                System.err.println("local server ended: $e")
            }
        }.apply { isDaemon = true; start() }
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
        Frames.OPEN, """{"token":"t","addr":"127.0.0.1:${dial.localPort}","use_https":false,"use_mtls":false,"client_addr":"198.51.100.7:52144"}""",
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
        val localAccepted = AtomicReference<Socket>()
        val localDone = CountDownLatch(1)
        acceptLocal(localAccepted, localDone)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(openFrame())
                out.flush()
                upgraded.await(5, TimeUnit.SECONDS)
                localDone.await(5, TimeUnit.SECONDS)
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
            assertClosedByPeer(localAccepted.get())
        } finally {
            t.stop()
            accepted.get()?.close()
            localAccepted.get()?.close()
        }
    }

    @Test
    fun stopClosesItsSessions() {
        val accepted = AtomicReference<Socket>()
        val upgraded = CountDownLatch(1)
        acceptUpgrade(accepted, upgraded)
        val localAccepted = AtomicReference<Socket>()
        val localDone = CountDownLatch(1)
        acceptLocal(localAccepted, localDone)
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
            assertTrue(localDone.await(5, TimeUnit.SECONDS))
            t.stop()
            assertClosedByPeer(accepted.get())
            assertClosedByPeer(localAccepted.get())
        } finally {
            t.stop()
            accepted.get()?.close()
            localAccepted.get()?.close()
        }
    }

    @Test
    fun openWithoutClientAddrIsIgnored() =
        assertOpenIsIgnored("""{"token":"t","addr":"127.0.0.1:${dial.localPort}","use_https":false,"use_mtls":false}""")

    @Test
    fun openWithAnEmptyClientAddrIsIgnored() =
        assertOpenIsIgnored("""{"token":"t","addr":"127.0.0.1:${dial.localPort}","use_https":false,"use_mtls":false,"client_addr":""}""")

    private fun assertOpenIsIgnored(payload: String) {
        val localConnections = AtomicInteger()
        Thread {
            try {
                while (true) {
                    local.accept().close()
                    localConnections.incrementAndGet()
                }
            } catch (e: IOException) {
                System.err.println("local server ended: $e")
            }
        }.apply { isDaemon = true; start() }
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(ControlServer.frame(Frames.OPEN, payload))
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("control stream ended: $e")
            }
        })
        val t = tunnel()
        run(t)
        try {
            assertTrue(t.awaitBound(5))
            Thread.sleep(1_000)
            assertEquals("an OPEN without a client_addr must not open a session", 0, localConnections.get())
            assertEquals(0L, stats.snapshot().connections)
        } finally {
            t.stop()
        }
    }

    private fun assertClientAddrsDropped() {
        val deadline = System.currentTimeMillis() + 5_000
        while (clientAddrs.isNotEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertTrue("the address must be dropped with the session", clientAddrs.isEmpty())
    }

    @Test
    fun openWithAnUnknownFieldIsServed() {
        val accepted = AtomicReference<Socket>()
        val upgraded = CountDownLatch(1)
        acceptUpgrade(accepted, upgraded)
        val localAccepted = AtomicReference<Socket>()
        val localDone = CountDownLatch(1)
        acceptLocal(localAccepted, localDone)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(
                    ControlServer.frame(
                        Frames.OPEN,
                        """{"token":"t","addr":"127.0.0.1:${dial.localPort}","use_https":false,"use_mtls":false,"client_addr":"198.51.100.7:52144","extra":1}""",
                    ),
                )
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("control stream ended: $e")
            }
        })
        val t = tunnel()
        run(t)
        try {
            assertTrue("an OPEN with an unknown field must still dial back", upgraded.await(5, TimeUnit.SECONDS))
        } finally {
            t.stop()
            accepted.get()?.close()
            localAccepted.get()?.close()
        }
    }

    @Test
    fun clientAddrIsDroppedWhenTheDialBackIsRefused() {
        val requestRead = CountDownLatch(1)
        val refuse = CountDownLatch(1)
        val peer = AtomicReference<Socket>()
        Thread {
            try {
                val c = dial.accept()
                peer.set(c)
                val input = c.getInputStream()
                var tail = 0
                while (tail != 0x0d0a0d0a) {
                    val b = input.read()
                    if (b < 0) break
                    tail = (tail shl 8) or b
                }
                requestRead.countDown()
                refuse.await(5, TimeUnit.SECONDS)
                c.getOutputStream().apply { write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".toByteArray()); flush() }
            } catch (e: IOException) {
                System.err.println("dial-back peer ended: $e")
            }
        }.apply { isDaemon = true; start() }
        val localAccepted = AtomicReference<Socket>()
        val localDone = CountDownLatch(1)
        acceptLocal(localAccepted, localDone)
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
            assertTrue(requestRead.await(5, TimeUnit.SECONDS))
            assertTrue(localDone.await(5, TimeUnit.SECONDS))
            assertEquals("198.51.100.7:52144", clientAddrs[localAccepted.get().port])
            refuse.countDown()
            assertClientAddrsDropped()
        } finally {
            t.stop()
            peer.get()?.close()
            localAccepted.get()?.close()
        }
    }

    @Test
    fun clientAddrIsKnownForItsLocalConnectionUntilTheSessionEnds() {
        val accepted = AtomicReference<Socket>()
        val upgraded = CountDownLatch(1)
        acceptUpgrade(accepted, upgraded)
        val localAccepted = AtomicReference<Socket>()
        val localDone = CountDownLatch(1)
        acceptLocal(localAccepted, localDone)
        val release = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(openFrame())
                out.flush()
                release.await(10, TimeUnit.SECONDS)
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
            assertTrue(localDone.await(5, TimeUnit.SECONDS))
            assertEquals("198.51.100.7:52144", clientAddrs[localAccepted.get().port])
            release.countDown()
            assertClosedByPeer(localAccepted.get())
            assertClientAddrsDropped()
        } finally {
            t.stop()
            accepted.get()?.close()
            localAccepted.get()?.close()
        }
    }

    private fun moveFrame(vararg addrs: String) =
        ControlServer.frame(Frames.MOVE, """{"addrs":[${addrs.joinToString(",") { "\"$it\"" }}]}""")

    @Test
    fun moveOpensANewConnectionAndKeepsTheOldOne() {
        val other = ControlServer.start()
        val pingNow = CountDownLatch(1)
        val pong = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closedByPhone = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(moveFrame("127.0.0.1:${other.port}"))
                out.flush()
                Thread {
                    try {
                        val src = s.source.buffer()
                        while (true) {
                            val f = Frames.read(src) ?: break
                            if (f.first == Frames.PONG) pong.countDown()
                        }
                    } catch (e: IOException) {
                        System.err.println("moved-away stream read ended: $e")
                    }
                    if (release.count > 0) closedByPhone.countDown()
                }.apply { isDaemon = true; start() }
                pingNow.await(10, TimeUnit.SECONDS)
                out.write(ControlServer.frame(Frames.PING))
                out.flush()
                release.await(10, TimeUnit.SECONDS)
                out.close()
            } catch (e: IOException) {
                System.err.println("moved-away stream write failed: $e")
            }
        })
        other.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue("the phone must open a control connection to the MOVE target", other.takeRequest(5, TimeUnit.SECONDS) != null)
            assertFalse("the phone must keep the connection that carried the MOVE", closedByPhone.await(500, TimeUnit.MILLISECONDS))
            pingNow.countDown()
            assertTrue("the moved-away connection must still answer PING", pong.await(5, TimeUnit.SECONDS))
            release.countDown()
            Thread.sleep(300)
            assertEquals("the end of the old connection must not reconnect", 1, server.requestCount)
        } finally {
            release.countDown()
            t.stop()
            other.close()
        }
    }

    @Test
    fun moveFallsBackToTheControlHostOnANewConnection() {
        val unreachable = ServerSocket(0, 50, InetAddress.getLoopbackAddress()).use { it.localPort }
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(moveFrame("not-an-address", "127.0.0.1:$unreachable"))
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("moved-away stream ended: $e")
            }
        })
        server.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            val first = server.takeRequest(5, TimeUnit.SECONDS)
            val second = server.takeRequest(10, TimeUnit.SECONDS)
            assertTrue("the phone must fall back to the control host", first != null && second != null)
            assertTrue("the fallback must open a new connection", first!!.connectionIndex != second!!.connectionIndex)
        } finally {
            t.stop()
        }
    }

    @Test
    fun malformedMoveIsIgnored() {
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(ControlServer.frame(Frames.MOVE, "{"))
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("control stream ended: $e")
            }
        })
        val t = tunnel()
        run(t)
        try {
            assertTrue(t.awaitBound(5))
            Thread.sleep(1_000)
            assertEquals("a malformed MOVE must not open a connection", 1, server.requestCount)
        } finally {
            t.stop()
        }
    }

    private fun moveAndHold(vararg addrs: String): MockResponse = ControlServer.answer(200) { s ->
        try {
            val out = s.sink.buffer()
            out.write(moveFrame(*addrs))
            out.flush()
            s.source.buffer().readByteArray()
        } catch (e: IOException) {
            System.err.println("moved-away stream ended: $e")
        }
    }

    @Test
    fun moveOnTheNewConnectionIsFollowed() {
        val second = ControlServer.start()
        val third = ControlServer.start()
        server.enqueue(moveAndHold("127.0.0.1:${second.port}"))
        second.enqueue(moveAndHold("127.0.0.1:${third.port}"))
        third.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue("a MOVE on the new connection must be followed", third.takeRequest(10, TimeUnit.SECONDS) != null)
        } finally {
            t.stop()
            second.close()
            third.close()
        }
    }

    @Test
    fun secondMoveOnAMovedConnectionIsIgnored() {
        val target = ControlServer.start()
        val other = ControlServer.start()
        val targetBound = CountDownLatch(1)
        val secondSent = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(moveFrame("127.0.0.1:${target.port}"))
                out.flush()
                targetBound.await(10, TimeUnit.SECONDS)
                out.write(moveFrame("127.0.0.1:${other.port}"))
                out.flush()
                secondSent.countDown()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("moved-away stream ended: $e")
            }
        })
        target.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue(target.takeRequest(10, TimeUnit.SECONDS) != null)
            targetBound.countDown()
            assertTrue(secondSent.await(5, TimeUnit.SECONDS))
            Thread.sleep(1_000)
            assertEquals("a second MOVE on a moved connection must be ignored", 0, other.requestCount)
        } finally {
            t.stop()
            target.close()
            other.close()
        }
    }

    @Test
    fun moveAnsweredWithoutABindIsFollowed() {
        val target = ControlServer.start()
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(moveFrame("127.0.0.1:${target.port}"))
                out.flush()
                out.close()
            } catch (e: IOException) {
                System.err.println("draining answer write failed: $e")
            }
        })
        target.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue("the MOVE of a draining node's answer must be followed", target.takeRequest(10, TimeUnit.SECONDS) != null)
        } finally {
            t.stop()
            target.close()
        }
    }

    @Test
    fun moveFromTheFallbackIsFollowedAfterABackoff() {
        val unreachable = ServerSocket(0, 50, InetAddress.getLoopbackAddress()).use { it.localPort }
        val stamps = ConcurrentLinkedQueue<Long>()
        repeat(3) {
            server.enqueue(ControlServer.answer(200) { s ->
                stamps.add(System.nanoTime())
                try {
                    val out = s.sink.buffer()
                    out.write(moveFrame("127.0.0.1:$unreachable"))
                    out.flush()
                    s.source.buffer().readByteArray()
                } catch (e: IOException) {
                    System.err.println("moved-away stream ended: $e")
                }
            })
        }
        val t = tunnel()
        run(t)
        try {
            repeat(3) { assertTrue("control stream ${it + 1}", server.takeRequest(10, TimeUnit.SECONDS) != null) }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (stamps.size < 3 && System.nanoTime() < deadline) Thread.sleep(10)
            val at = stamps.toList()
            assertEquals(3, at.size)
            val gap = TimeUnit.NANOSECONDS.toMillis(at[2] - at[1])
            assertTrue("a MOVE answered by the fallback connection must wait the reconnect backoff, gap ${gap}ms", gap >= 200)
        } finally {
            t.stop()
        }
    }

    @Test
    fun parseMoveTargetAcceptsHostPortOnly() {
        assertEquals(InetAddress.getByName("203.0.113.2") to 443, parseMoveTarget("203.0.113.2:443"))
        assertEquals(InetAddress.getByName("2001:db8::1") to 443, parseMoveTarget("[2001:db8::1]:443"))
        for (bad in listOf("not-an-address", ":443", "203.0.113.2:", "203.0.113.2:0", "203.0.113.2:70000", "2001:db8::1:443", "")) {
            assertNull("\"$bad\" must be rejected", parseMoveTarget(bad))
        }
    }

    @Test
    fun moveWithoutAddressesIsIgnored() {
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(ControlServer.frame(Frames.MOVE, """{"addrs":[]}"""))
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("control stream ended: $e")
            }
        })
        val t = tunnel()
        run(t)
        try {
            assertTrue(t.awaitBound(5))
            Thread.sleep(1_000)
            assertEquals("a MOVE without addresses must not open a connection", 1, server.requestCount)
        } finally {
            t.stop()
        }
    }

    @Test
    fun lostMoveTargetConnectionReconnectsThroughTheControlHost() {
        val target = ControlServer.start()
        val next = ControlServer.start()
        server.enqueue(moveAndHold("127.0.0.1:${target.port}", "127.0.0.1:${next.port}"))
        target.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(byteArrayOf(Frames.PING.toByte(), 0x7f, 0xff.toByte(), 0xff.toByte(), 0xff.toByte()))
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("target stream ended: $e")
            }
        })
        server.enqueue(hold())
        next.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue(server.takeRequest(5, TimeUnit.SECONDS) != null)
            assertTrue("the phone must bind on the MOVE target", target.takeRequest(5, TimeUnit.SECONDS) != null)
            assertTrue("a lost bound connection must reconnect through the control host", server.takeRequest(10, TimeUnit.SECONDS) != null)
            assertEquals("a lost bound connection must not try the next MOVE address", 0, next.requestCount)
        } finally {
            t.stop()
            target.close()
            next.close()
        }
    }

    private fun assertStaysOpen(s: Socket) {
        s.soTimeout = 500
        assertThrows("the session must stay open", SocketTimeoutException::class.java) { s.getInputStream().read() }
    }

    @Test
    fun sessionOnTheNewConnectionSurvivesTheEndOfTheOldOne() {
        val target = ControlServer.start()
        val accepted = AtomicReference<Socket>()
        val upgraded = CountDownLatch(1)
        acceptUpgrade(accepted, upgraded)
        val localAccepted = AtomicReference<Socket>()
        val localDone = CountDownLatch(1)
        acceptLocal(localAccepted, localDone)
        val release = CountDownLatch(1)
        val oldEnded = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(moveFrame("127.0.0.1:${target.port}"))
                out.flush()
                release.await(10, TimeUnit.SECONDS)
                out.close()
            } catch (e: IOException) {
                System.err.println("moved-away stream write failed: $e")
            } finally {
                oldEnded.countDown()
            }
        })
        target.enqueue(ControlServer.answer(200) { s ->
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
            assertTrue(localDone.await(5, TimeUnit.SECONDS))
            release.countDown()
            assertTrue(oldEnded.await(5, TimeUnit.SECONDS))
            assertStaysOpen(accepted.get())
            assertStaysOpen(localAccepted.get())
        } finally {
            release.countDown()
            t.stop()
            target.close()
            accepted.get()?.close()
            localAccepted.get()?.close()
        }
    }

    @Test
    fun moveAwayConnectionStillOpensSessionsThatSurviveTheNewOne() {
        val target = ControlServer.start()
        val accepted = AtomicReference<Socket>()
        val upgraded = CountDownLatch(1)
        acceptUpgrade(accepted, upgraded)
        val localAccepted = AtomicReference<Socket>()
        val localDone = CountDownLatch(1)
        acceptLocal(localAccepted, localDone)
        val targetBound = CountDownLatch(1)
        val releaseTarget = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(moveFrame("127.0.0.1:${target.port}"))
                out.flush()
                targetBound.await(10, TimeUnit.SECONDS)
                out.write(openFrame())
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("moved-away stream ended: $e")
            }
        })
        target.enqueue(ControlServer.answer(200) { s ->
            try {
                targetBound.countDown()
                releaseTarget.await(10, TimeUnit.SECONDS)
                s.sink.buffer().close()
            } catch (e: IOException) {
                System.err.println("target stream ended: $e")
            }
        })
        server.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue("an OPEN on the moved-away connection must still dial back", upgraded.await(10, TimeUnit.SECONDS))
            assertTrue(localDone.await(5, TimeUnit.SECONDS))
            releaseTarget.countDown()
            assertTrue("the end of the new connection must reconnect", server.takeRequest(5, TimeUnit.SECONDS) != null)
            assertTrue(server.takeRequest(5, TimeUnit.SECONDS) != null)
            assertStaysOpen(accepted.get())
            assertStaysOpen(localAccepted.get())
        } finally {
            releaseTarget.countDown()
            t.stop()
            target.close()
            accepted.get()?.close()
            localAccepted.get()?.close()
        }
    }

    @Test
    fun stopEndsTheMovedAwayConnection() {
        val target = ControlServer.start()
        val oldEnded = CountDownLatch(1)
        server.enqueue(ControlServer.answer(200) { s ->
            try {
                val out = s.sink.buffer()
                out.write(moveFrame("127.0.0.1:${target.port}"))
                out.flush()
                s.source.buffer().readByteArray()
            } catch (e: IOException) {
                System.err.println("moved-away stream reset: $e")
            } finally {
                oldEnded.countDown()
            }
        })
        target.enqueue(hold())
        val t = tunnel()
        val runner = run(t)
        try {
            assertTrue(target.takeRequest(5, TimeUnit.SECONDS) != null)
            assertFalse("the moved-away connection must stay open until the stop", oldEnded.await(300, TimeUnit.MILLISECONDS))
            t.stop()
            runner.join(2_000)
            assertFalse("run must return at once after stop", runner.isAlive)
            assertTrue("stop must end the moved-away connection", oldEnded.await(2, TimeUnit.SECONDS))
        } finally {
            t.stop()
            target.close()
        }
    }

    private fun refuseWith(code: Int): MockResponse = ControlServer.answer(code) { s ->
        try {
            s.sink.close()
            s.source.buffer().readByteArray()
        } catch (e: IOException) {
            System.err.println("refused control stream ended: $e")
        }
    }

    @Test
    fun moveTriesTheNextAddressOnARefusal() {
        val refuser = ControlServer.start()
        val target = ControlServer.start()
        server.enqueue(moveAndHold("127.0.0.1:${refuser.port}", "127.0.0.1:${target.port}"))
        refuser.enqueue(refuseWith(503))
        target.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            assertTrue("the refusing address must be tried", refuser.takeRequest(5, TimeUnit.SECONDS) != null)
            assertTrue("the next address must be tried after a refusal", target.takeRequest(5, TimeUnit.SECONDS) != null)
        } finally {
            t.stop()
            refuser.close()
            target.close()
        }
    }

    @Test
    fun moveFallsBackWhenEveryAddressRefuses() {
        val r1 = ControlServer.start()
        val r2 = ControlServer.start()
        server.enqueue(moveAndHold("127.0.0.1:${r1.port}", "127.0.0.1:${r2.port}"))
        r1.enqueue(refuseWith(503))
        r2.enqueue(refuseWith(403))
        server.enqueue(hold())
        val t = tunnel()
        run(t)
        try {
            val first = server.takeRequest(5, TimeUnit.SECONDS)
            assertTrue(r1.takeRequest(5, TimeUnit.SECONDS) != null)
            assertTrue(r2.takeRequest(5, TimeUnit.SECONDS) != null)
            val second = server.takeRequest(10, TimeUnit.SECONDS)
            assertTrue("the phone must fall back to the control host", first != null && second != null)
            assertTrue("the fallback must open a new connection", first!!.connectionIndex != second!!.connectionIndex)
        } finally {
            t.stop()
            r1.close()
            r2.close()
        }
    }
}
