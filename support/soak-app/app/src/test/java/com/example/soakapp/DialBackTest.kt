package com.example.soakapp

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext

class DialBackTest {
    private val listener = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    private val addr = "127.0.0.1:${listener.localPort}"

    @After
    fun closeListener() = listener.close()

    private fun dialBack() = DialBack("connect.example.test", SSLContext.getDefault(), SSLContext.getDefault(), 500)

    private fun peer(answer: (Socket) -> Unit) {
        Thread {
            try {
                listener.accept().use { answer(it) }
            } catch (e: IOException) {
                System.err.println("dial-back test peer ended: $e")
            }
        }.apply { isDaemon = true; start() }
    }

    private fun readRequest(s: Socket) {
        val input = s.getInputStream()
        var tail = 0
        while (tail != 0x0d0a0d0a) {
            val b = input.read()
            if (b < 0) return
            tail = (tail shl 8) or b
        }
    }

    private fun trickle(s: Socket, head: ByteArray) {
        val out = s.getOutputStream()
        out.write(head)
        out.flush()
        repeat(40) {
            out.write('x'.code)
            out.flush()
            Thread.sleep(100)
        }
    }

    private fun assertDeadline(useHttps: Boolean) {
        val start = System.nanoTime()
        assertThrows(SocketTimeoutException::class.java) { dialBack().open("t", addr, useHttps, false) }
        assertTrue("the deadline must end the dial-back", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 2_000)
    }

    @Test
    fun aTrickledStatusLineHitsTheDeadline() {
        peer { readRequest(it); trickle(it, "HTTP/1.1 101 ".toByteArray()) }
        assertDeadline(useHttps = false)
    }

    @Test
    fun aTrickledTlsHandshakeHitsTheDeadline() {
        peer { trickle(it, byteArrayOf(0x16, 0x03, 0x03, 0x40, 0x00)) }
        assertDeadline(useHttps = true)
    }

    @Test
    fun anImmediateUpgradeReturnsASocketWithoutReadTimeout() {
        peer {
            readRequest(it)
            it.getOutputStream().apply { write("HTTP/1.1 101 Switching Protocols\r\n\r\n".toByteArray()); flush() }
            it.getInputStream().read()
        }
        val opened = dialBack().open("t", addr, false, false)
        try {
            assertEquals(0, opened.soTimeout)
        } finally {
            opened.close()
        }
    }

    @Test
    fun aRefusalFails() {
        peer {
            readRequest(it)
            it.getOutputStream().apply { write("HTTP/1.1 404 Not Found\r\n\r\n".toByteArray()); flush() }
        }
        val e = assertThrows(IllegalStateException::class.java) { dialBack().open("t", addr, false, false) }
        assertEquals("dial-back refused: 404", e.message)
    }
}
