package com.example.tunnelapp

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.ConnectException
import java.net.InetAddress
import java.net.ServerSocket

class LocalConnectTest {
    private fun freePort(): Int = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }

    @Test
    fun connectsOnceTheServerIsBackWithinTheWindow() {
        val port = freePort()
        val server = Thread {
            Thread.sleep(300)
            ServerSocket(port, 1, InetAddress.getLoopbackAddress()).use { it.accept().close() }
        }.apply { isDaemon = true; start() }
        LocalConnect.open(port, 5_000).use { assertTrue(it.isConnected) }
        server.join(5_000)
    }

    @Test
    fun givesUpAfterTheWindow() {
        val port = freePort()
        val start = System.nanoTime()
        try {
            LocalConnect.open(port, 200).close()
            fail("a connect with no server must fail")
        } catch (e: ConnectException) {
            assertTrue((System.nanoTime() - start) / 1_000_000 >= 200)
        }
    }
}
