package com.example.tunnelapp

import java.net.ConnectException
import java.net.Socket

internal object LocalConnect {
    const val WINDOW_MS = 2_000L
    private const val RETRY_MS = 50L

    fun open(port: Int, windowMs: Long = WINDOW_MS): Socket {
        val deadline = System.nanoTime() + windowMs * 1_000_000
        while (true) {
            try {
                return Socket("127.0.0.1", port).apply { tcpNoDelay = true }
            } catch (e: ConnectException) {
                if (System.nanoTime() >= deadline) throw e
                Thread.sleep(RETRY_MS)
            }
        }
    }
}
