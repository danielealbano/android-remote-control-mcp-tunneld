package com.example.soakapp

import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap

internal class Sessions(private val onCloseError: (Throwable) -> Unit) {
    private val open = ConcurrentHashMap.newKeySet<Closeable>()
    @Volatile private var shut = false

    fun isClosed(): Boolean = shut

    fun add(c: Closeable): Boolean {
        open.add(c)
        if (!shut) return true
        if (open.remove(c)) close(c)
        return false
    }

    fun release(c: Closeable) {
        open.remove(c)
    }

    fun closeAll() {
        shut = true
        for (c in open.toList()) if (open.remove(c)) close(c)
    }

    private fun close(c: Closeable) {
        try { c.close() } catch (t: Throwable) { onCloseError(t) }
    }
}
