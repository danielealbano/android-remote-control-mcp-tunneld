package com.example.soakapp

import java.util.concurrent.atomic.AtomicBoolean

internal class SingleFlight {
    private val busy = AtomicBoolean(false)

    fun launch(name: String, block: () -> Unit): Boolean {
        if (!busy.compareAndSet(false, true)) return false
        try {
            Thread({
                try { block() } finally { busy.set(false) }
            }, name).apply { isDaemon = true }.start()
        } catch (t: Throwable) {
            busy.set(false)
            throw t
        }
        return true
    }
}
