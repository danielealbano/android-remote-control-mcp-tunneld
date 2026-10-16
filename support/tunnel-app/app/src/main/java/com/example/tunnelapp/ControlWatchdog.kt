package com.example.tunnelapp

import android.util.Log
import okhttp3.Call
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

internal object ControlWatchdog {
    private val silenceNanos = TimeUnit.SECONDS.toNanos(90)
    private const val CHECK_SECONDS = 5L
    private val scheduler = ScheduledThreadPoolExecutor(1) { r -> Thread(r, "control-watchdog").apply { isDaemon = true } }
        .apply { removeOnCancelPolicy = true }

    fun watch(label: String, call: Call, lastFrameAt: AtomicLong, silent: AtomicBoolean): ScheduledFuture<*> =
        scheduler.scheduleWithFixedDelay({
            if (System.nanoTime() - lastFrameAt.get() > silenceNanos && !call.isCanceled()) {
                Log.w(TAG, "$label: no control frame for 90s; dropping the connection")
                silent.set(true)
                call.cancel()
            }
        }, CHECK_SECONDS, CHECK_SECONDS, TimeUnit.SECONDS)
}
