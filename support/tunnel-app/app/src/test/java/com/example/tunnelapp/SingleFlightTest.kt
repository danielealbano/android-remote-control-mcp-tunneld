package com.example.tunnelapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class SingleFlightTest {
    private fun awaitTrue(what: String, cond: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!cond()) {
            if (System.nanoTime() > deadline) throw AssertionError("timed out waiting for $what")
            Thread.sleep(5)
        }
    }

    @Test
    fun secondLaunchWhileBusyIsDropped() {
        val sf = SingleFlight()
        val release = CountDownLatch(1)
        val started = CountDownLatch(1)
        val runs = AtomicInteger()
        assertTrue(sf.launch("first") { runs.incrementAndGet(); started.countDown(); release.await() })
        assertTrue(started.await(5, TimeUnit.SECONDS))
        assertFalse(sf.launch("second") { runs.incrementAndGet() })
        release.countDown()
        awaitTrue("the single flight to be released") { sf.launch("third") { runs.incrementAndGet() } }
        awaitTrue("the third block to run") { runs.get() == 2 }
        Thread.sleep(50)
        assertEquals(2, runs.get())
    }

    @Test
    fun releasedAfterBlockThrows() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        val uncaught = CountDownLatch(1)
        Thread.setDefaultUncaughtExceptionHandler { _, _ -> uncaught.countDown() }
        try {
            val sf = SingleFlight()
            assertTrue(sf.launch("throws") { throw IllegalStateException("boom") })
            assertTrue(uncaught.await(5, TimeUnit.SECONDS))
            awaitTrue("the single flight to be released after a throw") { sf.launch("next") {} }
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(previous)
        }
    }
}
