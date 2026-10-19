package com.example.soakapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class RenewGateTest {
    private val gate = RenewGate()

    @Test
    fun renewRunsOnlyWhileTheIdentityIsCurrent() {
        assertEquals(42, gate.renew("abc", { true }) { 42 })
        val ran = AtomicBoolean(false)
        assertThrows(ForgottenIdentity::class.java) { gate.renew("abc", { false }) { ran.set(true) } }
        assertFalse(ran.get())
    }

    @Test
    fun forgetWaitsForARunningRenew() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val renewing = Thread { gate.renew("abc", { true }) { entered.countDown(); release.await(5, TimeUnit.SECONDS) } }
            .apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val forgotten = AtomicBoolean(false)
        val forgetting = Thread { gate.forget { forgotten.set(true) } }.apply { isDaemon = true; start() }
        forgetting.join(200)
        assertFalse(forgotten.get())
        release.countDown()
        forgetting.join(5_000)
        renewing.join(5_000)
        assertTrue(forgotten.get())
    }

    @Test
    fun renewalRunsTheAttemptsThenTheCommit() {
        val attempts = AtomicInteger()
        val committed = AtomicBoolean(false)
        gate.renewal("abc", { true }, { attempt -> attempt { attempts.incrementAndGet() }; attempt { attempts.incrementAndGet() } }) {
            committed.set(true)
        }
        assertEquals(2, attempts.get())
        assertTrue(committed.get())
    }

    @Test
    fun renewalSkipsTheCommitOnceTheIdentityIsForgotten() {
        val held = AtomicBoolean(true)
        val committed = AtomicBoolean(false)
        assertThrows(ForgottenIdentity::class.java) {
            gate.renewal("abc", { held.get() }, { attempt -> attempt {}; held.set(false) }) { committed.set(true) }
        }
        assertFalse(committed.get())
    }

    @Test
    fun forgetDuringARetrySleepReturnsAtOnceAndNoAttemptFollows() {
        val held = AtomicBoolean(true)
        val attempts = AtomicInteger()
        val committed = AtomicBoolean(false)
        val sleeping = CountDownLatch(1)
        val wake = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val renewing = Thread {
            try {
                gate.renewal("abc", { held.get() }, { attempt ->
                    IssueRetry.run(null, { _ -> attempt { if (attempts.incrementAndGet() == 1) throw IOException("first attempt fails") } }, { "00" },
                        { _ -> sleeping.countDown(); wake.await(5, TimeUnit.SECONDS) }) { _, _, _ -> }
                }) { committed.set(true) }
            } catch (t: Throwable) {
                failure.set(t)
            }
        }.apply { isDaemon = true; start() }
        assertTrue(sleeping.await(5, TimeUnit.SECONDS))
        val forgetting = Thread { gate.forget { held.set(false) } }.apply { isDaemon = true; start() }
        forgetting.join(1_000)
        assertFalse("forget must not wait for a retry sleep", forgetting.isAlive)
        wake.countDown()
        renewing.join(5_000)
        assertTrue(failure.get() is ForgottenIdentity)
        assertEquals(1, attempts.get())
        assertFalse(committed.get())
    }
}
