package com.example.soakapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.security.ProviderException

class EnrollRetryTest {
    private class Recorder(failures: List<Throwable>, nonceFailures: List<Throwable> = emptyList()) {
        private val pending = ArrayDeque(failures)
        private val pendingNonce = ArrayDeque(nonceFailures)
        val enrolled = mutableListOf<String>()
        val sleeps = mutableListOf<Long>()
        val retries = mutableListOf<Int>()
        var fetched = 0

        fun enroll(n: String): String {
            enrolled += n
            pending.removeFirstOrNull()?.let { throw it }
            return "name-$n"
        }

        fun freshNonce(): String {
            fetched++
            pendingNonce.removeFirstOrNull()?.let { throw it }
            return "nonce-$fetched"
        }

        fun run(retries: Int = 3): String =
            EnrollRetry.run(retries, this::freshNonce, this::enroll, { sleeps += it }) { n, _, _ -> this.retries += n }
    }

    private fun refused(after: Long = 0) = EnrollError("registry_unavailable", true, after, 503)

    @Test
    fun successFirstTry() {
        val r = Recorder(emptyList())
        assertEquals("name-nonce-1", r.run())
        assertEquals(listOf("nonce-1"), r.enrolled)
        assertEquals(emptyList<Long>(), r.sleeps)
    }

    @Test
    fun refusalHonoursRetryAfterWithAFreshNonce() {
        val r = Recorder(listOf(refused(7)))
        assertEquals("name-nonce-2", r.run())
        assertEquals(listOf("nonce-1", "nonce-2"), r.enrolled)
        assertEquals(listOf(7_000L), r.sleeps)
    }

    @Test
    fun refusalWithoutRetryAfterWaitsOneSecond() {
        val r = Recorder(listOf(refused()))
        r.run()
        assertEquals(listOf(1_000L), r.sleeps)
    }

    @Test
    fun networkErrorWaitsTwoSecondsWithAFreshNonce() {
        val r = Recorder(listOf(IOException("connection reset")))
        r.run()
        assertEquals(listOf("nonce-1", "nonce-2"), r.enrolled)
        assertEquals(listOf(2_000L), r.sleeps)
    }

    @Test
    fun keyGenerationFailureReusesTheUnusedNonceAfterThreeSeconds() {
        val r = Recorder(listOf(ProviderException("Failed to generate key pair.")))
        assertEquals("name-nonce-1", r.run())
        assertEquals(listOf("nonce-1", "nonce-1"), r.enrolled)
        assertEquals(listOf(3_000L), r.sleeps)
        assertEquals(1, r.fetched)
    }

    @Test
    fun failedNonceFetchIsRetriedLikeAnyOtherFailure() {
        val r = Recorder(emptyList(), listOf(IOException("nonce endpoint down")))
        assertEquals("name-nonce-2", r.run())
        assertEquals(listOf("nonce-2"), r.enrolled)
        assertEquals(listOf(2_000L), r.sleeps)
    }

    @Test
    fun givesUpAfterTheConfiguredRetries() {
        val last = refused()
        val r = Recorder(List(3) { refused() } + last)
        try {
            r.run(3)
            fail("the fourth refusal must be thrown")
        } catch (t: EnrollError) {
            assertSame(last, t)
        }
        assertEquals(4, r.enrolled.size)
        assertEquals(listOf(1, 2, 3), r.retries)
        assertEquals(List(3) { 1_000L }, r.sleeps)
    }

    @Test
    fun theRetryCountIsAParameter() {
        val r = Recorder(List(10) { IOException("down") })
        assertEquals("name-nonce-11", r.run(10))
        assertEquals(11, r.enrolled.size)
    }

    @Test
    fun nonRetryableRefusalStops() {
        val banned = EnrollError("banned", false, 0, 403)
        val r = Recorder(listOf(banned))
        try {
            r.run()
            fail("a non-retryable refusal must be thrown")
        } catch (t: EnrollError) {
            assertSame(banned, t)
        }
        assertEquals(emptyList<Long>(), r.sleeps)
    }

    @Test
    fun otherErrorsStop() {
        val bad = IllegalStateException("malformed answer")
        val r = Recorder(listOf(bad))
        try {
            r.run()
            fail("an unexpected error must be thrown")
        } catch (t: IllegalStateException) {
            assertSame(bad, t)
        }
        assertEquals(1, r.enrolled.size)
    }
}
