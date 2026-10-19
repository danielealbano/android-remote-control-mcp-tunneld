package com.example.soakapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.security.ProviderException

class IssueRetryTest {
    private class Recorder(failures: List<Throwable>, private val nonceFailures: List<Throwable> = emptyList()) {
        private val pending = ArrayDeque(failures)
        private val pendingNonce = ArrayDeque(nonceFailures)
        val issued = mutableListOf<String>()
        val sleeps = mutableListOf<Long>()
        var fetched = 0

        fun issue(n: String) {
            issued += n
            pending.removeFirstOrNull()?.let { throw it }
        }

        fun freshNonce(): String {
            fetched++
            pendingNonce.removeFirstOrNull()?.let { throw it }
            return "fresh-$fetched"
        }

        fun run(nonce: String?) = IssueRetry.run(nonce, this::issue, this::freshNonce, { sleeps += it }) { _, _, _ -> }
    }

    private fun retryable(after: Long = 0) = EnrollError("acme_rate_limited", true, after, 503)

    @Test
    fun successFirstTryNoSleep() {
        val r = Recorder(emptyList())
        r.run("n0")
        assertEquals(listOf("n0"), r.issued)
        assertEquals(emptyList<Long>(), r.sleeps)
        assertEquals(0, r.fetched)
    }

    @Test
    fun nullNonceFetchesFirst() {
        val r = Recorder(emptyList(), listOf(IOException("nonce endpoint down")))
        r.run(null)
        assertEquals(listOf("fresh-2"), r.issued)
        assertEquals(listOf(5_000L), r.sleeps)
        assertEquals(2, r.fetched)
    }

    @Test
    fun retryAfterHonoured() {
        val r = Recorder(listOf(retryable(7)))
        r.run("n0")
        assertEquals(listOf("n0", "fresh-1"), r.issued)
        assertEquals(listOf(7_000L), r.sleeps)
    }

    @Test
    fun defaultSchedule() {
        val last = retryable()
        val r = Recorder(listOf(retryable(), retryable(), retryable(), last))
        try {
            r.run("n0")
            fail("the 4th failure must be rethrown")
        } catch (t: EnrollError) {
            assertSame(last, t)
        }
        assertEquals(listOf(5_000L, 10_000L, 15_000L), r.sleeps)
        assertEquals(4, r.issued.size)
    }

    @Test
    fun ioExceptionRetried() {
        val r = Recorder(listOf(IOException("reset"), IOException("reset")))
        r.run("n0")
        assertEquals(listOf(5_000L, 10_000L), r.sleeps)
        assertEquals(listOf("n0", "fresh-1", "fresh-2"), r.issued)
    }

    @Test
    fun nonRetryableStops() {
        val err = EnrollError("bad_csr", false, 0, 400)
        val r = Recorder(listOf(err))
        try {
            r.run("n0")
            fail("a non-retryable error must be rethrown")
        } catch (t: EnrollError) {
            assertSame(err, t)
        }
        assertEquals(emptyList<Long>(), r.sleeps)
    }

    @Test
    fun freshNonceFailureCountsAsRetry() {
        val r = Recorder(listOf(retryable()), listOf(IOException("nonce endpoint down")))
        r.run("n0")
        assertEquals(listOf(5_000L, 10_000L), r.sleeps)
        assertEquals(listOf("n0", "fresh-2"), r.issued)
    }

    @Test
    fun otherThrowableStops() {
        val err = IllegalStateException("bug")
        val r = Recorder(listOf(err))
        try {
            r.run("n0")
            fail("an unexpected throwable must be rethrown")
        } catch (t: IllegalStateException) {
            assertSame(err, t)
        }
        assertEquals(emptyList<Long>(), r.sleeps)
    }

    @Test
    fun keyGenerationFailureRetriesFiveTimesTwoSecondsApart() {
        val r = Recorder(List(5) { ProviderException("Failed to generate key pair.") })
        r.run("n0")
        assertEquals(List(6) { "n0" }, r.issued)
        assertEquals(List(5) { 2_000L }, r.sleeps)
        assertEquals(0, r.fetched)
    }

    @Test
    fun keyGenerationFailureGivesUpAfterFiveRetries() {
        val last = ProviderException("Failed to generate key pair.")
        val r = Recorder(List(5) { ProviderException("Failed to generate key pair.") } + last)
        try {
            r.run("n0")
            fail("a sixth key generation failure must be thrown")
        } catch (t: ProviderException) {
            assertSame(last, t)
        }
        assertEquals(List(6) { "n0" }, r.issued)
        assertEquals(List(5) { 2_000L }, r.sleeps)
        assertEquals(0, r.fetched)
    }

    @Test
    fun keyGenerationRetriesDoNotUseTheOtherRetries() {
        val r = Recorder(List(5) { ProviderException("Failed to generate key pair.") } + List(3) { retryable(1) })
        r.run("n0")
        assertEquals(List(6) { "n0" } + listOf("fresh-1", "fresh-2", "fresh-3"), r.issued)
        assertEquals(List(5) { 2_000L } + List(3) { 1_000L }, r.sleeps)
    }

    @Test
    fun keyGenerationFailureAfterARefusalReusesTheFetchedNonce() {
        val r = Recorder(listOf(retryable(1), ProviderException("Failed to generate key pair.")))
        r.run("n0")
        assertEquals(listOf("n0", "fresh-1", "fresh-1"), r.issued)
        assertEquals(listOf(1_000L, 2_000L), r.sleeps)
        assertEquals(1, r.fetched)
    }

    @Test
    fun keyGenerationFailureWithoutANonceFetchesOnlyOnce() {
        val r = Recorder(listOf(ProviderException("Failed to generate key pair.")))
        r.run(null)
        assertEquals(listOf("fresh-1", "fresh-1"), r.issued)
        assertEquals(listOf(2_000L), r.sleeps)
        assertEquals(1, r.fetched)
    }
}
