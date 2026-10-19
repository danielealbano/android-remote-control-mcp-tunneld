package com.example.soakapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StatsTest {
    private var now = 1_000L
    private val stats = Stats { now }

    @Test
    fun tracksPhonesPerNodeAndReconnects() {
        stats.connected(1, "10.0.0.1", reconnect = false)
        stats.connected(2, "10.0.0.2", reconnect = false)
        stats.connected(3, "10.0.0.1", reconnect = false)
        stats.disconnected(2)
        var s = stats.snapshot("running", 3)
        assertEquals(2, s.connected)
        assertEquals(1, s.reconnecting)
        assertEquals(mapOf("10.0.0.1" to 2), s.byNode)
        assertEquals(0L, s.reconnects)
        now = 5_000L
        stats.connected(2, "10.0.0.3", reconnect = true)
        stats.removed(1)
        s = stats.snapshot("running", 3)
        assertEquals(2, s.connected)
        assertEquals(0, s.reconnecting)
        assertEquals(mapOf("10.0.0.1" to 1, "10.0.0.3" to 1), s.byNode)
        assertEquals(1L, s.reconnects)
        assertEquals(5_000L, s.lastReconnect)
    }

    @Test
    fun countsTrafficErrorsAndCertificates() {
        stats.served(10, 100)
        stats.served(5, 50)
        stats.error("first")
        now = 2_000L
        stats.error("second")
        stats.enrolled()
        stats.resumed()
        stats.resumed()
        stats.issued("gts")
        stats.renewed("letsencrypt")
        stats.issueFailed("phone 4: boom")
        stats.enrollFailed("phone 5: refused")
        val s = stats.snapshot("running", 3)
        assertEquals(2L, s.served)
        assertEquals(15L, s.bytesIn)
        assertEquals(150L, s.bytesOut)
        assertEquals(2L, s.errors)
        assertEquals("second", s.lastError!!.text)
        assertEquals(2_000L, s.lastError.at)
        assertEquals(1L, s.enrolled)
        assertEquals(2L, s.resumed)
        assertEquals(mapOf("gts" to 1L, "letsencrypt" to 1L), s.issued)
        assertEquals(1L, s.renewals)
        assertEquals(1L, s.issueFailures)
        assertEquals("phone 4: boom", s.lastIssueFailure!!.text)
        assertEquals(1L, s.enrollFailures)
        assertEquals("phone 5: refused", s.lastEnrollFailure!!.text)
        assertNull(s.commandError)
    }
}
