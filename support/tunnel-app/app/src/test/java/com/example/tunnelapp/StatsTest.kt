package com.example.tunnelapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StatsTest {
    private var now = 1_000L
    private val stats = Stats { now }

    @Test
    fun tracksTheLinkAndReconnects() {
        assertEquals("stopped", stats.snapshot().state)
        stats.connected("10.0.0.1", reconnect = false)
        var s = stats.snapshot()
        assertEquals("connected", s.state)
        assertEquals("10.0.0.1", s.node)
        assertEquals(0L, s.reconnects)
        stats.disconnected()
        s = stats.snapshot()
        assertEquals("reconnecting", s.state)
        assertNull(s.node)
        now = 7_000L
        stats.connected("10.0.0.2", reconnect = true)
        s = stats.snapshot()
        assertEquals(1L, s.reconnects)
        assertEquals(7_000L, s.lastReconnect)
        stats.stopped()
        assertEquals("stopped", stats.snapshot().state)
    }

    @Test
    fun countsTrafficAndCertificates() {
        stats.request()
        stats.request()
        stats.connection()
        stats.bytesIn(10)
        stats.bytesOut(20)
        stats.error("dial-back failed")
        stats.certificate("abc", "gts", 9_000L)
        stats.renewed()
        stats.issueFailed("renewal failed: boom")
        stats.enrollFailed("enroll: refused")
        stats.commandFailed("refresh: boom")
        val s = stats.snapshot()
        assertEquals(2L, s.requests)
        assertEquals(1L, s.connections)
        assertEquals(10L, s.bytesIn)
        assertEquals(20L, s.bytesOut)
        assertEquals(1L, s.errors)
        assertEquals("dial-back failed", s.lastError?.text)
        assertEquals("gts", s.certificate?.ca)
        assertEquals(9_000L, s.certificate?.notAfter)
        assertEquals(1L, s.renewals)
        assertEquals(1L, s.issueFailures)
        assertEquals("renewal failed: boom", s.lastIssueFailure?.text)
        assertEquals(1L, s.enrollFailures)
        assertEquals("enroll: refused", s.lastEnrollFailure?.text)
        assertEquals("refresh: boom", s.commandError?.text)
    }
}
