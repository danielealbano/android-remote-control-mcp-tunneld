package com.example.tunnelapp

import android.os.BatteryManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScreenTest {
    private val device = Device(
        uptimeMs = 61_000, batteryPct = 55, temperatureC = 29.0, power = "AC, charging",
        heapUsedMb = 40, heapMaxMb = 256, nativeMb = 20, threads = 42,
    )

    private fun snapshot(at: Long, requests: Long, bytesIn: Long = 2048) = Snapshot(
        at = at, state = "connected", node = "10.0.0.1", reconnects = 0, lastReconnect = 0,
        requests = requests, connections = 1, errors = 0, bytesIn = bytesIn, bytesOut = 0, lastError = null,
        certificate = Certificate("abc", "letsencrypt", at + 90_000_000), renewals = 1, enrollFailures = 0,
        lastEnrollFailure = null, issueFailures = 2, lastIssueFailure = Event(at - 5_000, "renewal failed: boom"), commandError = null,
    )

    @Test
    fun rendersTheTunnel() {
        val text = Screen(clockText = { "T$it" }, dateText = { "D$it" }).render(snapshot(1_000_000, 3), device)
        assertFalse(text.contains("/min"))
        assertTrue(text.contains("tunnel-app · connected · T1000000"))
        assertTrue(text.contains(" name abc"))
        assertTrue(text.contains(" node 10.0.0.1"))
        assertTrue(text.contains(" reconnects 0\n"))
        assertTrue(text.contains(" in -\n out -\n"))
        assertTrue(text.contains(" CA letsencrypt"))
        assertTrue(text.contains(" enrollment failures 0\n issuance failures 2\n last T995000 (5s ago)\n  renewal failed: boom"))
        assertTrue(text.contains(" expires D91000000 (in 1d 1h)"))
        assertTrue(text.contains(" battery 55%, 29.0 °C, AC, charging"))
        assertTrue(text.contains(" app uptime 1m 1s"))
    }

    @Test
    fun ratesUseTheSnapshotAMinuteAgo() {
        val screen = Screen(clockText = { "T$it" }, dateText = { "D$it" })
        screen.render(snapshot(0, 0), device)
        val text = screen.render(snapshot(30_000, 10, bytesIn = 2048 + 75_000), device)
        assertTrue(text, text.contains(" requests 10 (20/min)"))
        assertTrue(text, text.contains(" in 0.020 Mbit/s\n out 0.000 Mbit/s\n"))
    }

    @Test
    fun formats() {
        assertEquals("wireless, full", Screen.power(BatteryManager.BATTERY_PLUGGED_WIRELESS, BatteryManager.BATTERY_STATUS_FULL))
        assertEquals("0.125 Mbit/s", Screen.mbits(125_000.0))
        assertEquals("2h 0m", Screen.duration(7_200_000))
    }
}
