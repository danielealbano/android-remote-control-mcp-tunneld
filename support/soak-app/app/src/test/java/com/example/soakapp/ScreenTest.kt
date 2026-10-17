package com.example.soakapp

import android.os.BatteryManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScreenTest {
    private val device = Device(
        uptimeMs = 3_725_000, batteryPct = 80, temperatureC = 31.5, power = "USB, not charging",
        heapUsedMb = 120, heapMaxMb = 512, nativeMb = 80, threads = 1234,
    )

    private fun snapshot(at: Long, served: Long, bytesOut: Long = 0) = Snapshot(
        at = at, state = "running", phones = 3, connected = 2, reconnecting = 1, byNode = mapOf("10.0.0.1" to 2),
        reconnects = 1, lastReconnect = at - 125_000, served = served, errors = 0, bytesIn = 0, bytesOut = bytesOut,
        lastError = Event(at - 30_000, "phone 1: dial-back failed"), enrolled = 1, resumed = 2,
        issued = mapOf("gts" to 3L), renewals = 0, enrollFailures = 1, lastEnrollFailure = Event(at - 60_000, "phone 2: enroll refused"),
        issueFailures = 0, lastIssueFailure = null, commandError = null,
    )

    @Test
    fun firstRenderHasNoRates() {
        val text = Screen(clockText = { "T$it" }).render(snapshot(1_000_000, 10), device)
        assertFalse(text.contains("/min"))
        assertTrue(text.contains(" in -\n out -\n"))
        assertTrue(text.contains("soak-app · running · T1000000"))
        assertTrue(text.contains(" 3 total, 2 connected, 1 reconnecting"))
        assertTrue(text.contains(" 10.0.0.1         2"))
        assertTrue(text.contains(" reconnects 1, last 2m 5s ago"))
        assertTrue(text.contains(" last error T970000 (30s ago)"))
        assertTrue(text.contains(" issued gts 3"))
        assertTrue(text.contains(" enrollment failures 1\n last T940000 (1m 0s ago)\n  phone 2: enroll refused\n issuance failures 0"))
        assertTrue(text.contains(" app uptime 1h 2m"))
        assertTrue(text.contains(" battery 80%, 31.5 °C, USB, not charging"))
        assertTrue(text.contains(" threads 1,234"))
    }

    @Test
    fun ratesUseTheSnapshotAMinuteAgo() {
        val screen = Screen(clockText = { "T$it" })
        screen.render(snapshot(0, 0), device)
        screen.render(snapshot(30_000, 300), device)
        val text = screen.render(snapshot(90_000, 1_500, bytesOut = 3L shl 20), device)
        assertTrue(text, text.contains(" served 1,500 (1,200/min)"))
        assertTrue(text, text.contains(" in 0.000 Mbit/s\n out 0.419 Mbit/s\n"))
    }

    @Test
    fun formats() {
        assertEquals("0.000 Mbit/s", Screen.mbits(0.0))
        assertEquals("0.002 Mbit/s", Screen.mbits(1_500.0))
        assertEquals("87.400 Mbit/s", Screen.mbits(87_400_000.0))
        assertEquals("59s", Screen.duration(59_000))
        assertEquals("1d 1h", Screen.duration(90_000_000))
        assertEquals("0s ago", Screen.ago(1_000, 5_000))
        assertEquals(301, Screen.clip("x".repeat(400)).length)
        assertEquals("USB, not charging", Screen.power(BatteryManager.BATTERY_PLUGGED_USB, BatteryManager.BATTERY_STATUS_NOT_CHARGING))
        assertEquals("on battery, discharging", Screen.power(0, BatteryManager.BATTERY_STATUS_DISCHARGING))
    }
}
