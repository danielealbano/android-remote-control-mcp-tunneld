package com.example.soakapp

import android.os.BatteryManager
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class Device(
    val uptimeMs: Long,
    val batteryPct: Int,
    val temperatureC: Double,
    val power: String,
    val heapUsedMb: Long,
    val heapMaxMb: Long,
    val nativeMb: Long,
    val threads: Int,
)

class Screen(
    private val window: Long = 60_000L,
    private val clockText: (Long) -> String = { SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(Date(it)) },
) {
    private val history = ArrayDeque<Snapshot>()

    fun render(s: Snapshot, d: Device): String {
        history.addLast(s)
        while (history.size > 1 && s.at - history[1].at >= window) history.removeFirst()
        val base = history.first().takeIf { it !== s && s.at > it.at }
        fun rate(value: (Snapshot) -> Long): Long? = base?.let { (value(s) - value(it)) * 60_000L / (s.at - it.at) }
        fun bitRate(value: (Snapshot) -> Long): String = base?.let { mbits((value(s) - value(it)) * 8_000.0 / (s.at - it.at)) } ?: "-"
        val out = StringBuilder()
        fun line(text: String) { out.append(text).append('\n') }

        line("soak-app · ${s.state} · ${clockText(s.at)}")
        s.commandError?.let { line("command failed ${clockText(it.at)}: ${clip(it.text)}") }
        line("")
        line("PHONES")
        line(" ${count(s.phones.toLong())} total, ${count(s.connected.toLong())} connected, ${count(s.reconnecting.toLong())} reconnecting")
        s.byNode.forEach { (node, n) -> line(" %-16s %s".format(Locale.ROOT, node, count(n.toLong()))) }
        line(" reconnects ${count(s.reconnects)}" + if (s.lastReconnect > 0) ", last ${ago(s.at, s.lastReconnect)}" else "")
        line("")
        line("TRAFFIC")
        line(" served ${count(s.served)}${perMinute(rate { it.served }, ::count)}")
        line(" errors ${count(s.errors)}${perMinute(rate { it.errors }, ::count)}")
        line(" in ${bitRate { it.bytesIn }}")
        line(" out ${bitRate { it.bytesOut }}")
        s.lastError?.let { line(" last error ${clockText(it.at)} (${ago(s.at, it.at)})"); line("  ${clip(it.text)}") }
        line("")
        line("CERTIFICATES")
        line(" enrolled ${count(s.enrolled)}, resumed ${count(s.resumed)}")
        line(" issued " + if (s.issued.isEmpty()) "0" else s.issued.entries.joinToString(", ") { "${it.key} ${count(it.value)}" })
        line(" renewals ${count(s.renewals)}")
        line(" enrollment failures ${count(s.enrollFailures)}")
        s.lastEnrollFailure?.let { line(" last ${clockText(it.at)} (${ago(s.at, it.at)})"); line("  ${clip(it.text)}") }
        line(" issuance failures ${count(s.issueFailures)}")
        s.lastIssueFailure?.let { line(" last ${clockText(it.at)} (${ago(s.at, it.at)})"); line("  ${clip(it.text)}") }
        line("")
        line("DEVICE")
        line(" app uptime ${duration(d.uptimeMs)}")
        line(" battery ${d.batteryPct}%, ${"%.1f".format(Locale.ROOT, d.temperatureC)} °C, ${d.power}")
        line(" heap ${d.heapUsedMb} / ${d.heapMaxMb} MiB, native ${d.nativeMb} MiB")
        line(" threads ${count(d.threads.toLong())}")
        return out.toString()
    }

    private fun perMinute(value: Long?, format: (Long) -> String): String = value?.let { " (${format(it)}/min)" } ?: ""

    companion object {
        private const val MAX_TEXT = 300

        fun count(n: Long): String = "%,d".format(Locale.ROOT, n)

        fun mbits(bitsPerSecond: Double): String = "%.3f Mbit/s".format(Locale.ROOT, bitsPerSecond / 1_000_000)

        fun duration(ms: Long): String {
            val s = ms / 1000
            return when {
                s < 60 -> "${s}s"
                s < 3600 -> "${s / 60}m ${s % 60}s"
                s < 86400 -> "${s / 3600}h ${s % 3600 / 60}m"
                else -> "${s / 86400}d ${s % 86400 / 3600}h"
            }
        }

        fun ago(now: Long, at: Long): String = "${duration(maxOf(0L, now - at))} ago"

        fun clip(text: String): String = if (text.length <= MAX_TEXT) text else text.take(MAX_TEXT) + "…"

        fun power(plugged: Int, status: Int): String {
            val source = when (plugged) {
                BatteryManager.BATTERY_PLUGGED_AC -> "AC"
                BatteryManager.BATTERY_PLUGGED_USB -> "USB"
                BatteryManager.BATTERY_PLUGGED_WIRELESS -> "wireless"
                BatteryManager.BATTERY_PLUGGED_DOCK -> "dock"
                0 -> "on battery"
                else -> "power unknown"
            }
            val state = when (status) {
                BatteryManager.BATTERY_STATUS_CHARGING -> "charging"
                BatteryManager.BATTERY_STATUS_DISCHARGING -> "discharging"
                BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "not charging"
                BatteryManager.BATTERY_STATUS_FULL -> "full"
                else -> "status unknown"
            }
            return "$source, $state"
        }
    }
}
