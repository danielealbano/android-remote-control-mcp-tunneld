package com.example.soakapp

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class Event(val at: Long, val text: String)

data class Snapshot(
    val at: Long,
    val state: String,
    val phones: Int,
    val connected: Int,
    val reconnecting: Int,
    val byNode: Map<String, Int>,
    val reconnects: Long,
    val lastReconnect: Long,
    val served: Long,
    val errors: Long,
    val bytesIn: Long,
    val bytesOut: Long,
    val lastError: Event?,
    val enrolled: Long,
    val resumed: Long,
    val issued: Map<String, Long>,
    val renewals: Long,
    val enrollFailures: Long,
    val lastEnrollFailure: Event?,
    val issueFailures: Long,
    val lastIssueFailure: Event?,
    val commandError: Event?,
)

class Stats(private val clock: () -> Long = System::currentTimeMillis) {
    private val served = AtomicLong()
    private val errors = AtomicLong()
    private val bytesIn = AtomicLong()
    private val bytesOut = AtomicLong()
    private val enrolled = AtomicLong()
    private val resumed = AtomicLong()
    private val renewals = AtomicLong()
    private val enrollFailures = AtomicLong()
    private val issueFailures = AtomicLong()
    private val reconnects = AtomicLong()
    private val lastReconnect = AtomicLong()
    private val issued = ConcurrentHashMap<String, AtomicLong>()
    private val nodes = ConcurrentHashMap<Int, String>()
    private val reconnecting = ConcurrentHashMap.newKeySet<Int>()
    private val lastError = AtomicReference<Event?>()
    private val lastEnrollFailure = AtomicReference<Event?>()
    private val lastIssueFailure = AtomicReference<Event?>()
    private val commandError = AtomicReference<Event?>()

    fun served(requestBytes: Long, responseBytes: Long) {
        served.incrementAndGet()
        bytesIn.addAndGet(requestBytes)
        bytesOut.addAndGet(responseBytes)
    }

    fun error(text: String) {
        errors.incrementAndGet()
        lastError.set(Event(clock(), text))
    }

    fun enrolled() { enrolled.incrementAndGet() }

    fun resumed() { resumed.incrementAndGet() }

    fun issued(ca: String) { issued.computeIfAbsent(ca) { AtomicLong() }.incrementAndGet() }

    fun renewed(ca: String) {
        renewals.incrementAndGet()
        issued(ca)
    }

    fun enrollFailed(text: String) {
        enrollFailures.incrementAndGet()
        lastEnrollFailure.set(Event(clock(), text))
    }

    fun issueFailed(text: String) {
        issueFailures.incrementAndGet()
        lastIssueFailure.set(Event(clock(), text))
    }

    fun commandFailed(text: String) { commandError.set(Event(clock(), text)) }

    fun connected(phone: Int, node: String, reconnect: Boolean) {
        reconnecting.remove(phone)
        nodes[phone] = node
        if (reconnect) {
            reconnects.incrementAndGet()
            lastReconnect.set(clock())
        }
    }

    fun disconnected(phone: Int) {
        nodes.remove(phone)
        reconnecting.add(phone)
    }

    fun removed(phone: Int) {
        nodes.remove(phone)
        reconnecting.remove(phone)
    }

    fun snapshot(state: String, phones: Int): Snapshot = Snapshot(
        at = clock(), state = state, phones = phones,
        connected = nodes.size, reconnecting = reconnecting.size,
        byNode = nodes.values.groupingBy { it }.eachCount().toSortedMap(),
        reconnects = reconnects.get(), lastReconnect = lastReconnect.get(),
        served = served.get(), errors = errors.get(), bytesIn = bytesIn.get(), bytesOut = bytesOut.get(),
        lastError = lastError.get(),
        enrolled = enrolled.get(), resumed = resumed.get(),
        issued = issued.mapValues { it.value.get() }.toSortedMap(),
        renewals = renewals.get(), enrollFailures = enrollFailures.get(), lastEnrollFailure = lastEnrollFailure.get(),
        issueFailures = issueFailures.get(), lastIssueFailure = lastIssueFailure.get(),
        commandError = commandError.get(),
    )
}
