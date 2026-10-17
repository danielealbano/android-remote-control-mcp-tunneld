package com.example.tunnelapp

import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class Event(val at: Long, val text: String)

class Certificate(val name: String, val ca: String, val notAfter: Long)

data class Snapshot(
    val at: Long,
    val state: String,
    val node: String?,
    val reconnects: Long,
    val lastReconnect: Long,
    val requests: Long,
    val connections: Long,
    val errors: Long,
    val bytesIn: Long,
    val bytesOut: Long,
    val lastError: Event?,
    val certificate: Certificate?,
    val renewals: Long,
    val enrollFailures: Long,
    val lastEnrollFailure: Event?,
    val issueFailures: Long,
    val lastIssueFailure: Event?,
    val commandError: Event?,
)

class Stats(private val clock: () -> Long = System::currentTimeMillis) {
    private val requests = AtomicLong()
    private val connections = AtomicLong()
    private val errors = AtomicLong()
    private val bytesIn = AtomicLong()
    private val bytesOut = AtomicLong()
    private val renewals = AtomicLong()
    private val enrollFailures = AtomicLong()
    private val issueFailures = AtomicLong()
    private val reconnects = AtomicLong()
    private val lastReconnect = AtomicLong()
    private val link = AtomicReference<String?>(null)
    private val node = AtomicReference<String?>(null)
    private val certificate = AtomicReference<Certificate?>(null)
    private val lastError = AtomicReference<Event?>()
    private val lastEnrollFailure = AtomicReference<Event?>()
    private val lastIssueFailure = AtomicReference<Event?>()
    private val commandError = AtomicReference<Event?>()

    fun request() { requests.incrementAndGet() }

    fun connection() { connections.incrementAndGet() }

    fun bytesIn(n: Int) { bytesIn.addAndGet(n.toLong()) }

    fun bytesOut(n: Int) { bytesOut.addAndGet(n.toLong()) }

    fun error(text: String) {
        errors.incrementAndGet()
        lastError.set(Event(clock(), text))
    }

    fun certificate(name: String, ca: String, notAfter: Long) { certificate.set(Certificate(name, ca, notAfter)) }

    fun renewed() { renewals.incrementAndGet() }

    fun enrollFailed(text: String) {
        enrollFailures.incrementAndGet()
        lastEnrollFailure.set(Event(clock(), text))
    }

    fun issueFailed(text: String) {
        issueFailures.incrementAndGet()
        lastIssueFailure.set(Event(clock(), text))
    }

    fun commandFailed(text: String) { commandError.set(Event(clock(), text)) }

    fun connected(at: String, reconnect: Boolean) {
        link.set("connected")
        node.set(at)
        if (reconnect) {
            reconnects.incrementAndGet()
            lastReconnect.set(clock())
        }
    }

    fun disconnected() {
        link.set("reconnecting")
        node.set(null)
    }

    fun stopped() {
        link.set(null)
        node.set(null)
    }

    fun snapshot(): Snapshot = Snapshot(
        at = clock(), state = link.get() ?: "stopped", node = node.get(),
        reconnects = reconnects.get(), lastReconnect = lastReconnect.get(),
        requests = requests.get(), connections = connections.get(), errors = errors.get(),
        bytesIn = bytesIn.get(), bytesOut = bytesOut.get(), lastError = lastError.get(),
        certificate = certificate.get(), renewals = renewals.get(),
        enrollFailures = enrollFailures.get(), lastEnrollFailure = lastEnrollFailure.get(), issueFailures = issueFailures.get(),
        lastIssueFailure = lastIssueFailure.get(), commandError = commandError.get(),
    )
}
