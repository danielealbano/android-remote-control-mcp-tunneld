package com.example.tunnelapp

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

internal class ForgottenIdentity(name: String) : RuntimeException("identity $name was forgotten")

internal class RenewGate {
    private val lock = ReentrantReadWriteLock()

    fun <T> renew(name: String, current: () -> Boolean, block: () -> T): T =
        lock.read { if (current()) block() else throw ForgottenIdentity(name) }

    fun renewal(name: String, current: () -> Boolean, issue: ((() -> Unit) -> Unit) -> Unit, commit: () -> Unit) {
        issue { attempt -> renew(name, current, attempt) }
        renew(name, current, commit)
    }

    fun <T> forget(block: () -> T): T = lock.write(block)
}
