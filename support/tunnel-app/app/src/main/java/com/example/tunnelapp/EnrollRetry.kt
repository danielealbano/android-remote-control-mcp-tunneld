package com.example.tunnelapp

import java.io.IOException
import java.security.ProviderException

internal object EnrollRetry {
    const val REFUSAL_WAIT_MS = 1_000L
    const val NETWORK_WAIT_MS = 2_000L
    const val KEYGEN_WAIT_MS = 3_000L

    fun waitMs(t: Throwable): Long? = when (t) {
        is EnrollError -> if (t.retryable) maxOf(t.retryAfterSec * 1000, REFUSAL_WAIT_MS) else null
        is IOException -> NETWORK_WAIT_MS
        is ProviderException -> KEYGEN_WAIT_MS
        else -> null
    }

    fun <T> run(
        retries: Int,
        freshNonce: () -> String,
        enroll: (String) -> T,
        sleep: (Long) -> Unit,
        onRetry: (Int, Long, Throwable) -> Unit,
    ): T {
        var nonce: String? = null
        var retry = 0
        while (true) {
            try {
                val current = nonce ?: freshNonce().also { nonce = it }
                return enroll(current)
            } catch (t: Throwable) {
                val wait = waitMs(t)
                if (wait == null || retry >= retries) throw t
                retry++
                onRetry(retry, wait, t)
                sleep(wait)
                if (t !is ProviderException) nonce = null
            }
        }
    }
}
