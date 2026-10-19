package com.example.tunnelapp

import java.io.IOException
import java.security.ProviderException

internal object IssueRetry {
    const val RETRIES = 3
    const val KEYGEN_RETRIES = 5
    const val KEYGEN_WAIT_MS = 2_000L

    fun waitMs(t: Throwable, retry: Int): Long? = when (t) {
        is EnrollError -> when {
            !t.retryable -> null
            t.retryAfterSec > 0 -> t.retryAfterSec * 1000
            else -> (retry + 1) * 5_000L
        }
        is IOException -> (retry + 1) * 5_000L
        else -> null
    }

    fun run(
        nonce: String?,
        issue: (String) -> Unit,
        freshNonce: () -> String,
        sleep: (Long) -> Unit,
        onRetry: (Int, Long, Throwable) -> Unit,
    ) {
        var n: String? = nonce
        var retry = 0
        var keygen = 0
        while (true) {
            try {
                val current = n ?: freshNonce().also { n = it }
                issue(current)
                return
            } catch (t: Throwable) {
                if (t is ProviderException && keygen < KEYGEN_RETRIES) {
                    keygen++
                    onRetry(keygen, KEYGEN_WAIT_MS, t)
                    sleep(KEYGEN_WAIT_MS)
                    continue
                }
                val wait = waitMs(t, retry)
                if (wait == null || retry >= RETRIES) throw t
                onRetry(retry + 1, wait, t)
                sleep(wait)
                n = null
                retry++
            }
        }
    }
}
