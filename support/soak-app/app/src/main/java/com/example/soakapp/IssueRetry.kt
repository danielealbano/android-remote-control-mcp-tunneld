package com.example.soakapp

import java.io.IOException

internal object IssueRetry {
    const val RETRIES = 3

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
        while (true) {
            try {
                issue(n ?: freshNonce())
                return
            } catch (t: Throwable) {
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
