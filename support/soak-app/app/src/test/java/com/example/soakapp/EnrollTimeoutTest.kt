package com.example.soakapp

import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Test

class EnrollTimeoutTest {
    @Test
    fun issueWaitsLongerThanTheServerCapAndEnrollKeepsItsTimeout() {
        assertEquals(400_000, Enroll.issueClient(OkHttpClient()).readTimeoutMillis)
        assertEquals(300_000, Enroll.enrollClient(OkHttpClient()).readTimeoutMillis)
    }
}
