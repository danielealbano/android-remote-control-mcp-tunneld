package com.example.tunnelapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import java.security.ProviderException

class DevicePropsTest {
    @Test
    fun withPropsSucceedingNeverFallsBack() {
        var fallbacks = 0
        val r = DeviceProps.withFallback({ "with" }, { fail("must not fall back"); "without" }) { fallbacks++ }
        assertEquals("with", r)
        assertEquals(0, fallbacks)
    }

    @Test
    fun providerExceptionFallsBackOnceAndReportsTheCause() {
        val cause = ProviderException("Failed to generate key pair.")
        val seen = mutableListOf<ProviderException>()
        val r = DeviceProps.withFallback({ throw cause }, { "without" }) { seen += it }
        assertEquals("without", r)
        assertEquals(listOf(cause), seen)
    }

    @Test
    fun otherFailuresPropagateWithoutFallback() {
        val boom = IllegalStateException("boom")
        try {
            DeviceProps.withFallback<String>({ throw boom }, { fail("must not fall back"); "without" }) { fail("must not report") }
            fail("expected the failure to propagate")
        } catch (e: IllegalStateException) {
            assertSame(boom, e)
        }
    }

    @Test
    fun fallbackFailureReachesTheCaller() {
        val second = ProviderException("still failing")
        try {
            DeviceProps.withFallback<String>({ throw ProviderException("first") }, { throw second }) {}
            fail("expected the fallback's failure to propagate")
        } catch (e: ProviderException) {
            assertSame(second, e)
        }
    }
}
