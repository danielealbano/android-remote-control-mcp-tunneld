package com.example.soakapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.Closeable
import java.io.IOException

class SessionsTest {
    private class Fake(private val fail: Boolean = false) : Closeable {
        var closed = 0
        override fun close() {
            closed++
            if (fail) throw IOException("close failed")
        }
    }

    @Test
    fun closeAllClosesRegisteredItems() {
        val s = Sessions {}
        val a = Fake()
        assertTrue(s.add(a))
        s.closeAll()
        assertEquals(1, a.closed)
        assertTrue(s.isClosed())
    }

    @Test
    fun addAfterCloseAllClosesTheItemAndRefusesIt() {
        val s = Sessions {}
        s.closeAll()
        val a = Fake()
        assertFalse(s.add(a))
        assertEquals(1, a.closed)
    }

    @Test
    fun releasedItemIsNotClosed() {
        val s = Sessions {}
        val a = Fake()
        s.add(a)
        s.release(a)
        s.closeAll()
        assertEquals(0, a.closed)
    }

    @Test
    fun closeErrorReachesTheCallback() {
        val errors = mutableListOf<Throwable>()
        val s = Sessions { errors.add(it) }
        s.add(Fake(fail = true))
        s.closeAll()
        assertEquals(1, errors.size)
    }
}
