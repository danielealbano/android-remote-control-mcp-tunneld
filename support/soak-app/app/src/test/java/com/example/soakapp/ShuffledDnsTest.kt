package com.example.soakapp

import okhttp3.Dns
import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.InetAddress
import kotlin.random.Random

class ShuffledDnsTest {
    private val nodes = (1..4).map { InetAddress.getByAddress(byteArrayOf(10, 0, 0, it.toByte())) }

    @Test
    fun everyLookupIsAPermutationAndEveryNodeComesFirst() {
        val dns = ShuffledDns(Dns { nodes }, Random(42))
        val first = mutableMapOf<InetAddress, Int>()
        repeat(400) {
            val got = dns.lookup("connect.example.test")
            assertEquals(nodes.toSet(), got.toSet())
            assertEquals(nodes.size, got.size)
            first.merge(got[0], 1, Int::plus)
        }
        assertEquals(nodes.toSet(), first.keys)
        first.values.forEach { assert(it in 60..140) { "first-address counts are uneven: $first" } }
    }
}
