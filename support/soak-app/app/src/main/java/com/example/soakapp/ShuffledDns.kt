package com.example.soakapp

import okhttp3.Dns
import java.net.InetAddress
import kotlin.random.Random

class ShuffledDns(private val base: Dns, private val random: Random = Random.Default) : Dns {
    override fun lookup(hostname: String): List<InetAddress> = base.lookup(hostname).shuffled(random)
}
