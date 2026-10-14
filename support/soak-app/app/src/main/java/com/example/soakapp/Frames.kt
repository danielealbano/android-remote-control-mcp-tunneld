package com.example.soakapp

import okio.BufferedSource
import java.io.IOException

object Frames {
    const val OPEN = 1
    const val PING = 2
    const val PONG = 3
    const val RENEW_NUDGE = 4
    private const val MAX = 1 shl 20

    val PONG_FRAME = byteArrayOf(PONG.toByte(), 0, 0, 0, 0)

    fun read(source: BufferedSource): Pair<Int, ByteArray>? {
        if (source.exhausted()) return null
        val type = source.readByte().toInt() and 0xff
        val len = source.readInt()
        if (len < 0 || len > MAX) throw IOException("control frame too large: $len")
        return type to (if (len == 0) ByteArray(0) else source.readByteArray(len.toLong()))
    }
}
