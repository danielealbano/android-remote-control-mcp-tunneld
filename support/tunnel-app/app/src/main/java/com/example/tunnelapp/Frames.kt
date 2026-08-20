package com.example.tunnelapp

import okio.BufferedSource
import java.io.IOException

// Frames is the v2 control-frame codec: [type:1][payloadLen:4 BE][payload JSON], 1 MiB cap. The data
// stream is opaque (no framing). Payloads: OPEN {stream_id}, RENEW_NUDGE {nonce, ari_window}.
object Frames {
    const val OPEN = 1
    const val PING = 2
    const val PONG = 3
    const val RENEW_NUDGE = 4
    private const val MAX = 1 shl 20

    val PONG_FRAME = byteArrayOf(PONG.toByte(), 0, 0, 0, 0)

    // read parses one frame from source (blocking); returns (type, payloadJsonBytes) or null on EOF.
    fun read(source: BufferedSource): Pair<Int, ByteArray>? = try {
        val type = source.readByte().toInt() and 0xff
        val len = source.readInt() // big-endian
        if (len < 0 || len > MAX) throw IOException("control frame too large: $len")
        type to (if (len == 0) ByteArray(0) else source.readByteArray(len.toLong()))
    } catch (_: Throwable) {
        null
    }
}
