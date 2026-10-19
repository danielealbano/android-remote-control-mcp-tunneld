package com.example.tunnelapp

import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.SocketHandler
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import okio.Socket
import java.net.InetAddress

internal object ControlServer {
    const val HOST = "connect.example.test"
    val held: HeldCertificate = HeldCertificate.Builder().commonName(HOST).addSubjectAlternativeName(HOST).build()
    private val serverCerts = HandshakeCertificates.Builder().heldCertificate(held).build()
    private val clientCerts = HandshakeCertificates.Builder().addTrustedCertificate(held.certificate).build()

    fun start(): MockWebServer = MockWebServer().also {
        it.useHttps(serverCerts.sslSocketFactory())
        it.start(InetAddress.getLoopbackAddress(), 0)
    }

    fun client(): OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager)
        .dns { listOf(InetAddress.getLoopbackAddress()) }
        .build()

    fun answer(code: Int, onStream: (Socket) -> Unit): MockResponse =
        MockResponse.Builder().code(code).removeHeader("Content-Length").socketHandler(object : SocketHandler {
            override fun handle(socket: Socket) = onStream(socket)
        }).build()

    fun frame(type: Int, payload: String = ""): ByteArray {
        val p = payload.toByteArray()
        return Buffer().writeByte(type).writeInt(p.size).write(p).readByteArray()
    }
}
