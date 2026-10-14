package com.example.soakapp

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.request.receive
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference

class Server(private val port: Int) {
    private class Material(val key: PrivateKey, val chain: Array<X509Certificate>)
    private val material = AtomicReference<Material>()
    private var engine: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>? = null
    private var stopped = false

    fun localPort() = port

    @Synchronized
    fun start(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
        if (stopped) return
        material.set(Material(tlsKey, chain)); engine = buildEngine().also { it.start(wait = false) }
    }

    @Synchronized
    fun swapIdentity(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
        if (stopped) return
        material.set(Material(tlsKey, chain)); engine?.stop(100, 500)
        engine = buildEngine().also { it.start(wait = false) }
    }

    @Synchronized
    fun stop() { stopped = true; engine?.stop(100, 500); engine = null }

    private fun buildEngine(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
        val ks = ServerTls.keyStore(material.get().key, material.get().chain)
        return embeddedServer(
            factory = Netty,
            configure = {
                sslConnector(
                    keyStore = ks, keyAlias = ServerTls.ALIAS,
                    keyStorePassword = { ServerTls.PASSWORD }, privateKeyPassword = { ServerTls.PASSWORD },
                ) { host = "127.0.0.1"; port = this@Server.port }
            },
            module = {
                routing {
                    post("/op") {
                        val raw = call.request.queryParameters["resp"]
                        val n = raw?.toIntOrNull()?.takeIf { it in 0..MAX_RESPONSE } ?: run {
                            call.respondText("bad resp: $raw", status = HttpStatusCode.BadRequest)
                            return@post
                        }
                        call.receive<ByteArray>()
                        call.respondBytes(PATTERN.copyOf(n), ContentType.Application.OctetStream)
                    }
                }
            },
        )
    }

    companion object {
        const val MAX_RESPONSE = 65536
        private val PATTERN = ByteArray(MAX_RESPONSE) { (it % 251).toByte() }
    }
}
