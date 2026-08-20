package com.example.tunnelapp

import io.ktor.http.ContentType
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.delay
import org.json.JSONObject
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference

// Server is the phone's local HTTPS edge: Ktor on the Netty engine, TLS via sslConnector backed by the
// non-exportable TLS TEE key + issued cert (ServerTls). Fixed loopback port so a renewal restart is
// transparent (the tunnel splices to it per dial-back).
class Server(private val port: Int, private val appNonce: String, private val name: String) {
    private class Material(val key: PrivateKey, val chain: Array<X509Certificate>)
    private val material = AtomicReference<Material>()
    // engine is mutated by start/swapIdentity/stop from different threads; @Synchronized serializes them (so
    // two restarts can never double-bind the fixed port) and publishes engine safely. `stopped` prevents a
    // late renewal from resurrecting a torn-down server.
    private var engine: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>? = null
    private var stopped = false

    fun localPort() = port

    @Synchronized
    fun start(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
        if (stopped) return
        material.set(Material(tlsKey, chain)); engine = buildEngine().also { it.start(wait = false) }
    }

    // swapIdentity restarts the embedded server on the SAME fixed port with the new key/chain. Transparent
    // because /api/v1/data dial-backs are per-connection (no persistent listener connection to preserve).
    @Synchronized
    fun swapIdentity(tlsKey: PrivateKey, chain: Array<X509Certificate>) {
        if (stopped) return
        material.set(Material(tlsKey, chain)); engine?.stop(100, 500)
        engine = buildEngine().also { it.start(wait = false) }
    }

    @Synchronized
    fun stop() { stopped = true; engine?.stop(100, 500); engine = null }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

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
                    get("/info") {
                        val leaf = material.get().chain[0]
                        val sha = MessageDigest.getInstance("SHA-256").digest(leaf.encoded)
                        call.respondText(
                            JSONObject()
                                .put("nonce", appNonce)
                                .put("tls_cert_sha256", hex(sha))
                                .put("not_before", leaf.notBefore.time)
                                .put("not_after", leaf.notAfter.time)
                                .put("name", name)
                                .put("san", leaf.subjectAlternativeNames?.joinToString(",") { it[1].toString() } ?: "")
                                .put("issuer", leaf.issuerX500Principal.name)
                                .toString(),
                            ContentType.Application.Json,
                        )
                    }
                    get("/wait") {
                        val seconds = call.request.queryParameters["seconds"]?.toIntOrNull() ?: 1
                        val rate = 1 shl 20 // ~1 MiB/s
                        val chunk = ByteArray(rate)
                        val alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArray()
                        for (i in chunk.indices) chunk[i] = alpha[i % alpha.size]
                        val md = MessageDigest.getInstance("SHA-256")
                        call.respondBytesWriter {
                            writeStringUtf8("${rate.toLong() * seconds}\n")
                            repeat(seconds) {
                                md.update(chunk); writeFully(chunk); flush(); delay(1000) // pace ~1 MiB/s
                            }
                            writeStringUtf8("\n" + hex(md.digest()) + "\n")
                        }
                    }
                }
            },
        )
    }
}
