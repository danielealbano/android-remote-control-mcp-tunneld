package com.example.tunnelapp

import okhttp3.Dns
import okhttp3.OkHttpClient
import java.io.File
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager

object Tls {
    // pebbleTrust: the pushed Pebble issuing-CA PEM is the sole trust anchor for tunneld's server certs.
    fun pebbleTrust(pebbleCaPemPath: String): X509TrustManager {
        val certs = CertificateFactory.getInstance("X.509")
            .generateCertificates(File(pebbleCaPemPath).inputStream())
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
        certs.forEachIndexed { i, c -> setCertificateEntryOn(ks, "pebble$i", c as X509Certificate) }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    private fun setCertificateEntryOn(ks: KeyStore, alias: String, c: X509Certificate) = ks.setCertificateEntry(alias, c)

    val loopbackDns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> = listOf(InetAddress.getByName("127.0.0.1"))
    }

    // serverClient: server-TLS only (Phase-1 enroll — the phone has no identity yet).
    fun serverClient(trust: X509TrustManager): OkHttpClient = client(sslContext(null, trust), trust)

    // mtlsClient presents the CURRENT live identity cert + signs with the live AndroidKeyStore identity
    // key, resolved dynamically per handshake — so a renewal that rotates the identity is picked up on the
    // next handshake and reconnect (mirrors client/control.go's GetClientCertificate callback re-reading
    // the identity each handshake).
    fun mtlsClient(id: Identity, trust: X509TrustManager): OkHttpClient =
        client(sslContext(DynamicIdentityKeyManager(id), trust), trust)

    fun sslContext(km: X509ExtendedKeyManager?, trust: X509TrustManager): SSLContext =
        SSLContext.getInstance("TLS").apply { init(km?.let { arrayOf(it) }, arrayOf(trust), SecureRandom()) }

    private fun client(ctx: SSLContext, trust: X509TrustManager): OkHttpClient =
        OkHttpClient.Builder().dns(loopbackDns).sslSocketFactory(ctx.socketFactory, trust).build()

    // DynamicIdentityKeyManager resolves the CURRENT identity per handshake and returns a CONSISTENT cert+key
    // pair even across a concurrent renewal: chooseClientAlias captures ONE atomic Cred snapshot in a
    // thread-local that getCertificateChain/getPrivateKey then read (the Go client bundles both into one
    // *tls.Certificate under c.mu — client/control.go). Client auth only (the server uses ServerTls); the key
    // never leaves the TEE.
    class DynamicIdentityKeyManager(private val id: Identity) : X509ExtendedKeyManager() {
        private val selected = ThreadLocal<Cred>()
        private fun pick(): String = id.identityCred().also { selected.set(it) }.alias
        private fun cred(): Cred = selected.get() ?: id.identityCred().also { selected.set(it) }
        override fun getClientAliases(k: String?, i: Array<Principal>?) = arrayOf(pick())
        override fun chooseClientAlias(k: Array<out String>?, i: Array<Principal>?, s: Socket?) = pick()
        override fun chooseEngineClientAlias(k: Array<out String>?, i: Array<Principal>?, e: SSLEngine?) = pick()
        override fun getServerAliases(k: String?, i: Array<Principal>?): Array<String>? = null
        override fun chooseServerAlias(k: String?, i: Array<Principal>?, s: Socket?): String? = null
        override fun chooseEngineServerAlias(k: String?, i: Array<Principal>?, e: SSLEngine?): String? = null
        override fun getCertificateChain(a: String?) = cred().chain
        override fun getPrivateKey(a: String?) = cred().key
    }
}
