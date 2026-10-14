package com.example.soakapp

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

class Net(caPath: String?, private val port: Int?) {
    private val trust: X509TrustManager = trustManager(caPath?.let { loadRoots(it) })
    private val dns: Dns = if (port == null) Dns.SYSTEM else Dns { listOf(InetAddress.getByName("127.0.0.1")) }

    fun url(host: String, path: String): String = if (port == null) "https://$host$path" else "https://$host:$port$path"

    fun serverClient(): OkHttpClient = client(sslContext(null))

    fun mtlsClient(id: Identity): OkHttpClient = client(sslContext(DynamicIdentityKeyManager(id)))

    private fun sslContext(km: X509ExtendedKeyManager?): SSLContext =
        SSLContext.getInstance("TLS").apply { init(km?.let { arrayOf(it) }, arrayOf(trust), SecureRandom()) }

    private fun client(ctx: SSLContext): OkHttpClient =
        OkHttpClient.Builder().dns(dns).sslSocketFactory(ctx.socketFactory, trust).build()

    private fun loadRoots(path: String): KeyStore {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
        File(path).inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCertificates(input)
                .forEachIndexed { i, c -> ks.setCertificateEntry("root$i", c as X509Certificate) }
        }
        return ks
    }

    private fun trustManager(roots: KeyStore?): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(roots)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

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
