package com.example.tunnelapp

import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

// ServerTls builds the in-memory KeyStore Ktor's sslConnector consumes for the local HTTPS server: it
// holds the OPAQUE AndroidKeyStore TLS key + the issued Pebble cert chain.
object ServerTls {
    const val ALIAS = "tls"
    val PASSWORD: CharArray = CharArray(0)

    fun keyStore(tlsKey: PrivateKey, chain: Array<X509Certificate>): KeyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry(ALIAS, tlsKey, PASSWORD, chain)
        }
}
