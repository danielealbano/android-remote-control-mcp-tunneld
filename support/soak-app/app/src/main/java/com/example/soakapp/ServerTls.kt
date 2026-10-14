package com.example.soakapp

import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

object ServerTls {
    const val ALIAS = "tls"
    val PASSWORD: CharArray = CharArray(0)

    fun keyStore(tlsKey: PrivateKey, chain: Array<X509Certificate>): KeyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry(ALIAS, tlsKey, PASSWORD, chain)
        }
}
