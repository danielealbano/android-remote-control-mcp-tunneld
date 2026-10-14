package com.example.soakapp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

object Keys {
    private const val KS = "AndroidKeyStore"

    private fun ks(): KeyStore = KeyStore.getInstance(KS).apply { load(null) }

    fun generateEcKey(alias: String, challenge: ByteArray? = null) {
        val ks = ks()
        ks.deleteEntry(alias)
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(
                KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512,
            )
        if (challenge != null) b.setAttestationChallenge(challenge)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KS)
            .apply { initialize(b.build()); generateKeyPair() }
    }

    fun privateKey(alias: String): PrivateKey = ks().getKey(alias, null) as PrivateKey
    fun publicKey(alias: String): PublicKey = (ks().getCertificate(alias) as X509Certificate).publicKey
    fun deleteKey(alias: String) = ks().deleteEntry(alias)

    fun deleteAll(prefix: String) {
        val ks = ks()
        ks.aliases().toList().filter { it.startsWith(prefix) }.forEach { ks.deleteEntry(it) }
    }

    fun attestationChainPem(alias: String): String {
        val chain = ks().getCertificateChain(alias) ?: error("no attestation chain for $alias")
        return buildString { for (c in chain) append(pem("CERTIFICATE", c.encoded)) }
    }

    fun pem(type: String, der: ByteArray): String {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP).chunked(64).joinToString("\n")
        return "-----BEGIN $type-----\n$b64\n-----END $type-----\n"
    }

    fun hexToBytes(s: String): ByteArray {
        require(s.length % 2 == 0 && s.isNotEmpty()) { "bad hex" }
        return ByteArray(s.length / 2) {
            val hi = Character.digit(s[it * 2], 16)
            val lo = Character.digit(s[it * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "bad hex" }
            ((hi shl 4) + lo).toByte()
        }
    }
}
