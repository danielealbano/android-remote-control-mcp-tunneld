package com.example.tunnelapp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

// Keys owns the non-exportable AndroidKeyStore EC P-256 keys. Only CSRs + attestation chains leave the
// TEE; PrivateKey handles are opaque (getEncoded()==null).
object Keys {
    private const val KS = "AndroidKeyStore"

    private fun ks(): KeyStore = KeyStore.getInstance(KS).apply { load(null) }

    // generateEcKey mints a non-exportable EC P-256 key under alias. Conscrypt signs an AndroidKeyStore
    // EC key for TLS via Signature("NONEwithECDSA") (the TLS stack pre-hashes the transcript), so the key
    // MUST authorize DIGEST_NONE or keymaster rejects the CertificateVerify mid-handshake. PURPOSE_SIGN
    // suffices (ECDHE needs no key-decryption); SHA-256/384/512 are kept for the CSR. When challenge !=
    // null the key is hardware-attested over it.
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

    // attestationChainPem PEM-encodes the AndroidKeyStore cert chain for an attested key — the leaf
    // attestation cert → device/batch/factory roots tunneld's seven-point verifier checks.
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
            ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
        }
    }
}
