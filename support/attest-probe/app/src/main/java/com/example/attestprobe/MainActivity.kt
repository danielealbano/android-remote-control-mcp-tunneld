package com.example.attestprobe

import android.app.Activity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

// A real, launched app (NOT instrumentation) that mints a hardware-attested P-256 key bound to the
// server nonce and writes the attestation chain for the e2e gate to read. setShowWhenLocked /
// setTurnScreenOn (API 27) let onCreate run headless over the keyguard; the key is not auth-bound.
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        val dir = filesDir
        try {
            val nonceHex = intent.getStringExtra("nonce")
                ?: error("missing '-e nonce <hex>' extra")
            val nonce = hexToBytes(nonceHex)
            val alias = "attest-probe"
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(nonce)
                .build()
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(spec)
            kpg.generateKeyPair()
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val chain = ks.getCertificateChain(alias)
                ?: error("no attestation chain (hardware attestation unsupported?)")
            val pem = buildString {
                for (c in chain) {
                    append("-----BEGIN CERTIFICATE-----\n")
                    append(Base64.encodeToString(c.encoded, Base64.NO_WRAP).chunked(64)
                        .joinToString("\n"))
                    append("\n-----END CERTIFICATE-----\n")
                }
            }
            File(dir, "chain.pem").writeBytes(pem.toByteArray())
            File(dir, "done").writeBytes(ByteArray(0)) // marker LAST — chain.pem is complete
        } catch (t: Throwable) {
            File(dir, "error").writeText(t.toString())
        } finally {
            finish()
        }
    }

    private fun hexToBytes(s: String): ByteArray {
        require(s.length % 2 == 0 && s.isNotEmpty()) { "bad nonce hex" }
        return ByteArray(s.length / 2) {
            ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
        }
    }
}
