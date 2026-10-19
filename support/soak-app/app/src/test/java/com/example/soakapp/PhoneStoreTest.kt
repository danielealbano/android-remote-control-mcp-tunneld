package com.example.soakapp

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

class PhoneStoreTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val env = Env("enroll.example.test", "connect.example.test", "free.example.com")

    private fun cert(cn: String): X509Certificate {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val name = X500Name("CN=$cn")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(name, BigInteger.ONE, Date(now - 60_000), Date(now + 3_600_000), name, kp.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(kp.private))
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    private fun identity(name: String) = Identity(
        Net(null, null), 0, name, env.enrollHost, env.controlHost, env.tunnelDomain,
        "soak-${env.key}-0-identity-1", "", arrayOf(cert("identity")), emptyArray(), "gts", 1,
    )

    @Test
    fun holdsOnlyTheSavedIdentity() {
        val store = PhoneStore(tmp.root, env)
        val id = identity("abc")
        store.save(0, id)
        assertTrue(store.holds(0, id))
        assertFalse(store.holds(0, identity("zzz")))
        assertFalse(store.holds(1, id))
        File(File(tmp.root, env.key), "0.json").delete()
        assertFalse(store.holds(0, id))
    }
}
