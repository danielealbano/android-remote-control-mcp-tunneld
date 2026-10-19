package com.example.tunnelapp

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

class IdentityStoreTest {
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

    private fun identity(publicChain: Array<X509Certificate>, tlsAlias: String, prevId: String, prevTls: String) = Identity(
        Net(null, null), "abc", env.enrollHost, env.controlHost, env.tunnelDomain,
        "tunnel-${env.key}-identity-2", tlsAlias, arrayOf(cert("identity")), publicChain, "gts", 2, prevId, prevTls,
    )

    @Test
    fun savedIdentityRoundTripsWithItsPreviousGeneration() {
        val id = identity(arrayOf(cert("abc.free.example.com"), cert("issuer")), "tunnel-${env.key}-tls-2",
            "tunnel-${env.key}-identity-1", "tunnel-${env.key}-tls-1")
        IdentityStore(tmp.root, env).save(id)
        val saved = IdentityStore(tmp.root, env).load()!!
        val want = id.state()
        assertEquals("abc", saved.name)
        assertEquals(listOf(env.enrollHost, env.controlHost, env.tunnelDomain), listOf(saved.enrollHost, saved.controlHost, saved.tunnelDomain))
        val got = saved.state
        assertEquals(want.identityAlias, got.identityAlias)
        assertEquals(want.tlsAlias, got.tlsAlias)
        assertEquals(want.prevIdentityAlias, got.prevIdentityAlias)
        assertEquals(want.prevTlsAlias, got.prevTlsAlias)
        assertEquals("gts", got.caId)
        assertEquals(2, got.generation)
        assertEquals(want.identityChain.map { it.encoded.toList() }, got.identityChain.map { it.encoded.toList() })
        assertEquals(want.publicChain.map { it.encoded.toList() }, got.publicChain.map { it.encoded.toList() })
        assertFalse(File(tmp.root, "${env.key}.json.tmp").exists())
    }

    @Test
    fun identitySavedBeforeItsFirstCertificateRoundTrips() {
        IdentityStore(tmp.root, env).save(identity(emptyArray(), "", "", ""))
        val got = IdentityStore(tmp.root, env).load()!!.state
        assertEquals(0, got.publicChain.size)
        assertEquals("", got.tlsAlias)
        assertEquals("", got.prevIdentityAlias)
    }

    @Test
    fun nothingSavedLoadsNothing() {
        assertNull(IdentityStore(tmp.root, env).load())
    }

    @Test
    fun holdsOnlyTheSavedIdentity() {
        val store = IdentityStore(tmp.root, env)
        val id = identity(emptyArray(), "", "", "")
        store.save(id)
        assertTrue(store.holds(id))
        val other = Identity(
            Net(null, null), "zzz", env.enrollHost, env.controlHost, env.tunnelDomain,
            "tunnel-${env.key}-identity-2", "", arrayOf(cert("identity")), emptyArray(), "gts", 2, "", "",
        )
        assertFalse(store.holds(other))
        File(tmp.root, "${env.key}.json").delete()
        assertFalse(store.holds(id))
    }

    @Test
    fun environmentsAreKeptApart() {
        IdentityStore(tmp.root, env).save(identity(emptyArray(), "", "", ""))
        assertNull(IdentityStore(tmp.root, Env("enroll.example.test", "connect.example.test", "other.example.com")).load())
    }
}
