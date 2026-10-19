package com.example.tunnelapp

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

// Csr builds PKCS#10 CSRs signed by an AndroidKeyStore EC key via a ContentSigner wrapping a
// Signature("SHA256withECDSA") over the keystore PrivateKey — the private bytes never leave the TEE.
object Csr {
    // identity: CN "phone" (the server ignores the CSR subject and assigns the name).
    fun identityCsr(key: PrivateKey, pub: PublicKey): String = build(key, pub, "phone", null)

    // tls: CN + one DNS SAN == <name>.<tunnelDomain> (PROTOCOL §2).
    fun tlsCsr(key: PrivateKey, pub: PublicKey, fqdn: String): String = build(key, pub, fqdn, fqdn)

    private fun build(key: PrivateKey, pub: PublicKey, cn: String, sanDns: String?): String {
        val algId: AlgorithmIdentifier = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHECDSA")
        val ksSig = Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
        val buf = ByteArrayOutputStream()
        val signer = object : ContentSigner {
            override fun getAlgorithmIdentifier(): AlgorithmIdentifier = algId
            override fun getOutputStream(): OutputStream = buf
            override fun getSignature(): ByteArray { ksSig.update(buf.toByteArray()); return ksSig.sign() }
        }
        val builder = JcaPKCS10CertificationRequestBuilder(X500Name("CN=$cn"), pub)
        if (sanDns != null) {
            val ext = ExtensionsGenerator()
            ext.addExtension(
                Extension.subjectAlternativeName, false,
                GeneralNames(GeneralName(GeneralName.dNSName, sanDns)),
            )
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate())
        }
        return Keys.pem("CERTIFICATE REQUEST", builder.build(signer).encoded)
    }
}
