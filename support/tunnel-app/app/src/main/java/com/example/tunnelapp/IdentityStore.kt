package com.example.tunnelapp

import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

class Env(val enrollHost: String, val controlHost: String, val tunnelDomain: String) {
    val key: String = "e" + MessageDigest.getInstance("SHA-256")
        .digest("$enrollHost\n$controlHost\n$tunnelDomain".toByteArray())
        .take(6).joinToString("") { "%02x".format(it) }
}

class IdentityStore(root: File, env: Env) {
    class Saved(
        val name: String,
        val enrollHost: String,
        val controlHost: String,
        val tunnelDomain: String,
        val state: Identity.State,
    )

    private val file = File(root, "${env.key}.json")

    @Synchronized
    fun save(id: Identity) {
        val s = id.state()
        val json = JSONObject()
            .put("name", id.name)
            .put("enroll_host", id.enrollHost)
            .put("control_host", id.controlHost)
            .put("tunnel_domain", id.tunnelDomain)
            .put("identity_alias", s.identityAlias)
            .put("tls_alias", s.tlsAlias)
            .put("prev_identity_alias", s.prevIdentityAlias)
            .put("prev_tls_alias", s.prevTlsAlias)
            .put("identity_chain", Enroll.chainPem(s.identityChain))
            .put("public_chain", Enroll.chainPem(s.publicChain))
            .put("ca", s.caId)
            .put("generation", s.generation)
        file.parentFile?.mkdirs()
        val tmp = File(file.path + ".tmp")
        tmp.writeText(json.toString())
        check(tmp.renameTo(file)) { "could not move ${tmp.path} into place" }
    }

    @Synchronized
    fun load(): Saved? = if (file.exists()) parse(file) else null

    @Synchronized
    fun holds(id: Identity): Boolean = file.exists() && parse(file).name == id.name

    @Synchronized
    fun forget(): Boolean {
        if (!file.exists()) return false
        val s = parse(file).state
        listOf(s.identityAlias, s.tlsAlias, s.prevIdentityAlias, s.prevTlsAlias).filter { it.isNotEmpty() }.forEach { Keys.deleteKey(it) }
        check(file.delete()) { "could not delete ${file.path}" }
        return true
    }

    private fun parse(f: File): Saved {
        val j = JSONObject(f.readText())
        return Saved(
            j.getString("name"), j.getString("enroll_host"), j.getString("control_host"), j.getString("tunnel_domain"),
            Identity.State(
                j.getString("identity_alias"), j.getString("tls_alias"),
                Enroll.parseChain(j.getString("identity_chain")),
                j.getString("public_chain").let { if (it.isEmpty()) emptyArray() else Enroll.parseChain(it) },
                j.getString("ca"), j.getInt("generation"),
                j.getString("prev_identity_alias"), j.getString("prev_tls_alias"),
            ),
        )
    }
}
