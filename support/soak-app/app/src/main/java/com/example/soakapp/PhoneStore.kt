package com.example.soakapp

import org.json.JSONObject
import java.io.File

class PhoneStore(private val dir: File) {
    class Saved(
        val name: String,
        val enrollHost: String,
        val controlHost: String,
        val tunnelDomain: String,
        val state: Identity.State,
    )

    private fun file(i: Int) = File(dir, "$i.json")

    @Synchronized
    fun save(i: Int, id: Identity) {
        val s = id.state()
        val json = JSONObject()
            .put("name", id.name)
            .put("enroll_host", id.enrollHost)
            .put("control_host", id.controlHost)
            .put("tunnel_domain", id.tunnelDomain)
            .put("identity_alias", s.identityAlias)
            .put("tls_alias", s.tlsAlias)
            .put("identity_chain", Enroll.chainPem(s.identityChain))
            .put("public_chain", Enroll.chainPem(s.publicChain))
            .put("ca", s.caId)
            .put("generation", s.generation)
        dir.mkdirs()
        val tmp = File(dir, "$i.json.tmp")
        tmp.writeText(json.toString())
        check(tmp.renameTo(file(i))) { "phone $i: could not move ${tmp.path} into place" }
    }

    @Synchronized
    fun load(i: Int): Saved? {
        val f = file(i)
        if (!f.exists()) return null
        val j = JSONObject(f.readText())
        return Saved(
            j.getString("name"), j.getString("enroll_host"), j.getString("control_host"), j.getString("tunnel_domain"),
            Identity.State(
                j.getString("identity_alias"), j.getString("tls_alias"),
                Enroll.parseChain(j.getString("identity_chain")), Enroll.parseChain(j.getString("public_chain")),
                j.getString("ca"), j.getInt("generation"),
            ),
        )
    }

    @Synchronized
    fun delete(i: Int) {
        val f = file(i)
        check(!f.exists() || f.delete()) { "phone $i: could not delete ${f.path}" }
    }
}
