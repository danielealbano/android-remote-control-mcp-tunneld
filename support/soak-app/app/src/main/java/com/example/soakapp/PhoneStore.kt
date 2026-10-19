package com.example.soakapp

import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

class Env(val enrollHost: String, val controlHost: String, val tunnelDomain: String) {
    val key: String = "e" + MessageDigest.getInstance("SHA-256")
        .digest("$enrollHost\n$controlHost\n$tunnelDomain".toByteArray())
        .take(6).joinToString("") { "%02x".format(it) }
}

class PhoneStore(root: File, env: Env) {
    class Saved(
        val name: String,
        val enrollHost: String,
        val controlHost: String,
        val tunnelDomain: String,
        val state: Identity.State,
    )

    private val dir = File(root, env.key)

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
        return parse(f)
    }

    @Synchronized
    fun holds(i: Int, id: Identity): Boolean {
        val f = file(i)
        return f.exists() && parse(f).name == id.name
    }

    @Synchronized
    fun forgetAll(): Int {
        val saved = dir.listFiles { f -> f.isFile && f.name.endsWith(".json") } ?: return 0
        for (f in saved) {
            val s = parse(f).state
            listOf(s.identityAlias, s.tlsAlias).filter { it.isNotEmpty() }.forEach { Keys.deleteKey(it) }
            check(f.delete()) { "could not delete ${f.path}" }
        }
        return saved.size
    }

    companion object {
        private val legacyName = Regex("""\d+\.json""")

        fun migrateLegacy(root: File) {
            val legacy = root.listFiles { f -> f.isFile && legacyName.matches(f.name) } ?: return
            for (f in legacy) {
                val s = parse(f)
                val dir = File(root, Env(s.enrollHost, s.controlHost, s.tunnelDomain).key)
                val target = File(dir, f.name)
                check(!target.exists()) { "legacy ${f.path} left in place: ${target.path} already exists" }
                dir.mkdirs()
                check(f.renameTo(target)) { "could not move ${f.path} to ${target.path}" }
                Log.i(TAG, "moved saved phone ${s.name} (${f.name}) into ${dir.name}")
            }
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
                ),
            )
        }
    }
}
