package org.nessus.didcomm.service

import mu.KotlinLogging


object PropertiesService: ObjectService<PropertiesService>() {
    private val log = KotlinLogging.logger { }

    override fun getService() = apply { }

    const val PROTOCOL_TRUST_PING_ROTATE_DID = "protocol.trust-ping.rotate-did"

    private val variables = mutableMapOf<String, String>()

    init {
        variables[PROTOCOL_TRUST_PING_ROTATE_DID] = "true"
    }

    fun asString(key: String): String? {
        return findKey(key)?.let { variables[it] }
    }

    fun asBoolean(key: String): Boolean {
        return asString(key).toBoolean()
    }

    fun getVars(): Map<String, String> {
        return variables.toMap()
    }

    fun delVar(key: String): String? {
        return findKey(key)?.also {
            log.debug { "Delete variable: $it" }
            variables.remove(it)
        }
    }

    fun putVar(key: String, value: String?) {
        log.debug { "Put variable: $key=$value" }
        value?.also { variables[key] = it } ?: run { delVar(key) }
    }

    private fun findKey(key: String): String?  {
        return variables.keys.firstOrNull { it.lowercase() == key.lowercase() }
    }

}