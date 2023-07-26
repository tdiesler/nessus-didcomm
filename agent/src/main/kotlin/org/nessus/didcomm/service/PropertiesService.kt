package org.nessus.didcomm.service


object PropertiesService: ObjectService<PropertiesService>() {

    override fun getService() = apply { }

    const val PROTOCOL_TRUST_PING_ROTATE_DID = "protocol.trust-ping.rotate-did"
    const val PROTOCOL_OUT_OF_BAND_ROUTING_KEY_AS_ENDPOINT_URL = "protocol.out-of-band.routing-key-as-endpoint-url"

    private val variables = mutableMapOf<String, Any>()

    init {
        variables[PROTOCOL_TRUST_PING_ROTATE_DID] = true
        variables[PROTOCOL_OUT_OF_BAND_ROUTING_KEY_AS_ENDPOINT_URL] = false
    }

    fun getVar(key: String): String? {
        return findKey(key)?.let { k -> variables[k]?.let { v -> "$v" } }
    }

    fun asBoolean(key: String): Boolean {
        return getVar(key).toBoolean()
    }

    fun getVars(): Map<String, Any> {
        return variables.toMap()
    }

    fun delVar(key: String): String? {
        return findKey(key)?.also {
            log.debug { "Delete variable: $it" }
            variables.remove(it)
        }
    }

    fun putVar(key: String, value: Any?) {
        log.debug { "Put variable: $key=$value" }
        value?.also { variables[key] = it } ?: run { delVar(key) }
    }

    private fun findKey(key: String): String?  {
        return variables.keys.firstOrNull { it.lowercase() == key.lowercase() }
    }

}