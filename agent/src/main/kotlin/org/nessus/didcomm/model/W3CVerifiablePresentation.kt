package org.nessus.didcomm.model

import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialKeywords.JSONLD_TERM_VERIFIABLECREDENTIAL
import com.danubetech.verifiablecredentials.jsonld.VerifiableCredentialKeywords.JSONLD_TERM_VERIFIABLE_PRESENTATION
import foundation.identity.jsonld.JsonLDObject

typealias DanubeTechVerifiablePresentation = com.danubetech.verifiablecredentials.VerifiablePresentation
typealias WaltIdVerifiablePresentation = id.walt.credentials.w3c.VerifiablePresentation

open class W3CVerifiablePresentation private constructor(jsonLD: JsonLDObject) : DanubeTechVerifiablePresentation(jsonLD.jsonObject) {

    init {
        check(types.contains(JSONLD_TERM_VERIFIABLE_PRESENTATION)) { "No '$JSONLD_TERM_VERIFIABLE_PRESENTATION' type: $types" }
    }

    companion object {
        fun fromJson(json: String) = fromJson(JsonLDObject.fromJson(json))
        fun fromJson(jsonLD: JsonLDObject) = W3CVerifiablePresentation(jsonLD)
        fun fromMap(data: Map<String, Any?>) = fromJson(JsonLDObject.fromMap(data))
    }

    @Suppress("UNCHECKED_CAST")
    val verifiableCredential: List<W3CVerifiableCredential> get() = let {
        return when(val value = jsonObject[JSONLD_TERM_VERIFIABLECREDENTIAL]) {
            is Map<*, *> -> listOf(W3CVerifiableCredential.fromMap(value as Map<String, Any?>))
            is List<*> -> value.map { W3CVerifiableCredential.fromMap(it as Map<String, Any?>) }
            else -> listOf()
        }
    }

    class Builder(jsonLD: JsonLDObject): JsonLDObject.Builder<Builder>(jsonLD) {
        override fun build(): W3CVerifiablePresentation {
            val jsonLD: JsonLDObject = super.build()
            return W3CVerifiablePresentation(jsonLD)
        }
    }

    fun hasType(type: String): Boolean = let {
        verifiableCredential.any { it.hasType(type) }
    }
}

// Extensions ----------------------------------------------------------------------------------------------------------

fun W3CVerifiablePresentation.toWaltIdType() = WaltIdVerifiablePresentation.fromJson(toJson())