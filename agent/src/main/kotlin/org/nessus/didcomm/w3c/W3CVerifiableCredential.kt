package org.nessus.didcomm.w3c

import id.walt.auditor.VerificationPolicyResult
import id.walt.credentials.w3c.schema.SchemaValidatorFactory
import mu.KotlinLogging
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.toUnionMap

typealias DanubeTechVerifiableCredential = com.danubetech.verifiablecredentials.VerifiableCredential
typealias DanubeTechValidation = com.danubetech.verifiablecredentials.validation.Validation
typealias WaltIdVerifiableCredential = id.walt.credentials.w3c.VerifiableCredential

/**
 * W3C Verifiable Credentials Data Model v1.1
 *
 * https://www.w3.org/TR/2022/REC-vc-data-model-20220303
 */
open class W3CVerifiableCredential internal constructor(jsonObject: Map<String, Any?>) : DanubeTechVerifiableCredential(jsonObject) {

    data class CredentialSchema(val id: String, val type: String)

    companion object {

        fun fromJson(input: String): W3CVerifiableCredential {
            return W3CVerifiableCredential(input.decodeJson())
        }

        fun fromTemplate(path: String, data: Map<String, Any?> = mapOf()): W3CVerifiableCredential {
            val template = loadTemplate(path)
            val effData = data.toMutableMap()
            if ("issuanceDate" !in data)
                effData["issuanceDate"] = "${dateTimeNow()}"
            val content = template.toUnionMap(effData)
            return W3CVerifiableCredential(content)
        }

        @Suppress("UNCHECKED_CAST")
        fun loadTemplate(path: String): Map<String, Any> {
            val url = W3CVerifiableCredential::class.java.getResource(path)
            checkNotNull(url) { "No resource: $path" }
            val finalProperties = setOf("@context", "type", "credentialSchema")
            fun stripMapValues(map: Map<String, Any>): Map<String, Any> {
                return map.mapValues { (k, v) -> when {
                    k in finalProperties -> v
                    v is Map<*, *> -> stripMapValues(v as Map<String, Any>)
                    v is List<*> -> listOf<Any>()
                    else -> ""
                }}
            }
            return stripMapValues(url.readText().decodeJson())
        }

        private const val JWT_PATTERN = "(^[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\$)"
        fun isJWT(data: String) = Regex(JWT_PATTERN).matches(data)
    }

    /**
     * Validate credential integrity and schema
     */
    fun validate() = apply {
        W3CVerifiableCredentialValidator.validate(this, true)
    }

    /**
     * The value of the credentialSchema property MUST be one or more data schemas that provide verifiers
     * with enough information to determine if the provided data conforms to the provided schema.
     * https://www.w3.org/TR/vc-data-model/#data-schemas
     */
    val credentialSchema: CredentialSchema? get() = run {
        val schemaMap = jsonObject["credentialSchema"] as? Map<*, *>
        schemaMap?.run { CredentialSchema(get("id") as String, get("type") as String) }
    }

    fun hasType(type: String): Boolean {
        return types.contains(type)
    }

    // Accidental override: The following declarations have the same JVM signature
    // val contexts: List<URI> get() = super.getContexts()
    // val types: List<String> get() = super.getTypes()
    // val id: URI? get() = super.getId()
    // val issuer: URI get() = super.getIssuer()
    // val issuanceDate: Date get() = super.getIssuanceDate()
    // val expirationDate: Date get() = super.getExpirationDate()
    // val credentialSubject: CredentialSubject get() = CredentialSubject.getFromJsonLDObject(this)
    // val credentialStatus: CredentialStatus get() = CredentialStatus.getFromJsonLDObject(this)
    // val proof: LdProof get() = super.getLdProof()

    fun encodeJson(pretty: Boolean = false): String {
        return toJson(pretty)
    }
}

object W3CVerifiableCredentialValidator {
    private val log = KotlinLogging.logger {}

    fun validate(vc: W3CVerifiableCredential, strict: Boolean = true): VerificationPolicyResult {

        // Differences between Contexts, Types, and CredentialSchemas
        // https://www.w3.org/TR/vc-data-model/#differences-between-contexts-types-and-credentialschemas

        runCatching { DanubeTechValidation.validateJson(vc) }.onFailure {
            val result = VerificationPolicyResult.failure(listOf(it.message as String))
            result.errors.forEach { log.error { it } }
            if (strict) throw it
            return result
        }

        val result = vc.credentialSchema?.id?.let {
            SchemaValidatorFactory.get(it).validate(vc.toJson())
        } ?: VerificationPolicyResult.success()

        result.errors.forEach { log.error { it } }
        if (result.isFailure && strict)
            throw IllegalStateException("Schema validation failed with ${result.errors.size} errors")

        return result
    }
}


