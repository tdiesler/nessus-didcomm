package org.nessus.didcomm.model

import foundation.identity.jsonld.JsonLDObject
import foundation.identity.jsonld.JsonLDUtils
import id.walt.auditor.VerificationPolicyResult
import id.walt.credentials.w3c.schema.SchemaValidatorFactory
import id.walt.credentials.w3c.templates.VcTemplateService
import id.walt.servicematrix.ServiceRegistry
import mu.KotlinLogging
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.unionMap

/**
 * W3C Verifiable Credentials Data Model v1.1
 *
 * https://www.w3.org/TR/2022/REC-vc-data-model-20220303
 */

typealias DanubeTechVerifiableCredential = com.danubetech.verifiablecredentials.VerifiableCredential
typealias DanubeTechValidation = com.danubetech.verifiablecredentials.validation.Validation
typealias WaltIdVerifiableCredential = id.walt.credentials.w3c.VerifiableCredential


open class W3CVerifiableCredential private constructor(jsonLD: JsonLDObject) : DanubeTechVerifiableCredential(jsonLD.jsonObject) {

    companion object {
        fun fromJson(json: String) = fromJson(JsonLDObject.fromJson(json))
        fun fromJson(jsonLD: JsonLDObject) = W3CVerifiableCredential(jsonLD)
        fun fromMap(data: Map<String, Any?>) = fromJson(JsonLDObject.fromMap(data))
        fun fromTemplate(pathOrName: String, subjectData: Map<String, Any?> = mapOf(), stripValues: Boolean = true) =
            Builder.fromTemplate(pathOrName, subjectData, stripValues).build()

        @Suppress("UNCHECKED_CAST")
        fun loadTemplate(pathOrName: String, stripValues: Boolean = true): Map<String, Any?> {
            val templateService: VcTemplateService = ServiceRegistry.getService()
            val vcTemplate: WaltIdVerifiableCredential? = templateService.getTemplate(pathOrName).template
            checkNotNull(vcTemplate) { "Cannot load template: $pathOrName" }
            return if (stripValues) {
                val fixedProperties = setOf("@context", "type", "credentialSchema")
                fun stripMapValues(map: Map<String, Any?>): Map<String, Any?> {
                    return map.mapValues { (k, v) -> when {
                        k in fixedProperties -> v
                        v is Map<*, *> -> stripMapValues(v as Map<String, Any?>)
                        v is List<*> -> listOf<Any>()
                        else -> ""
                    }}
                }
                stripMapValues(vcTemplate.toJson().decodeJson())
            } else {
                vcTemplate.toJson().decodeJson()
            }
        }
    }

    /**
     * https://www.w3.org/TR/vc-data-model/#data-schemas
     */
    @Suppress("UNCHECKED_CAST")
    val credentialSchema: List<CredentialSchema> get() = let {
        when(val value = jsonObject["credentialSchema"]) {
            is Map<*, *> -> listOf(CredentialSchema.fromMap(value as Map<String, Any>))
            is List<*> -> value.map { CredentialSchema.fromMap(it as Map<String, Any>) }
            is CredentialSchema -> listOf(value)
            else -> listOf()
        }
    }

    /**
     * https://www.w3.org/TR/vc-data-model/#status
     */
    @Suppress("UNCHECKED_CAST")
    val credentialStatus: CredentialStatus? get() = let {
        when(val value = jsonObject["credentialStatus"]) {
            is Map<*, *> -> CredentialStatus.fromMap(value as Map<String, Any>)
            is CredentialStatus -> value
            else -> null
        }
    }

    fun hasType(type: String): Boolean = let {
        this.types.contains(type)
    }

    /**
     * Validate credential integrity and schema
     */
    fun validate() = apply {
        W3CVerifiableCredentialValidator.validateCredential(this, true)
    }

    class Builder(jsonLD: JsonLDObject): JsonLDObject.Builder<Builder>(jsonLD) {

        companion object {
            fun fromTemplate(pathOrName: String, subjectData: Map<String, Any?> = mapOf(), stripValues: Boolean = true): Builder {
                val template = loadTemplate(pathOrName, stripValues)
                val mutableData = subjectData.toMutableMap()
                if ("issuanceDate" !in subjectData)
                    mutableData["issuanceDate"] = "${dateTimeNow()}"
                val contentMap = template.unionMap(mutableData)
                return Builder(JsonLDObject.fromMap(contentMap))
            }
        }

        fun credentialStatus(status: CredentialStatus) = apply {
            JsonLDUtils.jsonLdAdd(jsonLdObject, "credentialStatus", status)
        }

        override fun build(): W3CVerifiableCredential {
            val jsonLD: JsonLDObject = super.build()
            return W3CVerifiableCredential(jsonLD)
        }
    }
}

/**
 * Useful when enforcing a specific structure on a given collection of data.
 * https://www.w3.org/TR/vc-data-model/#data-schemas
 */
open class CredentialSchema(jsonLD: JsonLDObject): JsonLDObject(jsonLD.jsonObject) {
    val id: String = JsonLDUtils.jsonLdGetString(jsonObject, "id")
    companion object {
        fun fromJson(jsonLD: JsonLDObject) = CredentialSchema(jsonLD)
        fun fromJson(json: String) = fromJson(JsonLDObject.fromJson(json))
        fun fromMap(data: Map<String, Any?>) = fromJson(JsonLDObject.fromMap(data))
    }
}

/**
 * The current status of a verifiable credential, such as whether it is suspended or revoked.
 * https://www.w3.org/TR/vc-data-model/#status
 */
open class CredentialStatus(jsonLD: JsonLDObject): JsonLDObject(jsonLD.jsonObject) {
    val id: String = JsonLDUtils.jsonLdGetString(jsonObject, "id")
    companion object {
        fun fromJson(jsonLD: JsonLDObject) = CredentialStatus(jsonLD)
        fun fromJson(json: String) = fromJson(JsonLDObject.fromJson(json))
        fun fromMap(data: Map<String, Any?>) = fromJson(JsonLDObject.fromMap(data))
    }
}

object W3CVerifiableCredentialValidator {
    private val log = KotlinLogging.logger {}

    fun validateCredential(vc: W3CVerifiableCredential, strict: Boolean = true): VerificationPolicyResult {

        runCatching {
            DanubeTechValidation.validateJson(vc)
        }.onFailure {
            val result = VerificationPolicyResult.failure(it)
            result.errors.forEach { log.error { it } }
            if (strict) throw it
            return result
        }

        vc.credentialSchema.forEach {
            val validator = SchemaValidatorFactory.get(it.id)
            val result = validator.validate(vc.credentialSubject.toJson())
            if (result.isFailure) {
                log.error { "Failed to validate schema: ${result.errors.map { e -> e.message }}" }
                if (strict) result.errors.first().cause ?.also { th -> throw th }
                return result
            }
        }

        return VerificationPolicyResult.success()
    }
}

// Extensions ----------------------------------------------------------------------------------------------------------

fun W3CVerifiableCredential.toWaltIdType() = WaltIdVerifiableCredential.fromJson(toJson())