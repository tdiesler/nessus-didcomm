package org.nessus.didcomm.model

import id.walt.auditor.VerificationPolicyResult
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.VerifiablePresentation
import id.walt.credentials.w3c.schema.SchemaValidatorFactory
import id.walt.credentials.w3c.templates.VcTemplateService
import id.walt.servicematrix.ServiceRegistry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import mu.KotlinLogging
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.unionMap

typealias DanubeTechVerifiableCredential = com.danubetech.verifiablecredentials.VerifiableCredential
typealias DanubeTechVerifiablePresentation = com.danubetech.verifiablecredentials.VerifiablePresentation
typealias DanubeTechValidation = com.danubetech.verifiablecredentials.validation.Validation

/**
 * W3C Verifiable Credentials Data Model v1.1
 *
 * https://www.w3.org/TR/2022/REC-vc-data-model-20220303
 */

typealias W3CVerifiableCredential = VerifiableCredential
typealias W3CVerifiablePresentation = VerifiablePresentation

val VerifiableCredential.isVerifiableCredential get() = !isVerifiablePresentation
val VerifiableCredential.isVerifiablePresentation get() = type.contains("VerifiablePresentation")
val VerifiableCredential.verifiableCredential get() = (this as? W3CVerifiablePresentation)?.verifiableCredential

fun VerifiableCredential.hasType(type: String): Boolean {
    return if (isVerifiablePresentation) {
        verifiableCredential?.any { it.type.contains(type) } ?: false
    } else {
        this.type.contains(type)
    }
}

fun VerifiableCredential.shortString() = "$type $id"

fun VerifiableCredential.encodeJson(pretty: Boolean): String = toJsonData().encodeJson(pretty)
fun VerifiableCredential.toJsonData(): Map<String, Any?> = toJson().decodeJson()

/**
 * Validate credential integrity and schema
 */
fun VerifiableCredential.validate(): W3CVerifiableCredential {
    W3CVerifiableCredentialValidator.validateCredential(this, true)
    return this
}

object W3CVerifiableCredentialHelper {

    fun fromJsonData(data: Map<String, Any?>): W3CVerifiableCredential {
        val jsonObj = Json.parseToJsonElement(data.encodeJson()).jsonObject
        return W3CVerifiableCredential.fromJsonObject(jsonObj)
    }

    fun fromTemplate(pathOrName: String, stripValues: Boolean = true, data: Map<String, Any?> = mapOf()): W3CVerifiableCredential {
        val template = loadTemplate(pathOrName, stripValues)
        val effData = data.toMutableMap()
        if ("issuanceDate" !in data)
            effData["issuanceDate"] = "${dateTimeNow()}"
        val content = template.unionMap(effData)

        // Note, a vc loaded from template may not (yet) validate against the schema
        return fromJsonData(content)
    }

    @Suppress("UNCHECKED_CAST")
    fun loadTemplate(pathOrName: String, stripValues: Boolean = true): Map<String, Any?> {
        val templateService: VcTemplateService = ServiceRegistry.getService()
        val vcTemplate = templateService.getTemplate(pathOrName).template
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
            stripMapValues(vcTemplate.toJsonData())
        } else {
            vcTemplate.toJsonData()
        }
    }
}

object W3CVerifiableCredentialValidator {
    private val log = KotlinLogging.logger {}

    fun validateCredential(vc: W3CVerifiableCredential, strict: Boolean = true): VerificationPolicyResult {

        if ("VerifiablePresentation" in vc.type) {
            log.debug { "Not validating VerifiablePresentation" }
            return VerificationPolicyResult.success()
        }

        runCatching {
            val danubeVc = DanubeTechVerifiableCredential.fromJsonObject(vc.toJsonData())
            DanubeTechValidation.validateJson(danubeVc)
        }.onFailure {
            val result = VerificationPolicyResult.failure(listOf(it))
            result.errors.forEach { log.error { it } }
            if (strict) throw it
            return result
        }

        val result = vc.credentialSchema?.id?.let {
            runCatching {
                val validator = SchemaValidatorFactory.get(it)
                validator.validate(vc.toJson())
            }.onFailure {
                log.error { "Cannot validate credential: ${vc.encodeJson(true)}" }
            }.getOrThrow()
        } ?: VerificationPolicyResult.success()

        result.errors.forEach { log.error { it } }
        if (result.isFailure && strict)
            throw IllegalStateException("Schema validation failed with ${result.errors.size} errors")

        return result
    }
}


