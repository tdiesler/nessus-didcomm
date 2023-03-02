package org.nessus.didcomm.w3c

import com.fasterxml.jackson.databind.ObjectMapper
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import com.networknt.schema.SpecVersionDetector
import com.networknt.schema.ValidationMessage
import mu.KotlinLogging
import org.nessus.didcomm.util.decodeJson

typealias DanubeTechVerifiableCredential = com.danubetech.verifiablecredentials.VerifiableCredential
typealias DanubeTechValidation = com.danubetech.verifiablecredentials.validation.Validation
typealias WaltIdVerifiableCredential = id.walt.credentials.w3c.VerifiableCredential

open class W3CVerifiableCredential internal constructor(jsonObject: Map<String, Any>) : DanubeTechVerifiableCredential(jsonObject) {

    companion object {
        fun fromJson(input: String) = run {
            W3CVerifiableCredential(input.decodeJson())
        }
        fun fromPath(path: String) = run {
            val url = W3CVerifiableCredential::class.java.getResource(path)
            checkNotNull(url) { "No resource: $path" }
            W3CVerifiableCredential(url.readText().decodeJson())
        }

        private const val JWT_PATTERN = "(^[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\$)"
        fun isJWT(data: String) = Regex(JWT_PATTERN).matches(data)
    }

    /**
     * The value of the credentialSchema property MUST be one or more data schemas that provide verifiers
     * with enough information to determine if the provided data conforms to the provided schema.
     * https://www.w3.org/TR/vc-data-model/#data-schemas
     */
    val credentialSchema: CredentialSchema?
        get() = run {
            val credentialSchema = jsonObject["credentialSchema"] as? Map<*, *>
            credentialSchema?.run {
                CredentialSchema(get("id") as String, get("type") as String)
            }
        }

    fun merge(mergeData: Map<String, Any>): W3CVerifiableCredential {
        val mergedData = jsonObject.plus(mergeData)
        return W3CVerifiableCredential(mergedData)
    }

    fun encodeJson(pretty: Boolean = false): String {
        return toJson(pretty)
    }

    data class CredentialSchema(val id: String, val type: String)
}

object W3CVerifiableValidator {
    private val log = KotlinLogging.logger {}

    fun validateSubject(vc: W3CVerifiableCredential) {

        DanubeTechValidation.validateJson(vc)

        // Differences between Contexts, Types, and CredentialSchemas
        // https://www.w3.org/TR/vc-data-model/#differences-between-contexts-types-and-credentialschemas

        val schemaId = vc.credentialSchema?.id
        val subjectJson = vc.credentialSubject.toJson()

        if (schemaId != null) {
            val validationErrors =when {
                schemaId.startsWith("urn:example.org") -> {
                    validateAgainstExampleResource(vc.credentialSchema!!, subjectJson)
                }
                else -> run {
                    log.warn { "Unsupported schema id: $schemaId" }
                    setOf()
                }
            }
            if (validationErrors.isNotEmpty()) {
                validationErrors.forEach { log.error { it } }
                throw IllegalStateException("Validation errors")
            }
        }
    }

    private fun validateAgainstExampleResource(cs: W3CVerifiableCredential.CredentialSchema, input: String): Set<ValidationMessage> {
        require(cs.id.startsWith("urn:example.org")) { "Unexpected schema id: $cs"}

        val resourcePath = cs.id.substring(16)
        val schemaContent = readResource("/example/$resourcePath")
        return schemaContent?.let { schema -> validateSchema(schema, input) }
            ?: throw IllegalStateException(" Cannot load schema from: $resourcePath")
    }

    private fun validateSchema(schema: String, json: String): Set<ValidationMessage> {

        val versionFlag = detectSchemaVersion(schema)
        val factory = JsonSchemaFactory.getInstance(versionFlag)
        val jsonSchema = factory.getSchema(ObjectMapper().readTree(schema))

        val jsonNode = ObjectMapper().readTree(json)
        return jsonSchema.validate(jsonNode)
    }

    private fun detectSchemaVersion(jsonSchema: String): SpecVersion.VersionFlag {
        val schemaNode = ObjectMapper().readTree(jsonSchema)
        return SpecVersionDetector.detect(schemaNode)
    }

    private fun readResource(path: String): String? {
        val url = javaClass.getResource(path)
        url ?: log.error { "Cannot find resource: $path" }
        return url?.readText()
    }
}

