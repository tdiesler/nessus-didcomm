package org.nessus.didcomm.w3c

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import id.walt.credentials.w3c.W3CCredentialSchema
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.gson
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME

/**
 * A schema can be viewed from four perspectives: the author, issuer, verifier and holder.

 * Author:
 *  An author creates a schema as to provide a blueprint for a Verifiable Credential, specifying the shape and format
 *  of the data in such a credential.
 *
 * Issuer:
 *  Issuers utilize schemas to provide structure and meaning to the data they issue as Verifiable Credentials.
 *  By using schemas, issuers contribute to a credentialing ecosystem that promotes the usage and adoption of data standards.
 *
 * Verifier:
 *  Verifiers processes a Verifiable Credentials and need to do so with knowledge of the terms and data the
 *  compromise the credentials. Credential Schemas aid a verifier in both requesting and processing credentials that have
 *  been produced in a well-known format.
 *
 * Holder:
 *  Holders, or those who are the subject of credential issuance, can make sense of the data they control by evaluating
 *  it against a data schema. When data is requested from a holder which references a Credential Schema the holder has
 *  the capability to present the data specifically requested by the verifier.
 *
 *  https://w3c-ccg.github.io/vc-json-schemas
 */
class W3CCredentialSchemaBuilder(
    /**
     * A locally unique identifier to address the schema
     */
    val id: String,
    /**
     * The value of the name property is RECOMMENDED to be a human-readable name which describes the Credential Schema
     */
    val name: String,
    /**
     * The value of the version property MUST point to a semantic version of a given credential schema
     */
    val version: String,
    /**
     * The value of the author property is RECOMMENDED to be a DID of the author of the Credential Schema
     */
    val author: String,
    /**
     * A Credential Schema MUST have a schema property. The schema property MUST be a valid JSON Schema document.
     */
    val schema: String
) {
    /**
     * The value of the type property MUST point to a URI specifying the draft of the vc schema specification to use
     * The current draft URI is https://w3c-ccg.github.io/vc-json-schemas
     */
    internal var type: String = "https://w3c-ccg.github.io/vc-json-schemas"
        private set

    /**
     * The value of the authored property MUST be a valid [RFC3339] timestamp whose value reflects the date-time value for when the Credential Schema was created
     */
    private var authored: OffsetDateTime = dateTimeNow()

    fun authored(authored: OffsetDateTime) = also { this.authored = authored }
    fun type(type: String) = also { this.type = type }

    fun build(): W3CCredentialSchema {
        return W3CCredentialSchema.fromJson(
            """
        {
            "type": "$type",
            "id": "$id",
            "name": "$name",
            "version": "$version",
            "author": "$author",
            "authored": "${authored.format(ISO_OFFSET_DATE_TIME)}",
            "schema": $schema
        }"""
        )
    }

    class SchemaBuilder(
        val id: String,
    ) {
        private var description: String? = null
        private var type: String = "object"
        private var schema: String = "https://json-schema.org/draft/2020-12/schema"
        private val properties = mutableListOf<Property>()

        fun description(description: String) = also { this.description = description }
        fun schema(schema: String) = also { this.schema = schema }
        fun type(type: String) = also { this.type = type }

        fun property(name: String, type: String, required: Boolean = true, format: String? = null) = also {
            this.properties.add(Property(name, type, required, format))
        }

        fun build(): String {
            val propertiesObj = JsonObject()
            val required = JsonArray()
            properties.forEach {
                val propObj = JsonObject()
                propObj.addProperty("type", it.type)
                it.format?.also { v -> propObj.addProperty("format", v) }
                if (it.required) required.add(it.name)
                propertiesObj.add(it.name, propObj)
            }
            val jsonObj = JsonObject()
            jsonObj.addProperty("\$id", id)
            jsonObj.addProperty("\$schema", schema)
            jsonObj.addProperty("type", type)
            description?.also { jsonObj.addProperty("description", description) }
            jsonObj.add("properties", propertiesObj)
            jsonObj.add("required", required)
            jsonObj.addProperty("additionalProperties", false)
            return gson.toJson(jsonObj)
        }

        data class Property(
            val name: String,
            val type: String,
            val required: Boolean = true,
            val format: String? = null
        )
    }
}