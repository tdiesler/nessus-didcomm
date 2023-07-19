package org.nessus.didcomm.json

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.float
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.intOrNull

object AnyValueSerializer : KSerializer<Any> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("AnyValueSerializer")

    private fun toJsonElement(value: Any): JsonElement {
        return when (value) {
            is String -> JsonPrimitive(value)
            is Number -> JsonPrimitive(value)
            is Boolean -> JsonPrimitive(value)
            is List<*> -> buildJsonArray { value.forEach { v -> add(toJsonElement(checkNotNull(v)))}}
            is Map<*, *> -> buildJsonObject { value.forEach { (k,v) -> put("$k", toJsonElement(checkNotNull(v)))}}
            else -> throw SerializationException("Unsupported value type: ${value::class}")
        }
    }

    private fun fromJsonPrimitive(json: JsonPrimitive): Any {
        return when {
            json.isString -> json.content
            json.intOrNull != null -> json.int
            json.floatOrNull != null -> json.float
            json.booleanOrNull != null -> json.boolean
            else -> throw SerializationException("Unsupported JSON element: $json")
        }
    }

    private fun fromJsonArray(json: JsonArray): Any {
        return json.map { el ->
            when(el) {
                is JsonPrimitive -> fromJsonPrimitive(el)
                else -> throw SerializationException("Unsupported JSON element: $el")
            }
        }
    }

    private fun fromJsonObject(json: JsonObject): Any {
        return json.toMap().mapValues { (_, v) ->
            when(v) {
                is JsonPrimitive -> fromJsonPrimitive(v)
                is JsonArray -> fromJsonArray(v)
                else -> throw SerializationException("Unsupported JSON element: $v")
            }
        }
    }

    override fun serialize(encoder: Encoder, value: Any) {
        val jsonOutput = encoder as? JsonEncoder ?: error("This serializer can only be used with JSON format.")
        jsonOutput.encodeJsonElement(toJsonElement(value))
    }

    override fun deserialize(decoder: Decoder): Any {
        val jsonInput = decoder as? JsonDecoder ?: error("This serializer can only be used with JSON format.")
        val jsonElement = jsonInput.decodeJsonElement()
        return when (jsonElement) {
            is JsonNull -> throw SerializationException("Null values not supported: $decoder")
            is JsonPrimitive -> fromJsonPrimitive(jsonElement)
            is JsonArray -> fromJsonArray(jsonElement)
            is JsonObject -> fromJsonObject(jsonElement)
            else -> throw SerializationException("Unsupported value type: ${jsonElement::class}")
        }
    }
}