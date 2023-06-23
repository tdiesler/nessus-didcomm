package org.nessus.didcomm.json

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.float
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.intOrNull

object AnyValueSerializer : KSerializer<Any> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("AnyValueSerializer")

    override fun serialize(encoder: Encoder, value: Any) {
        val jsonOutput = encoder as? JsonEncoder ?: error("This serializer can only be used with JSON format.")
        val jsonElement = when (value) {
            is String -> JsonPrimitive(value)
            is Number -> JsonPrimitive(value)
            is Boolean -> JsonPrimitive(value)
            else -> throw SerializationException("Unsupported value type: ${value::class}")
        }
        jsonOutput.encodeJsonElement(jsonElement)
    }

    override fun deserialize(decoder: Decoder): Any {
        val jsonInput = decoder as? JsonDecoder ?: error("This serializer can only be used with JSON format.")
        val jsonElement = jsonInput.decodeJsonElement()
        check(jsonElement is JsonPrimitive)
        return when {
            jsonElement.isString -> jsonElement.content
            jsonElement.intOrNull != null -> jsonElement.int
            jsonElement.floatOrNull != null -> jsonElement.float
            jsonElement.booleanOrNull != null -> jsonElement.boolean
            else -> throw SerializationException("Unsupported JSON element: $jsonElement")
        }
    }
}