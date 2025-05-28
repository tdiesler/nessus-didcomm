package io.nessus.identity.portal

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

fun removeKeyRecursive(rawJson: String, keyToRemove: String): String {
    val jel = removeKeyRecursive(Json.Default.parseToJsonElement(rawJson), keyToRemove)
    return Json.Default.encodeToString(JsonElement.Companion.serializer(), jel)
}

fun removeKeyRecursive(element: JsonElement, keyToRemove: String): JsonElement {
    return when (element) {
        is JsonObject -> JsonObject(
            element.filterKeys { it != keyToRemove }
                .mapValues { (_, v) -> removeKeyRecursive(v, keyToRemove) }
        )
        is JsonArray -> JsonArray(element.map { removeKeyRecursive(it, keyToRemove) })
        else -> element
    }
}
