/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.util

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import id.walt.credentials.w3c.VerifiableCredential
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import org.didcommx.didcomm.message.Message
import org.json.JSONObject
import java.lang.reflect.Type
import java.util.*

/***********************************************************************************************************************
 * Message
 */

class EmptyBodyMap: LinkedHashMap<String, Any>()

fun Message.encodeJson(pretty: Boolean = false): String {
    var jsonObj = toJSONObject()
    if ((jsonObj["body"] as Map<*, *>).isEmpty()) {
        jsonObj = jsonObj.toMutableMap()
        jsonObj["body"] = EmptyBodyMap()
    }
    return jsonObj.encodeJson(pretty)
}

fun String.decodeMessage(): Message {
    return Message.parse(decodeJson())
}

/***********************************************************************************************************************
 * JSON
 */
val gsonBuilder: GsonBuilder = GsonBuilder()
    .registerTypeHierarchyAdapter(Collection::class.java, CollectionAdapter())
    .registerTypeHierarchyAdapter(Map::class.java, MapAdapter())

val gson: Gson = gsonBuilder
    .create()

val gsonPretty: Gson = gsonBuilder
    .setPrettyPrinting()
    .create()

@Suppress("UNCHECKED_CAST")
fun JSONObject.encodeJson(pretty: Boolean = false, sorted: Boolean = false): String {
    return (this as Map<String, Any?>).encodeJson(pretty, sorted)
}

fun Map<String, Any?>.encodeJson(pretty: Boolean = false, sorted: Boolean = false): String {
    val input = if (sorted) toDeeplySortedMap() else this
    return if (pretty) gsonPretty.toJson(input) else gson.toJson(input)
}

fun Any.encodeJson(pretty: Boolean = false): String {
    return if (pretty) gsonPretty.toJson(this) else gson.toJson(this)
}

fun String.isJson(): Boolean {
    return this.trim().startsWith('{')
}

@Suppress("UNCHECKED_CAST")
fun String.decodeJson(): Map<String, Any> {
    // Naive decoding of int values may produce double
    return gson.fromJson(this, Map::class.java).mapValues{ (_, v) ->
        if (v is Double && v % 1 == 0.0) v.toInt() else v
    } as Map<String, Any>
}

fun String.trimJson(): String {
    return gson.toJson(gson.fromJson(this, JsonObject::class.java))
}

internal class CollectionAdapter : JsonSerializer<Collection<*>> {
    override fun serialize(src: Collection<*>, type: Type, ctx: JsonSerializationContext): JsonElement? {
        if (src.isEmpty()) return null
        val array = JsonArray()
        src.forEach {
            array.add(ctx.serialize(it))
        }
        return array
    }
}

internal class MapAdapter : JsonSerializer<Map<String, *>> {
    override fun serialize(src: Map<String, *>, type: Type, ctx: JsonSerializationContext): JsonElement? {
        if (src.isEmpty() && src !is EmptyBodyMap)
            return null
        val obj = JsonObject()
        src.forEach {(k, v) -> when {
                k == "_isObject" -> {} // In VerifiableCredential
                else -> obj.add(k, ctx.serialize(v))
            }
        }
        return obj
    }
}

/***********************************************************************************************************************
 * Base64
 */

fun ByteArray.encodeBase64(): String = Base64.getEncoder().encodeToString(this)

fun String.decodeBase64(): ByteArray = Base64.getDecoder().decode(this)

fun String.decodeBase64Str(): String = String(this.decodeBase64())

fun ByteArray.encodeBase64Url(padding: Boolean = false): String = run {
    val encoder = if (padding) Base64.getUrlEncoder()
    else Base64.getUrlEncoder().withoutPadding()
    String(encoder.encode(this))
}

fun String.decodeBase64Url(): ByteArray = Base64.getUrlDecoder().decode(this)

fun String.decodeBase64UrlStr(): String = String(this.decodeBase64Url())

/***********************************************************************************************************************
 * Hex
 */

fun ByteArray.encodeHex(): String = HexFormat.of().formatHex(this)

fun String.decodeHex(): ByteArray = HexFormat.of().parseHex(this)

/***********************************************************************************************************************
 * MediaType
 */

fun MediaType.matches(contentType: String?): Boolean {
    return if (contentType != null) {
        val other = contentType.toMediaType()
        this.type == other.type && this.subtype == other .subtype
    } else false
}

/***********************************************************************************************************************
 * VerifiableCredential
 */

fun VerifiableCredential.encodeJson(pretty: Boolean = false): String {
    val mapEncoded = gson.fromJson(encode(), Map::class.java)
    return mapEncoded.encodeJson(pretty)
}