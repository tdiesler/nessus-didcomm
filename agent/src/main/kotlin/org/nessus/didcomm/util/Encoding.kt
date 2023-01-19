package org.nessus.didcomm.util

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import io.ipfs.multibase.Base58
import org.web3j.utils.Numeric
import java.util.*

/***********************************************************************************************************************
 * JSON
 */
val gson: Gson = GsonBuilder().create()

val prettyGson: Gson = GsonBuilder()
    .setPrettyPrinting()
    .create()

fun Map<String, Any?>.encodeJson(sorted: Boolean = false, pretty: Boolean = false): String {
    val input = if (sorted) this.toDeeplySortedMap() else this
    return if (pretty) {
        prettyGson.toJson(input)
    } else {
        gson.toJson(input)
    }
}

fun Map<String, Any?>.encodeJsonPretty(sorted: Boolean = false): String {
    val input = if (sorted) this.toDeeplySortedMap() else this
    return prettyGson.toJson(input)
}

@Suppress("UNCHECKED_CAST")
fun String.decodeJson(): Map<String, Any?> {
    // Naive decoding of int values may produce double
    return gson.fromJson(this, Map::class.java).mapValues{ (_, v) ->
        if (v is Double && v % 1 == 0.0) v.toInt() else v
    } as Map<String, Any?>
}

fun String.trimJson(): String {
    return gson.toJson(gson.fromJson(this, JsonObject::class.java))
}

fun String.sortedJson(): String {
    return this.decodeJson().encodeJson(true)
}

/***********************************************************************************************************************
 * Base58
 */

fun ByteArray.encodeBase58(): String = Base58.encode(this)

fun String.decodeBase58(): ByteArray = Base58.decode(this)

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

fun ByteArray.encodeHex(): String = Numeric.toHexString(this).substring(2)

fun String.decodeHex(): ByteArray = Numeric.hexStringToByteArray(this)


