package org.nessus.didcomm.util

import com.google.gson.Gson
import com.google.gson.GsonBuilder
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

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.encodeJson(pretty: Boolean = false): String {
    return if (pretty) {
        prettyGson.toJson(this.toDeeplySortedMap())
    } else {
        gson.toJson(this)
    }
}

@Suppress("UNCHECKED_CAST")
fun String.decodeJson(): Map<String, Any?> {
    return gson.fromJson(this, Map::class.java) as Map<String, Any?>
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

fun ByteArray.encodeBase64Url(padding: Boolean=false): String = run {
    val encoder = Base64.getUrlEncoder()
    if (!padding) encoder.withoutPadding()
    String(encoder.encode(this))
}

fun String.decodeBase64Url(): ByteArray = Base64.getUrlDecoder().decode(this)

fun String.decodeBase64UrlStr(): String = String(this.decodeBase64Url())

/***********************************************************************************************************************
 * Hex
 */

fun ByteArray.encodeHex(): String = Numeric.toHexString(this).substring(2)

fun String.decodeHex(): ByteArray = Numeric.hexStringToByteArray(this)


