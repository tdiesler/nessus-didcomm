package org.nessus.didcomm.util

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import io.ipfs.multibase.Base58
import org.web3j.utils.Numeric
import java.util.*

/***********************************************************************************************************************
 * JSON
 */
val gson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .create()

val prettyGson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .setPrettyPrinting()
    .create()

fun Map<String, Any?>.encodeJson(pretty: Boolean = false): String {
    return if (pretty) {
        fun putAll(src: Map<String, Any?>, dest: MutableMap<String, Any?>): Map<String, Any?> {
            for (en in src) {
                // The entry value is a Map
                if (en.value is Map<*, *>) {
                    dest[en.key] = putAll(en.value as Map<String, Any?>, mutableMapOf())
                }
                // The entry value is a List
                else if (en.value is List<*>) {
                    dest[en.key] = (en.value as List<Any>).map {
                        // The list value is a Map
                        if (it is Map<*, *>) {
                            putAll(it as Map<String, Any?>, mutableMapOf())
                        } else {
                            it
                        }
                    }
                }
                // The entry value is none of the above
                else {
                    dest[en.key] = en.value
                }
            }
            return dest.toSortedMap()
        }
        val srcMap = gson.fromJson(gson.toJson(this), Map::class.java)
        val auxMap = putAll(srcMap as Map<String, Any?>, mutableMapOf())
        prettyGson.toJson(auxMap)
    } else {
        gson.toJson(this)
    }
}

fun String.decodeJson(): Map<String, Any?> = gson.fromJson(this, Map::class.java) as Map<String, Any?>

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


