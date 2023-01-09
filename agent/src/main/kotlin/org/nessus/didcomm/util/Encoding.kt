package org.nessus.didcomm.util

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import io.ipfs.multibase.Base58
import org.web3j.utils.Numeric
import java.util.*

val gson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .create()

val prettyGson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .setPrettyPrinting()
    .create()

fun Map<String, Any?>.encodeJson(): String = gson.toJson(this)

fun String.decodeJson(): Map<String, Any?> = gson.fromJson(this, Map::class.java) as Map<String, Any?>

// Base58 ---------------------------------------------------------------------

fun ByteArray.encodeBase58(): String = Base58.encode(this)

fun String.decodeBase58(): ByteArray = Base58.decode(this)

// Base64 ---------------------------------------------------------------------

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

// Hex ------------------------------------------------------------------------

fun ByteArray.encodeHex(): String = Numeric.toHexString(this).substring(2)

fun String.decodeHex(): ByteArray = Numeric.hexStringToByteArray(this)


