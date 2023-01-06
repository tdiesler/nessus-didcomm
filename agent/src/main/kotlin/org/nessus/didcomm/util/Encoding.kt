package org.nessus.didcomm.util

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import io.ipfs.multibase.Base58
import java.util.*

val gson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .create()

val prettyGson: Gson = GsonBuilder()
    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
    .setPrettyPrinting()
    .create()

fun ByteArray.encodeBase58(): String = Base58.encode(this)

fun String.decodeBase58(): ByteArray = Base58.decode(this)

fun ByteArray.encodeBase64(): String = Base64.getEncoder().encodeToString(this)

fun String.decodeBase64(): ByteArray = Base64.getDecoder().decode(this)

fun String.decodeBase64Str(): String = String(Base64.getDecoder().decode(this))

fun Map<String, Any?>.encodeJson(): String = gson.toJson(this)

fun String.decodeJson(): Map<String, Any?> = gson.fromJson(this, Map::class.java) as Map<String, Any?>

