package org.nessus.didcomm.model

import com.google.gson.Gson
import org.didcommx.didcomm.message.Message

/**
 * Parses a JSON string to a DIDComm Message
 */
object MessageReader {

    private val gson = Gson()

    fun fromJson(json: String) : Message {
        val jsonMap: MutableMap<String, Any> = mutableMapOf()
        gson.fromJson(json, Map::class.java).forEach { en ->
            val enval = en.value!!
            when(val key: String = en.key.toString()) {
                "created_time" -> jsonMap[key] = (enval as Double).toLong()
                "expires_time" -> jsonMap[key] = (enval as Double).toLong()
                "custom_headers" -> if (enval is Map<*, *> && enval.isNotEmpty()) {
                    jsonMap[key] = enval
                }
                else -> jsonMap[key] = enval
            }
        }
        return Message.parse(jsonMap)
    }

    fun <T> fromJson(json: String, type: Class<T>) : T {
        return gson.fromJson(json, type)
    }
}
