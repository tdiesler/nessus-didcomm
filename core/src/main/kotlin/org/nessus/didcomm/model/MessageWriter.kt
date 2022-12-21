package org.nessus.didcomm.model

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import org.didcommx.didcomm.message.Message

/**
 * Serializes a DIDComm Message to JSON
 */
class MessageWriter {

    companion object {
        private val gson: Gson = GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .create()
        private val prettyGson: Gson = GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .setPrettyPrinting()
            .create()

        fun toJson(msg: Message, pretty: Boolean = false) : String {
            return toJson(msg as Any, pretty)
        }

        fun toJson(obj: Any, pretty: Boolean = false) : String {
            val gson = if (pretty) prettyGson else gson
            return gson.toJson(obj)
        }
    }
}
