/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
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
package org.nessus.didcomm.model.dcv2

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.nimbusds.jose.util.Base64URL
import org.didcommx.didcomm.message.Message

/**
 * Serializes a DIDComm Message to JSON
 */
object MessageWriter {

    private val gson: Gson = GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        .create()
    private val prettyGson: Gson = GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        .setPrettyPrinting()
        .create()

    fun toBase64URL(msg: Message): String {
        return Base64URL.encode(toJson(msg)).toString()
    }

    fun toJson(msg: Message, pretty: Boolean = false) : String {
        val jsonObj = gson.toJsonTree(msg).asJsonObject
        // Remove empty 'custom_headers'
        // [TODO] we may have to remove emtpty content for other headers too
        val customHeaders = jsonObj.getAsJsonObject("custom_headers")
        if (customHeaders.entrySet().isEmpty()) {
            jsonObj.remove("custom_headers")
        }
        return auxGson(pretty).toJson(jsonObj)
    }

    fun toJson(obj: Any, pretty: Boolean = false) : String {
        return auxGson(pretty).toJson(obj)
    }

    fun toMutableMap(obj: Any) : MutableMap<String, Any> {
        val result: MutableMap<String, Any> = mutableMapOf()
        val input: String = if (obj is String) obj else gson.toJson(obj)
        gson.fromJson(input, MutableMap::class.java).forEach {
                en -> result[en.key as String] = en.value!!
        }
        return result
    }

    private fun auxGson(pretty: Boolean = false): Gson {
        return if (pretty) prettyGson else gson
    }
}
