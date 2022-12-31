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
