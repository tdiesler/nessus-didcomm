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
package org.nessus.didcomm.protocol

import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.isJson
import org.nessus.didcomm.util.selectJson
import java.util.*

/**
 * Associates an endpoint message with additional metadata
 */
class EndpointMessage(
    val body: Any,
    extraHeaders: Map<String, Any?> = mapOf()
) {

    companion object {
        /**
         * Header constants
         */
        const val MESSAGE_ID = "MessageId"
        const val MESSAGE_PROTOCOL_URI = "MessageProtocolUri"
        const val MESSAGE_PTHID = "MessageParentThid"
        const val MESSAGE_THID = "MessageThid"
        const val MESSAGE_TYPE = "MessageType"
    }

    val headers: Map<String, Any?>
    init {
        check(body !is EndpointMessage) { "Nested endpoint message"}
        val effHeaders = extraHeaders.toMutableMap()
        if (body is String && body.isJson()) {
            val id = body.selectJson("@id")
            val type = body.selectJson("@type")
            val thid = body.selectJson("~thread.thid")
            val pthid = body.selectJson("~thread.pthid")
            id?.run { effHeaders[MESSAGE_ID] = id }
            type?.run { effHeaders[MESSAGE_TYPE] = type }
            thid?.run { effHeaders[MESSAGE_THID] = thid }
            pthid?.run { effHeaders[MESSAGE_PTHID] = pthid }
        }
        if (effHeaders[MESSAGE_ID] == null) {
            val auxId = "${UUID.randomUUID()}"
            val idx = auxId.indexOf('-') + 1
            effHeaders[MESSAGE_ID] = "00000000-${auxId.substring(idx)}"
        }
        this.headers = effHeaders.toSortedMap()
    }

    val id = headers[MESSAGE_ID] as String
    val type = headers[MESSAGE_TYPE] as? String
    val thid = headers[MESSAGE_THID] as? String ?: id
    val pthid = headers[MESSAGE_PTHID] as? String
    val protocolUri = headers[MESSAGE_PROTOCOL_URI] as? String

    val bodyAsJson: String get() = run {
        return if (body is String) body else gson.toJson(body)
    }

    fun checkMessageType(expectedType: String) {
        check(type == expectedType) { "Unexpected message type: $type" }
    }

    class Builder(var body: Any) {
        private var headers: MutableMap<String, Any?> = mutableMapOf()

        constructor(body: Any, headers: Map<String, Any?>): this(body) {
            this.headers.putAll(headers)
        }

        fun body(body: Any) = apply {this.body = body }
        fun header(k: String, v: Any) = apply { this.headers[k] = v }
        fun headers(headers: Map<String, Any>) = apply {this.headers.putAll(headers) }
        fun build() = EndpointMessage(body, headers)
    }

    override fun toString(): String {
        return "EndpointMessage(headers=$headers, body=$body)"
    }
}

typealias MessageListener = (msg: EndpointMessage) -> Unit
