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
package org.nessus.didcomm.model

import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.util.ellipsis
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.isJson
import org.nessus.didcomm.util.selectJson
import java.util.UUID

enum class MessageDirection { IN, OUT }

/**
 * Associates an endpoint message with additional metadata
 */
class EndpointMessage private constructor(
    val body: Any,
    extraHeaders: Map<String, Any?> = mapOf()
) {

    companion object {
        /**
         * Header constants
         */
        const val MESSAGE_HEADER_ID = "MessageId"
        const val MESSAGE_HEADER_DIRECTION = "MessageDirection"
        const val MESSAGE_HEADER_ENDPOINT_URL = "MessageEndpointUrl"
        const val MESSAGE_HEADER_MEDIA_TYPE = "MessageMediaType"
        const val MESSAGE_HEADER_PROTOCOL_URI = "MessageProtocolUri"
        const val MESSAGE_HEADER_SENDER_DID = "MessageSenderDid"
        const val MESSAGE_HEADER_RECIPIENT_DID = "MessageRecipientDid"
        const val MESSAGE_HEADER_PTHID = "MessageParentThid"
        const val MESSAGE_HEADER_THID = "MessageThid"
        const val MESSAGE_HEADER_TYPE = "MessageType"
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
            id?.also { effHeaders[MESSAGE_HEADER_ID] = id }
            type?.also { effHeaders[MESSAGE_HEADER_TYPE] = type }
            thid?.also { effHeaders[MESSAGE_HEADER_THID] = thid }
            pthid?.also { effHeaders[MESSAGE_HEADER_PTHID] = pthid }
        } else if (body is Message) {
            effHeaders[MESSAGE_HEADER_ID] = body.id
            effHeaders[MESSAGE_HEADER_MEDIA_TYPE] = body.typ.typ
            effHeaders[MESSAGE_HEADER_TYPE] = body.type
            body.thid?.also { effHeaders[MESSAGE_HEADER_THID] = body.thid }
            body.pthid?.also { effHeaders[MESSAGE_HEADER_PTHID] = body.pthid }
        }
        if (effHeaders[MESSAGE_HEADER_ID] == null) {
            val auxId = "${UUID.randomUUID()}"
            val idx = auxId.indexOf('-') + 1
            effHeaders[MESSAGE_HEADER_ID] = "00000000-${auxId.substring(idx)}"
        }
        this.headers = effHeaders.toSortedMap()
    }

    val id = headers[MESSAGE_HEADER_ID] as String
    val type = headers[MESSAGE_HEADER_TYPE] as? String
    val thid = headers[MESSAGE_HEADER_THID] as? String ?: id
    val pthid = headers[MESSAGE_HEADER_PTHID] as? String
    val protocolUri = headers[MESSAGE_HEADER_PROTOCOL_URI] as? String
    val senderDid = headers[MESSAGE_HEADER_SENDER_DID] as? String
    val recipientDid = headers[MESSAGE_HEADER_RECIPIENT_DID] as? String
    val messageDirection = headers[MESSAGE_HEADER_DIRECTION]

    val bodyAsJson: String get() = run {
        return if (body is String) body else gson.toJson(body)
    }

    fun checkMessageType(expectedType: String) {
        check(type == expectedType) { "Unexpected message type: $type" }
    }

    fun shortString(): String {
        return "[id=${id.ellipsis()}, thid=${thid.ellipsis()}, type=$type]"
    }

    override fun toString(): String {
        return "EndpointMessage(headers=$headers, body=$body)"
    }

    class Builder(var body: Any) {
        private var headers: MutableMap<String, Any?> = mutableMapOf()

        constructor(body: Any, headers: Map<String, Any?>): this(body) {
            this.headers.putAll(headers)
        }

        fun body(body: Any) = apply {this.body = body }
        fun inbound() = apply { headers[MESSAGE_HEADER_DIRECTION] = MessageDirection.IN }
        fun outbound() = apply { headers[MESSAGE_HEADER_DIRECTION] = MessageDirection.OUT }
        fun header(k: String, v: Any?) = apply { if (v != null) this.headers[k] = v }
        fun build() = EndpointMessage(body, headers)
    }
}