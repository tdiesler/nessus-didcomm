package org.nessus.didcomm.protocol

import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.isJson
import org.nessus.didcomm.util.selectJson

/**
 * Associates an endpoint message with additional metadata
 */
class EndpointMessage(
    val body: Any,
    headers: Map<String, Any?> = mapOf()
) {

    val headers: Map<String, Any?>
    init {
        check(body !is EndpointMessage) { "Nested endpoint message"}
        if (body is String && body.isJson()) {
            val id = body.selectJson("@id")
            val type = body.selectJson("@type")
            val thid = body.selectJson("~thread.thid") ?: id
            val pthid = body.selectJson("~thread.pthid")
            val effHeaders = headers.toMutableMap()
            id?.run { effHeaders[MESSAGE_ID] = id }
            type?.run { effHeaders[MESSAGE_TYPE] = type }
            thid?.run { effHeaders[MESSAGE_THID] = thid }
            pthid?.run { effHeaders[MESSAGE_PTHID] = pthid }
            this.headers = effHeaders.toSortedMap()
        } else {
            this.headers = headers.toSortedMap()
        }
    }

    companion object {
        /**
         * Header constants
         */
        const val MESSAGE_AUTO_ACCEPT = "MessageAutoAccept"
        const val MESSAGE_ID = "MessageId"
        const val MESSAGE_PROTOCOL_URI = "MessageProtocolUri"
        const val MESSAGE_PTHID = "MessageParentThid"
        const val MESSAGE_RECIPIENT_VERKEY = "MessageRecipientVerkey"
        const val MESSAGE_SENDER_VERKEY = "MessageSenderVerkey"
        const val MESSAGE_THID = "MessageThid"
        const val MESSAGE_TYPE = "MessageType"
    }

    val autoAccept get() = headers[MESSAGE_AUTO_ACCEPT] as? Boolean ?: true
    val messageId get() = headers[MESSAGE_ID] as? String ?: { "No MESSAGE_ID" }
    val messageType get() = headers[MESSAGE_TYPE] as? String ?: { "No MESSAGE_TYPE" }
    val protocolUri get() = headers[MESSAGE_PROTOCOL_URI] as? String ?: { "No MESSAGE_PROTOCOL_URI" }
    val pthid get() = headers[MESSAGE_PTHID] as? String
    val recipientVerkey get() = headers[MESSAGE_RECIPIENT_VERKEY] as? String
    val senderVerkey get() = headers[MESSAGE_SENDER_VERKEY] as? String
    val thid get() = headers[MESSAGE_THID] as? String

    val bodyAsJson: String get() = run {
        if (body is String) return body
        else return gson.toJson(body)
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

typealias MessageListener = (msg: EndpointMessage) -> MessageExchange?
