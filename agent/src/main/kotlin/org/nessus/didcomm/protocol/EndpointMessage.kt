package org.nessus.didcomm.protocol

import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson

/**
 * Associates an endpoint message with additional metadata
 */
class EndpointMessage(
    val body: Any? = null,
    headers: Map<String, Any?> = mapOf()
) {

    val headers: Map<String, Any?>
    init {
        this.headers = headers.toSortedMap()
    }

    companion object {
        /**
         * Header constants
         */
        const val MESSAGE_AUTO_ACCEPT = "MessageAutoAccept"
        const val MESSAGE_CONTENT_URI = "MessageContentUri"
        const val MESSAGE_DIRECTION = "MessageDirection"
        const val MESSAGE_FROM_ALIAS = "MessageFromAlias"
        const val MESSAGE_FROM_DID = "MessageFromDid"
        const val MESSAGE_FROM_ID = "MessageFromId"
        const val MESSAGE_PROTOCOL_METHOD = "MessageProtocolMethod"
        const val MESSAGE_PROTOCOL_PARAMS = "MessageProtocolParams"
        const val MESSAGE_PROTOCOL_URI = "MessageProtocolUri"
        const val MESSAGE_PARENT_THREAD_ID = "MessageParentThreadId"
        const val MESSAGE_THREAD_ID = "MessageThreadId"
        const val MESSAGE_TO_ALIAS = "MessageToAlias"
        const val MESSAGE_TO_DID = "MessageToDid"
        const val MESSAGE_TO_ID = "MessageToId"
    }

    val autoAccept get() = headers[MESSAGE_AUTO_ACCEPT] as? Boolean ?: true
    val contentUri get() = headers[MESSAGE_CONTENT_URI] as? String ?: { "No MESSAGE_CONTENT_URI" }
    val protocolMethod get() = headers[MESSAGE_PROTOCOL_METHOD] as? String ?: { "No MESSAGE_PROTOCOL_METHOD" }
    val protocolUri get() = headers[MESSAGE_PROTOCOL_URI] as? String ?: { "No MESSAGE_PROTOCOL_URI" }
    val parentThreadId get() = headers[MESSAGE_PARENT_THREAD_ID] as? String
    val threadId get() = headers[MESSAGE_THREAD_ID] as? String

    val bodyAsJson: String get() = run {
        if (body is String) return body
        else return gson.toJson(body)
    }

    @Suppress("UNCHECKED_CAST")
    val bodyAsMap: Map<String, Any?> get() = run {
        if (body is Map<*, *>)
            return body as Map<String, Any?>
        if (body is String)
            return body.decodeJson()
        val bodyJson = gson.toJson(body)
        return bodyJson.decodeJson()
    }

    class Builder() {
        private var body: Any? = null
        private var headers: MutableMap<String, Any?> = mutableMapOf()

        constructor(mex: MessageExchange): this(mex.last.body, mex.last.headers)
        constructor(body: Any? = null, headers: Map<String, Any?>): this() {
            this.body = body
            this.headers.putAll(headers)
        }

        fun body(body: Any) = apply {this.body = body }
        fun header(k: String, v: Any) = apply { this.headers[k] = v }
        fun headers(headers: Map<String, Any>) = apply {this.headers.putAll(headers) }
        fun build() = EndpointMessage(body, headers)
    }
}

enum class MessageDirection {
    INBOUND,
    OUTBOUND
}

typealias MessageListener = (msg: EndpointMessage) -> Boolean
