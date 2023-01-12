package org.nessus.didcomm.protocol

import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.PeerConnection
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.wallet.Wallet
import java.util.*


/**
 * Records a sequence of messages associated with a protocol
 */
class MessageExchange(
    msg: EndpointMessage? = null,
    val threadId: String = "${UUID.randomUUID()}",
    val parent: MessageExchange? = null
): AttachmentSupport() {

    private val _messages: MutableList<EndpointMessage> = mutableListOf()
    private val subExchanges: MutableList<MessageExchange> = mutableListOf()
    init {
        msg?.run { addMessage(msg) }
    }

    companion object {
        /**
         * Attachment keys
         */
        val MESSAGE_EXCHANGE_PEER_CONNECTION_KEY = AttachmentKey(PeerConnection::class.java)
    }

    val messages get() = _messages.toList()
    val last get() = messages.last()
    val headers get() = last.headers
    val body get() = last.body

    fun addSubExchange(messageExchange: MessageExchange) = apply {
        check(messageExchange.parent == this)
        subExchanges.add(messageExchange)
    }

    fun addMessage(msg: EndpointMessage) = apply {
        check(msg.threadId == this.threadId) { "Invalid thread id: ${msg.threadId}" }
        _messages.add(msg)
    }

    fun dispatchTo(target: Wallet, headers: Map<String, Any> = mapOf()) = apply {
        addMessage(EndpointMessage.Builder(this).headers(headers).build())
        MessageDispatchService.getService().sendTo(target, this)
    }

    fun getPeerConnection(): PeerConnection? {
        return getAttachment(MESSAGE_EXCHANGE_PEER_CONNECTION_KEY)
    }
}

enum class MessageDirection {
    INBOUND,
    OUTBOUND
}

/**
 * Associates an endpoint message with additional metadata
 */
class EndpointMessage(val body: Any? = null, headers: Map<String, Any> = mapOf()) {

    val headers: Map<String, Any>
    init {
        this.headers = headers.toMap()
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
        const val MESSAGE_THREAD_ID = "MessageThreadId"
        const val MESSAGE_TO_ALIAS = "MessageToAlias"
        const val MESSAGE_TO_DID = "MessageToDid"
        const val MESSAGE_TO_ID = "MessageToId"
    }

    val autoAccept get() = headers[MESSAGE_AUTO_ACCEPT] as? Boolean ?: true
    val contentUri get() = headers[MESSAGE_CONTENT_URI] as? String ?: { "No MESSAGE_CONTENT_URI" }
    val protocolMethod get() = headers[MESSAGE_PROTOCOL_METHOD] as? String ?: { "No MESSAGE_PROTOCOL_METHOD" }
    val protocolUri get() = headers[MESSAGE_PROTOCOL_URI] as? String ?: { "No MESSAGE_PROTOCOL_URI" }
    val threadId get() = headers[MESSAGE_THREAD_ID] as? String ?: { "No MESSAGE_THREAD_ID" }

    fun bodyAsMap(): Map<String, Any?> {
        if (body is String)
            return body.decodeJson()
        val bodyJson = gson.toJson(body)
        return bodyJson.decodeJson()
    }

    class Builder() {
        private var body: Any? = null
        private var headers: MutableMap<String, Any> = mutableMapOf()

        constructor(mex: MessageExchange): this(mex.body, mex.headers)
        constructor(body: Any? = null, headers: Map<String, Any>): this() {
            this.body = body
            this.headers.putAll(headers)
        }

        fun body(body: Any) = apply {this.body = body }
        fun header(k: String, v: Any) = apply { this.headers[k] = v }
        fun headers(headers: Map<String, Any>) = apply {this.headers.putAll(headers) }
        fun build() = EndpointMessage(body, headers)
    }
}

typealias MessageListener = (msg: EndpointMessage) -> Boolean
