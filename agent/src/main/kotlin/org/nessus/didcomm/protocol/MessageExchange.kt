package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.service.ProtocolWrapperKey
import org.nessus.didcomm.util.AttachmentSupport
import org.nessus.didcomm.util.Holder


/**
 * Records a sequence of endpoint messages
 *
 * - A message exchange may have a threadId
 * - Message exchanges without a threadId are not maintained in the registry
 * - It is guaranteed that all associated messages have the same threadId as the message exchange
 * - No two message exchanges can have the same threadId
 */
class MessageExchange(): AttachmentSupport() {
    val log = KotlinLogging.logger {}

    constructor(msg: EndpointMessage): this() {
        addMessage(msg)
    }

    companion object {
        /**
         * Attachment keys
         */
        // val MESSAGE_EXCHANGE_INVITEE_CONNECTION_ID_KEY = AttachmentKey("inviteeConnectionId", String::class.java)
        // val MESSAGE_EXCHANGE_INVITEE_PEER_CONNECTION_KEY = AttachmentKey("inviteePeerConnection", PeerConnection::class.java)

        // Maps thread Ids to their respective exchanges
        private val exchangeRegistry: MutableMap<String, MessageExchange> = mutableMapOf()

        /**
         * Find a MessageExchange by treadId
         */
        fun findMessageExchange(threadId: String?): MessageExchange? {
            return threadId?.run { exchangeRegistry[threadId] }
        }
    }

    private val messageStore: MutableList<EndpointMessage> = mutableListOf()
    private val threadIdHolder = Holder<String>(null)

    val threadId get() = threadIdHolder.obj
    val messages get() = messageStore.toList()
    val last get() = messages.last()

    fun addMessage(msg: EndpointMessage): MessageExchange {
        if (threadId == null)
            threadIdHolder.obj = msg.thid
        check(threadId == msg.thid) { "Unexpected message thread" }
        if (threadId != null) {
            val other = exchangeRegistry[threadId]
            check(other == null || this == other) { "Duplicate message exchange for: $threadId" }
            exchangeRegistry[threadId!!] = this
        }
        messageStore.add(msg)
        return this
    }

    fun <W: ProtocolWrapper<W, *>> withProtocol(key: ProtocolWrapperKey<W>): W {
        val protocolService = ProtocolService.getService()
        return protocolService.getProtocolWrapper(key, this)
    }
}
