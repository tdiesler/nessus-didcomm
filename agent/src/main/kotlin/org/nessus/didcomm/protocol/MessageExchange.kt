package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport


/**
 * A message exchange maintains a sequence of endpoint messages
 * that are associated with each other through their respective thread ids
 *
 * Incoming messages are automatically associated with an exchange based on
 * their (parent) thread id
 */
class MessageExchange(): AttachmentSupport() {
    val log = KotlinLogging.logger {}

    constructor(msg: EndpointMessage): this() {
        addMessage(msg)
    }

    companion object {

        // [TODO] MEMORY LEAK - eviction of outdated messages exchanges
        private val exchangeRegistry: MutableList<MessageExchange> = mutableListOf()

        /**
         * Find a MessageExchange by treadId
         * If no direct match is found, it retries with the parent treadId
         */
        fun findMessageExchange(msg: EndpointMessage): MessageExchange? {
            return exchangeRegistry.firstOrNull { it.threadIds.contains(msg.thid) }
                ?: exchangeRegistry.firstOrNull { it.threadIds.contains(msg.pthid) }
        }
    }

    private val messageStore: MutableList<EndpointMessage> = mutableListOf()

    val last get() = messages.last()
    val messages get() = messageStore.toList()
    val threadIds get() = messageStore.map { it.thid }

    fun addMessage(msg: EndpointMessage): MessageExchange {
        checkNotNull(msg.thid) { "No thread id in: $msg" }
        if (threadIds.isEmpty()) {
            check(findMessageExchange(msg) == null) { "Other message exchange exists for this thread: $msg" }
            exchangeRegistry.add(this)
        } else {
            check(threadIds.contains(msg.thid) || threadIds.contains(msg.pthid)) { "Invalid thread association: $msg" }
        }
        messageStore.add(msg)
        return this
    }

    fun getConnection(): Connection? {
        return getAttachment(AttachmentKey(Connection::class.java))
    }

    fun <T: Protocol<T>> withProtocol(key: ProtocolKey<T>): T {
        val protocolService = ProtocolService.getService()
        return protocolService.getProtocol(key, this)
    }
}
