package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.service.RFC0023DidDocument
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
import org.nessus.didcomm.wallet.Wallet


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
        val CONNECTION_ATTACHMENT_KEY = AttachmentKey(Connection::class.java)
        val INVITATION_ATTACHMENT_KEY = AttachmentKey(Invitation::class.java)
        val INVITER_WALLET_ATTACHMENT_KEY = AttachmentKey("InviterWallet", Wallet::class.java)
        val INVITEE_WALLET_ATTACHMENT_KEY = AttachmentKey("InviteeWallet", Wallet::class.java)
        val REQUESTER_DIDDOC_ATTACHMENT_KEY = AttachmentKey("RequesterDidDoc", RFC0023DidDocument::class.java)
        val RESPONDER_DIDDOC_ATTACHMENT_KEY = AttachmentKey("ResponderDidDoc", RFC0023DidDocument::class.java)

        // [TODO] MEMORY LEAK - evict outdated messages exchanges
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
            check(findMessageExchange(msg) == null) { "Other message exchange exists for: $msg" }
            exchangeRegistry.add(this)
        } else {
            check(threadIds.contains(msg.thid) || threadIds.contains(msg.pthid)) { "Invalid thread association: $msg" }
        }
        messageStore.add(msg)
        return this
    }

    fun expectedLastMessageType(expectedType: String) {
        val messageTypes = messages.map { it.messageType }
        check(messageTypes.last() == expectedType) { "Unexpected last message type: $messageTypes" }
    }

    /**
     * The connection is always that of the Nessus side
     * If both sides are Nessus, it is that of the Requester
     */
    fun getConnection(): Connection? {
        return getAttachment(CONNECTION_ATTACHMENT_KEY)
    }

    fun <T: Protocol<T>> withProtocol(key: ProtocolKey<T>): T {
        val protocolService = ProtocolService.getService()
        return protocolService.getProtocol(key, this)
    }
}
