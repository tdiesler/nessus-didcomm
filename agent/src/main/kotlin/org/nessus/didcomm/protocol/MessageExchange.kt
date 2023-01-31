package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol.Companion.RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.service.RFC0023DidDocument
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
import org.nessus.didcomm.wallet.Wallet
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit


/**
 * A message exchange records a sequence of messages associated with a Connection.
 *
 * These messages are correlated according to their respective thread ids, although
 * not enforced by the message exchange.
 *
 * In case of an external agent (e.g. AcaPy) we can only maintain a stub to the
 * actual connection maintained by the agent. In this case the message exchange
 * may not be able to see/record outgoing messages. In a best effort, we record
 * the command messages sent to the agent.
 */
class MessageExchange(): AttachmentSupport() {
    val log = KotlinLogging.logger {}

    constructor(msg: EndpointMessage): this() {
        addMessage(msg)
    }

    companion object {
        val INVITATION_ATTACHMENT_KEY = AttachmentKey(Invitation::class.java)
        val CONNECTION_ATTACHMENT_KEY = AttachmentKey(Connection::class.java)
        val REQUESTER_DIDDOC_ATTACHMENT_KEY = AttachmentKey("RequesterDidDoc", RFC0023DidDocument::class.java)
        val RESPONDER_DIDDOC_ATTACHMENT_KEY = AttachmentKey("ResponderDidDoc", RFC0023DidDocument::class.java)
        val WALLET_ATTACHMENT_KEY = AttachmentKey(Wallet::class.java)

        // [TODO] MEMORY LEAK - evict outdated messages exchanges
        private val exchangeRegistry: MutableList<MessageExchange> = mutableListOf()

        fun findByVerkey(recipientVerkey: String): MessageExchange {
            val mex = exchangeRegistry.firstOrNull { it.connection.myVerkey == recipientVerkey }
            checkNotNull(mex) { "Cannot find message exchange for recipient verkey: $recipientVerkey" }
            return mex
        }

        fun findByInvitationKey(invitationKey: String): List<MessageExchange> {
            return exchangeRegistry.filter {
                // It is legal for the exchange ot have an invitation and not (yet) a connection
                val pcon = it.getAttachment(CONNECTION_ATTACHMENT_KEY)
                val invi = it.getAttachment(INVITATION_ATTACHMENT_KEY)
                pcon?.invitationKey == invitationKey || invi?.invitationKey() == invitationKey
            }
        }
    }

    private val messageStore: MutableList<EndpointMessage> = mutableListOf()

    val mexId = "${UUID.randomUUID()}"
    val last get() = messages.last()
    val messages get() = messageStore.toList()
    val threadIds get() = messageStore.map { it.thid }

    var connection: Connection
        get() = run {
            checkNotNull(getAttachment(CONNECTION_ATTACHMENT_KEY)) { "No connection" }
            getAttachment(CONNECTION_ATTACHMENT_KEY) as Connection
        }
        set(pcon) = run {
            check(getAttachment(CONNECTION_ATTACHMENT_KEY) == null) { "Connection already set" }
            putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
        }

    val invitation: Invitation?
        get() = getAttachment(INVITATION_ATTACHMENT_KEY)

    fun addMessage(msg: EndpointMessage): MessageExchange {
        val logMsg = "Add message [id=${msg.id}, type=${msg.type}] to mex=$mexId"
        if (messageStore.isEmpty()) {
            msg.checkMessageType(RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION)
            putAttachment(INVITATION_ATTACHMENT_KEY, msg.body as Invitation)
            exchangeRegistry.add(this)
            messageStore.add(msg)
            log.info { logMsg }
            return this
        }
        check(msg.type != RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION) { "Invitation already added" }
        messageStore.add(msg)
        log.info { logMsg }
        return this
    }

    fun checkLastMessageType(expectedType: String) {
        last.checkMessageType(expectedType)
    }

    fun hasEndpointMessageFuture(messageType: String, cid: String): Boolean {
        val futureKey = AttachmentKey("$messageType?cid=$cid", CompletableFuture::class.java)
        return hasAttachment(futureKey)
    }

    fun placeEndpointMessageFuture(messageType: String, cid: String) {
        val futureId = "$messageType?cid=$cid"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        putAttachment(futureKey, CompletableFuture<EndpointMessage>())
        log.info("Placed future ${futureKey.name} on mex=$mexId")
    }

    // There is a potential race condition here, for example ...
    // - Invitee receives and Invitation and places DidEx Request future
    // - Responder
    fun awaitEndpointMessage(messageType: String, cid: String): EndpointMessage {
        val futureId = "$messageType?cid=$cid"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = getAttachment(futureKey)
        checkNotNull(future) { "No Future ${futureKey.name} on mex=$mexId" }
        try {
            log.info {"Wait for future ${futureKey.name} on mex=$mexId"}
            return future.get(10, TimeUnit.SECONDS) as EndpointMessage
        } finally {
            log.info {"Remove future ${futureKey.name} from mex=$mexId"}
            removeAttachment(futureKey)
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun completeEndpointMessageFuture(messageType: String, cid: String, epm: EndpointMessage) {
        val futureId = "$messageType?cid=$cid"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = getAttachment(futureKey) as? CompletableFuture<EndpointMessage>
        checkNotNull(future) { "No Future ${futureKey.name} on mex=$mexId" }
        log.info {"Complete future ${futureKey.name} on mex=$mexId"}
        future.complete(epm)
    }

    fun <T: Protocol<T>> withProtocol(key: ProtocolKey<T>): T {
        val protocolService = ProtocolService.getService()
        return protocolService.getProtocol(key, this)
    }

    fun <T: Any> withAttachment(key: AttachmentKey<T>, value: T): MessageExchange {
        putAttachment(key, value)
        return this
    }

    fun showMessages(name: String) {
        log.info { "MessageExchange ($name) - $mexId" }
        messages.forEach {
            log.info { "+ (id=${it.id}, thid=${it.thid}) - ${it.type}" }
        }
    }

    override fun toString(): String {
        return "MessageExchange(id=${mexId}, size=${messageStore.size}, thids=${threadIds})"
    }
}
