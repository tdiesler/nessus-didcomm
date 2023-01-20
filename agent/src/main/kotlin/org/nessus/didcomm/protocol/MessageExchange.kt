package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_CONTENT_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_DIRECTION
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ALIAS
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.service.ConnectionState
import org.nessus.didcomm.service.PeerConnection
import org.nessus.didcomm.service.ProtocolWrapperKey
import org.nessus.didcomm.service.RFC0019_ENCRYPTED_ENVELOPE_WRAPPER
import org.nessus.didcomm.service.RFC0023_DID_EXCHANGE_WRAPPER
import org.nessus.didcomm.service.RFC0048_TRUST_PING_WRAPPER
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE_WRAPPER
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_WRAPPER
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.wallet.Wallet
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future


/**
 * Records a sequence of messages associated with a protocol
 */
class MessageExchange (msg: EndpointMessage? = null): AttachmentSupport() {
    val log = KotlinLogging.logger {}

    private val _messages: MutableList<EndpointMessage> = mutableListOf()

    companion object {
        /**
         * Attachment keys
         */
        val MESSAGE_EXCHANGE_INVITEE_CONNECTION_ID_KEY = AttachmentKey("inviteeConnectionId", String::class.java)
        val MESSAGE_EXCHANGE_INVITEE_PEER_CONNECTION_KEY = AttachmentKey("inviteePeerConnection", PeerConnection::class.java)

        // Maps thread Ids to their respective exchanges
        private val exchangeRegistry: MutableMap<String, MessageExchange> = mutableMapOf()

        /**
         * Find a MessageExchange by treadId
         */
        fun findByThreadId(threadId: String): MessageExchange? {
            return exchangeRegistry[threadId]
        }
    }

    init {
        msg?.run { addMessage(msg) }
    }

    val messages get() = _messages.toList()
    val last get() = messages.last()

    private val threadIdFutures: MutableMap<String, CompletableFuture<Any>> = mutableMapOf()

    fun addMessage(msg: EndpointMessage) = apply {
        val maybeThreadId = msg.threadId
        val thisMessageExchange = this
        maybeThreadId?.apply {
            exchangeRegistry[this] = thisMessageExchange
        }
        _messages.add(msg)
    }

    @Suppress("UNCHECKED_CAST")
    fun <W: ProtocolWrapper<W, *>> withProtocol(key: ProtocolWrapperKey<W>): W {
        return when(key) {
            RFC0019_ENCRYPTED_ENVELOPE_WRAPPER -> RFC0019EncryptionEnvelopeWrapper(this)
            RFC0023_DID_EXCHANGE_WRAPPER -> RFC0023DidExchangeProtocolWrapper(this)
            RFC0048_TRUST_PING_WRAPPER -> RFC0048TrustPingProtocolWrapper(this)
            RFC0095_BASIC_MESSAGE_WRAPPER -> RFC0095BasicMessageProtocolWrapper(this)
            RFC0434_OUT_OF_BAND_WRAPPER -> RFC0434OutOfBandProtocolWrapper(this)
            else -> throw IllegalStateException("Unknown protocol: $key")
        } as W
    }

    fun addThreadIdFuture(thid: String) {
        threadIdFutures[thid] = CompletableFuture<Any>()
    }

    fun getThreadIdFuture(thid: String): Future<Any>? {
        return threadIdFutures[thid]
    }

    fun completeThreadIdFuture(thid: String, value: Any) {
        val future = threadIdFutures.remove(thid)
        future?.complete(value)
    }

    fun awaitPeerConnection(invitee: Wallet): PeerConnection?  {
        val connection = awaitConnectionState(invitee, setOf(ConnectionState.ACTIVE))
        if (connection["state"] == "active") {
            val peerConnection = PeerConnection.fromJson(connection)
            putAttachment(MESSAGE_EXCHANGE_INVITEE_PEER_CONNECTION_KEY, peerConnection)
            invitee.addConnection(peerConnection)
        }
        return getAttachment(MESSAGE_EXCHANGE_INVITEE_PEER_CONNECTION_KEY)
    }

    fun awaitConnectionState(wallet: Wallet, targetStates: Set<ConnectionState>): Map<String, Any?> {

        val supportedProtocols = setOf("didexchange/1.0")

        // Check if we already have an active connection
        var connection = messages
            .filter { supportedProtocols.contains(it.headers[MESSAGE_CONTENT_URI]) }
            .filter { it.bodyAsMap["state"] == "active" }
            .map { it.bodyAsMap }
            .lastOrNull()

        if (connection == null) {
            val record = AriesAgent.awaitConnectionRecord(wallet) {
                val currentState = ConnectionState.fromValue(it.state.name)
                it.invitationMsgId == last.threadId && targetStates.contains(currentState)
            }
            checkNotNull(record) {"${wallet.alias} has no connection record in state $targetStates"}

            val connectionProtocol = record.connectionProtocol.value
            check(supportedProtocols.contains(connectionProtocol)) { "Unsupported connection protocol: $connectionProtocol" }
            log.info { "${wallet.alias} connection: ${record.state}" }
            connection = gson.toJson(record).decodeJson()

            addMessage(EndpointMessage(
                connection, mapOf(
                    MESSAGE_THREAD_ID to last.threadId,
                    MESSAGE_DIRECTION to MessageDirection.INBOUND,
                    MESSAGE_FROM_ID to wallet.id,
                    MESSAGE_FROM_ALIAS to wallet.alias,
                    MESSAGE_CONTENT_URI to connectionProtocol,
                )
            ))
        }
        return connection
    }

}
