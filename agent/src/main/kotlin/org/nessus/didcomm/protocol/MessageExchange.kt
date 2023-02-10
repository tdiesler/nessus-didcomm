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

import mu.KotlinLogging
import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.did.DidDoc
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV1
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocolV1.Companion.RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V1
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocolV2.Companion.RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
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
 * may not be able to see/record outgoing messages. In the best effort, we record
 * the command messages sent to the agent.
 */
class MessageExchange(): AttachmentSupport() {

    constructor(msg: EndpointMessage): this() {
        addMessage(msg)
    }

    companion object {
        val log = KotlinLogging.logger {}

        val INVITATION_ATTACHMENT_KEY = AttachmentKey(Invitation::class)
        val CONNECTION_ATTACHMENT_KEY = AttachmentKey(Connection::class)
        val REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY = AttachmentKey("RequesterDidDoc", DidDoc::class)
        val RESPONDER_DID_DOCUMENT_ATTACHMENT_KEY = AttachmentKey("ResponderDidDoc", DidDoc::class)
        val WALLET_ATTACHMENT_KEY = AttachmentKey(Wallet::class)

        // [TODO] MEMORY LEAK - evict outdated messages exchanges
        private val exchangeRegistry: MutableList<MessageExchange> = mutableListOf()

        fun findByVerkey(recipientVerkey: String): MessageExchange {
            synchronized(exchangeRegistry) {
                val mex = exchangeRegistry.firstOrNull {
                    val pcon = it.getAttachment(CONNECTION_ATTACHMENT_KEY)
                    pcon?.myVerkey == recipientVerkey
                }
                if (mex == null) {
                    exchangeRegistry.forEach { log.error { "Candidate $it" } }
                }
                checkNotNull(mex) { "Cannot find message exchange for recipient verkey: $recipientVerkey" }
                return mex
            }
        }

        fun findByInvitationKey(invitationKey: String): List<MessageExchange> {
            return synchronized(exchangeRegistry) {
                exchangeRegistry.filter {
                    // It is legal for the exchange ot have an invitation and not (yet) a connection
                    val pcon = it.getAttachment(CONNECTION_ATTACHMENT_KEY)
                    val invi = it.getAttachment(INVITATION_ATTACHMENT_KEY)
                    pcon?.invitationKey == invitationKey || invi?.invitationKey() == invitationKey
                }
            }
        }
    }

    private val messageStore: MutableList<EndpointMessage> = mutableListOf()

    val id = "${UUID.randomUUID()}"
    val last get() = messages.last()

    @get:Synchronized
    val messages: List<EndpointMessage>
        get() = messageStore.toList()

    /**
     * The connection becomes available when this message exchange receives the first message, which
     * must be one of the supported invitation message types. The connection may be in any of its
     * supported states.
     *
     * @throws IllegalStateException when there is no connection available
     */
    fun getConnection(): Connection {
        synchronized(exchangeRegistry) {
            checkNotNull(getAttachment(CONNECTION_ATTACHMENT_KEY)) { "No connection" }
            return getAttachment(CONNECTION_ATTACHMENT_KEY) as Connection
        }
    }

    fun setConnection(pcon: Connection) {
        synchronized(exchangeRegistry) {
            check((getAttachment(CONNECTION_ATTACHMENT_KEY) == null)) { "Connection already set" }
            putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
        }
    }

    fun getInvitation(): Invitation? {
        return getAttachment(INVITATION_ATTACHMENT_KEY)
    }

    fun addMessage(msg: EndpointMessage): MessageExchange {
        synchronized(exchangeRegistry) {
            val logMsg = "Add message [id=${msg.id}, type=${msg.type}] to mex=$id"
            if (messageStore.isEmpty()) {
                check(msg.type in listOf(
                    RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V1,
                    RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2)) { "Unexpected message type: ${msg.type}" }
                val invitation = when(msg.body) {
                    is InvitationV1 -> Invitation(msg.body)
                    is Message -> Invitation(InvitationV2.fromMessage(msg.body))
                    else -> throw IllegalStateException( "Unexpected message body: ${msg.body.javaClass}" )
                }
                putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
                exchangeRegistry.add(this)
                messageStore.add(msg)
                log.info { logMsg }
                return this
            }
            check(msg.type !in listOf(
                RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V1,
                RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2)) { "Invitation already added" }
            messageStore.add(msg)
            log.info { logMsg }
            return this
        }
    }

    fun checkLastMessageType(expectedType: String) {
        last.checkMessageType(expectedType)
    }

    fun hasEndpointMessageFuture(messageType: String): Boolean {
        return hasAttachment(getFutureKey(messageType))
    }

    fun placeEndpointMessageFuture(messageType: String) {
        val futureKey = getFutureKey(messageType)
        putAttachment(futureKey, CompletableFuture<EndpointMessage>())
        log.info("Placed future ${futureKey.name} on mex=$id")
    }

    fun awaitEndpointMessage(messageType: String, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): EndpointMessage {
        val futureKey = getFutureKey(messageType)
        val future = getAttachment(futureKey)
        checkNotNull(future) { "No Future ${futureKey.name} on mex=$id" }
        try {
            log.info {"Wait for future ${futureKey.name} on mex=$id"}
            return future.get(timeout.toLong(), unit) as EndpointMessage
        } finally {
            log.info {"Remove future ${futureKey.name} from mex=$id"}
            removeAttachment(futureKey)
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun completeEndpointMessageFuture(messageType: String, epm: EndpointMessage) {
        val futureKey = getFutureKey(messageType)
        val future = getAttachment(futureKey) as? CompletableFuture<EndpointMessage>
        checkNotNull(future) { "No Future ${futureKey.name} on mex=$id" }
        log.info {"Complete future ${futureKey.name} on mex=$id"}
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
        log.info { "MessageExchange ($name) - $id" }
        messages.forEach {
            log.info { "+ (id=${it.id}, thid=${it.thid}) - ${it.type}" }
        }
    }

    override fun toString(): String {
        val pcon = getAttachment(CONNECTION_ATTACHMENT_KEY)
        return "MessageExchange(id=${id}, size=${messageStore.size}, verkey=${pcon?.myVerkey})"
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun getFutureKey(messageType: String): AttachmentKey<CompletableFuture<*>> {
        return AttachmentKey(messageType, CompletableFuture::class)
    }
}
