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

import id.walt.common.prettyPrint
import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidDocV1
import org.nessus.didcomm.model.DidPeer
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.PropertiesService.PROTOCOL_TRUST_PING_ROTATE_DID
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.util.dateTimeInstant
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.encodeJson
import java.time.OffsetDateTime
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Nessus DIDComm: Trust Ping Protocol 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0048-trust-ping
 */
class TrustPingProtocolV2(mex: MessageExchange): Protocol<TrustPingProtocolV2>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = TRUST_PING_PROTOCOL_V2.uri

    companion object {
        val TRUST_PING_MESSAGE_TYPE_PING_V2 = "${TRUST_PING_PROTOCOL_V2.uri}/ping"
        val TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2 = "${TRUST_PING_PROTOCOL_V2.uri}/ping-response"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            TRUST_PING_MESSAGE_TYPE_PING_V2 -> receiveTrustPing(to)
            TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2 -> receiveTrustPingResponse(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendTrustPing(connection: Connection? = null): TrustPingProtocolV2 {

        val pcon = connection ?: mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        val sender = modelService.findWalletByDid(pcon.myDid.uri)
        checkNotNull(sender) { "No sender wallet" }

        val senderDid = pcon.myDid
        val recipientDid = pcon.theirDid

        val trustPingBuilder = TrustPingMessageV2.Builder(
            id = "${UUID.randomUUID()}",
            type = TRUST_PING_MESSAGE_TYPE_PING_V2)
            .from(senderDid.uri)
            .to(listOf(recipientDid.uri))
            .createdTime(dateTimeNow())
            .expiresTime(dateTimeNow().plusHours(24))
            .comment("Ping from ${sender.name}")
            .responseRequested(true)

        // FIRST TRUST PING
        // Add the DidDoc attachment when we don't have a did:peer:2
        val maybeDidPeer = DidPeer.fromUri(senderDid.uri)

        if (pcon.state == ConnectionState.INVITATION) {
            mex.getInvitation()?.also { invitation ->
                trustPingBuilder.thid(invitation.id)
            }
            if (maybeDidPeer?.numalgo != 2) {
                val senderDidDoc = didService.loadDidDoc(senderDid.uri)
                val senderDidDocAttachment = senderDidDoc.toAttachment()
                trustPingBuilder.attachments(listOf(senderDidDocAttachment))
            }
            pcon.state = ConnectionState.COMPLETED
        }

        // Use the Connection's MessageExchange
        val senderMex = MessageExchange.findByConnectionId(pcon.id)
        checkNotNull(senderMex) { "No message exchange for: ${pcon.shortString()}" }

        val trustPingMsg = trustPingBuilder.build().toMessage()
        senderMex.addMessage(EndpointMessage.Builder(trustPingMsg).outbound().build())
        log.info { "Sender (${sender.name}) creates TrustPing: ${trustPingMsg.encodeJson(true)}" }

        // Register the TrustPing Response future
        senderMex.placeEndpointMessageFuture(TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2)

        dispatchEncryptedMessage(pcon, trustPingMsg) { packedEpm ->
            log.info { "Sender (${sender.name}) sends TrustPing: ${packedEpm.prettyPrint()}" }
        }

        return senderMex.withProtocol(TRUST_PING_PROTOCOL_V2)
    }

    fun awaitTrustPingResponse(timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): TrustPingProtocolV2 {
        mex.awaitEndpointMessage(TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2, timeout, unit)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    /**
     * Receives a Trust Ping and automatically sends the response
     */
    private fun receiveTrustPing(receiver: Wallet): TrustPingProtocolV2 {

        val trustPingEpm = mex.last
        val trustPingMsg = mex.last.body as Message
        trustPingEpm.checkMessageType(TRUST_PING_MESSAGE_TYPE_PING_V2)
        val trustPing = TrustPingMessageV2.fromMessage(trustPingMsg)

        // FIRST TRUST PING
        // Update the Inviter Did + Document + Connection

        val pcon = mex.getConnection()
        var fromPriorIssuerKid: String? = null

        if (pcon.state == ConnectionState.INVITATION) {

            val invitationDid = pcon.myDid
            val invitationDidDoc = didService.loadDidDoc(invitationDid.uri)
            fromPriorIssuerKid = invitationDidDoc.authentications.first()

            val senderDid = Did.fromUri(trustPing.from as String)
            val senderDidDoc = DidDocV1.fromMessage(trustPingMsg) ?: didService.resolveDidDoc(senderDid.uri)
            checkNotNull(senderDidDoc) { "No sender DidDoc" }

            didService.importDidDoc(senderDidDoc)

            // Rotate the inviter Did
            val inviterDid = when(properties.asBoolean(PROTOCOL_TRUST_PING_ROTATE_DID)) {
                true -> receiver.createDid(invitationDid.method)
                false -> invitationDid
            }

            pcon.myDid = inviterDid
            pcon.theirDid = senderDid
            pcon.theirLabel = modelService.findWalletByDid(senderDid.uri)?.name
            pcon.state = ConnectionState.ACTIVE
            receiver.currentConnection = pcon

            log.info { "Connection ${pcon.state}: ${pcon.encodeJson(true)}"}
        }

        if (trustPing.responseRequested != false)
            sendTrustPingResponse(receiver, trustPing.id, fromPriorIssuerKid)

        pcon.state = ConnectionState.ACTIVE

        if (mex.hasEndpointMessageFuture(TRUST_PING_MESSAGE_TYPE_PING_V2))
            mex.completeEndpointMessageFuture(TRUST_PING_MESSAGE_TYPE_PING_V2, trustPingEpm)

        return this
    }

    private fun sendTrustPingResponse(receiver: Wallet, threadId: String, fromPriorIssuerKid: String?) {
        val pcon = mex.getConnection()
        val receiverDid = pcon.myDid
        val senderDid = pcon.theirDid

        val trustPingResponse = TrustPingMessageV2.Builder(
                id = "${UUID.randomUUID()}",
                type = TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2)
            .thid(threadId)
            .from(receiverDid.uri)
            .to(listOf(senderDid.uri))
            .createdTime(dateTimeNow())
            .expiresTime(dateTimeNow().plusHours(24))
            .comment("Pong from ${receiver.name}")
            .build()

        val trustPingResponseMsg = trustPingResponse.toMessage()
        mex.addMessage(EndpointMessage.Builder(trustPingResponseMsg).outbound().build())
        log.info { "Receiver (${receiver.name}) creates TrustPing Response: ${trustPingResponseMsg.encodeJson(true)}" }

        dispatchEncryptedMessage(pcon, trustPingResponseMsg, fromPriorIssuerKid) { packedEpm ->
            log.info { "Receiver (${receiver.name}) sends TrustPing Response: ${packedEpm.prettyPrint()}" }
        }
    }

    private fun receiveTrustPingResponse(receiver: Wallet): TrustPingProtocolV2 {

        val trustPingResponseEpm = mex.last
        val trustPingResponseMsg = mex.last.body as Message
        trustPingResponseEpm.checkMessageType(TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2)

        val trustPingResponse = TrustPingMessageV2.fromMessage(trustPingResponseMsg)

        val pcon = mex.getConnection()
        pcon.theirDid = Did.fromUri(trustPingResponse.from as String)
        pcon.state = ConnectionState.ACTIVE
        receiver.currentConnection = pcon

        mex.completeEndpointMessageFuture(TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2, mex.last)

        return this
    }
}

class TrustPingMessageV2(
    val id: String,
    val type: String,
    val thid: String?,
    val from: String?,
    val to: List<String>?,
    val createdTime: OffsetDateTime?,
    val expiresTime: OffsetDateTime?,
    val comment: String?,
    val responseRequested: Boolean?,
    val attachments: List<Attachment>?,
) {
    internal constructor(builder: Builder): this(
        id = builder.id,
        type = builder.type,
        thid = builder.thid,
        from = builder.from,
        to = builder.to,
        createdTime = builder.createdTime,
        expiresTime = builder.expiresTime,
        comment = builder.comment,
        responseRequested = builder.responseRequested,
        attachments = builder.attachments,
    )

    companion object {
        fun fromMessage(msg: Message): TrustPingMessageV2 {
            requireNotNull(msg.from) { "No from" }
            val createdTime = msg.createdTime?.run { dateTimeInstant(msg.createdTime!!) }
            val expiresTime = msg.expiresTime?.run { dateTimeInstant(msg.expiresTime!!) }
            val comment = msg.body["comment"] as? String
            val responseRequested = msg.body["response_requested"] as? Boolean
            return Builder(msg.id, msg.type)
                .thid(msg.thid)
                .from(msg.from)
                .to(msg.to)
                .createdTime(createdTime)
                .expiresTime(expiresTime)
                .comment(comment)
                .responseRequested(responseRequested)
                .attachments(msg.attachments)
                .build()
        }
    }

    fun toMessage(): Message {
        val body = LinkedHashMap<String, Any>()
        comment?.also { body["comment"] = it }
        responseRequested?.also { body["response_requested"] = it }
        return MessageBuilder(id, body, type)
            .thid(thid)
            .from(from)
            .to(to)
            .createdTime(createdTime?.toInstant()?.epochSecond)
            .expiresTime(expiresTime?.toInstant()?.epochSecond)
            .attachments(attachments)
            .build()
    }

    class Builder(
        val id: String,
        val type: String) {

        internal var thid: String? = null
        internal var from: String? = null
        internal var to: List<String>? = null
        internal var createdTime: OffsetDateTime? = null
        internal var expiresTime: OffsetDateTime? = null
        internal var comment: String? = null
        internal var responseRequested: Boolean? = null
        internal var attachments: List<Attachment>? = null

        fun thid(thid: String?) = apply { this.thid = thid }
        fun from(from: String?) = apply { this.from = from }
        fun to(to: List<String>?) = apply { this.to = to }
        fun createdTime(createdTime: OffsetDateTime?) = apply { this.createdTime = createdTime }
        fun expiresTime(expiresTime: OffsetDateTime?) = apply { this.expiresTime = expiresTime }
        fun comment(comment: String?) = apply { this.comment = comment }
        fun responseRequested(responseRequested: Boolean?) = apply { this.responseRequested = responseRequested }
        fun attachments(attachments: List<Attachment>?) = apply { this.attachments = attachments?.toList() }

        fun build(): TrustPingMessageV2 {
            return TrustPingMessageV2(this)
        }
    }
}

