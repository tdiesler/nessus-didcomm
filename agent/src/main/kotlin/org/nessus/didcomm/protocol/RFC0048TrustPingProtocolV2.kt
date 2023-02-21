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
import org.didcommx.didcomm.common.Typ
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.didcommx.didcomm.model.PackEncryptedParams
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V2
import org.nessus.didcomm.util.dateTimeInstant
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.encodeJson
import java.time.OffsetDateTime
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Nessus DIDComm RFC0048: Trust Ping Protocol 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingProtocolV2(mex: MessageExchange): Protocol<RFC0048TrustPingProtocolV2>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0048_TRUST_PING_V2.uri

    companion object {
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2 = "${RFC0048_TRUST_PING_V2.uri}/ping"
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2 = "${RFC0048_TRUST_PING_V2.uri}/ping_response"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.ACAPY, AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2 -> receiveTrustPing(to)
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2 -> receiveTrustPingResponse()
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendTrustPing(connection: Connection? = null): RFC0048TrustPingProtocolV2 {

        val pcon = connection ?: mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        val sender = modelService.findWalletByVerkey(pcon.myVerkey)
        checkNotNull(sender) { "No sender wallet" }

        val senderDid = pcon.myDid
        val recipientDid = pcon.theirDid

        val trustPingBuilder = TrustPingMessageV2.Builder(
            id = "${UUID.randomUUID()}",
            type = RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2)
            .from(senderDid.uri)
            .to(listOf(recipientDid.uri))
            .createdTime(dateTimeNow())
            .expiresTime(dateTimeNow().plusHours(24))
            .comment("Ping from ${sender.name}")

        // FIRST TRUST PING
        // Attach our DID Document when this is the first time we do a Trust Ping

        if (pcon.state == ConnectionState.INVITATION) {
            val senderDidDoc = diddocV2Service.resolveDidDocument(senderDid.uri)
            val senderDidDocAttachment = diddocV2Service.createDidDocAttachment(senderDidDoc)
            trustPingBuilder.attachments(listOf(senderDidDocAttachment))
            pcon.state = ConnectionState.COMPLETED
        }

        // Use the Connection's MessageExchange
        val senderMex = MessageExchange.findByVerkey(pcon.myVerkey)
        val rfc0048 = senderMex.withProtocol(RFC0048_TRUST_PING_V2)

        // Register the TrustPing Response future
        senderMex.placeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2)

        val trustPingMsg = trustPingBuilder.build().toMessage()
        senderMex.addMessage(EndpointMessage(trustPingMsg))
        log.info { "Sender (${sender.name}) creates TrustPing: ${trustPingMsg.encodeJson(true)}" }

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(trustPingMsg, recipientDid.uri)
                .signFrom(senderDid.uri)
                .from(senderDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            EndpointMessage.MESSAGE_HEADER_ID to "${trustPingMsg.id}.packed",
            EndpointMessage.MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
        ))
        log.info { "Sender (${sender.name}) sends TrustPing: ${packedEpm.prettyPrint()}" }

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return rfc0048
    }

    fun awaitTrustPingResponse(timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): RFC0048TrustPingProtocolV2 {
        mex.awaitEndpointMessage(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2, timeout, unit)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    /**
     * Receives a Trust Ping and automatically sends the response
     */
    private fun receiveTrustPing(receiver: Wallet): RFC0048TrustPingProtocolV2 {

        val trustPingEpm = mex.last
        val trustPingMsg = mex.last.body as Message
        trustPingEpm.checkMessageType(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2)
        val trustPing = TrustPingMessageV2.fromMessage(trustPingMsg)

        // FIRST TRUST PING
        // Update the Inviter Did + Document + Connection

        val pcon = mex.getConnection()
        var fromPriorIssuerKid: String? = null

        if (pcon.state == ConnectionState.INVITATION) {

            val invitationDid = pcon.myDid
            val invitationDidDoc = diddocV2Service.resolveDidDocument(invitationDid.uri)
            fromPriorIssuerKid = invitationDidDoc.authentications.first()

            val senderDid = Did.fromSpec(trustPing.from as String)
            val senderDidDoc = diddocV2Service.resolveDidDocument(senderDid.uri)
            val senderEndpointUrl = senderDidDoc.serviceEndpoint() as String

            // Create and register the Did Document for this Invitation
            val inviterDid = receiver.createDid(DidMethod.KEY)
            val inviterEndpointUrl = receiver.endpointUrl

            pcon.myDid = inviterDid
            pcon.myEndpointUrl = inviterEndpointUrl
            pcon.theirDid = senderDid
            pcon.theirEndpointUrl = senderEndpointUrl
            pcon.state = ConnectionState.ACTIVE
        }

        val receiverDid = pcon.myDid
        val senderDid = pcon.theirDid

        val trustPingResponse = TrustPingMessageV2.Builder(
            id = "${UUID.randomUUID()}",
            type = RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2)
            .thid(trustPing.id)
            .from(receiverDid.uri)
            .to(listOf(senderDid.uri))
            .createdTime(dateTimeNow())
            .expiresTime(dateTimeNow().plusHours(24))
            .comment("Pong from ${receiver.name}")
            .build()

        val trustPingResponseMsg = trustPingResponse.toMessage()
        mex.addMessage(EndpointMessage(trustPingResponseMsg)).last
        log.info { "Receiver (${receiver.name}) creates TrustPing Response: ${trustPingResponseMsg.encodeJson(true)}" }

        val packResult = didComm.packEncrypted(
            if (fromPriorIssuerKid != null) {
                PackEncryptedParams.builder(trustPingResponseMsg, senderDid.uri)
                    .fromPriorIssuerKid(fromPriorIssuerKid)
                    .signFrom(receiverDid.uri)
                    .from(receiverDid.uri)
                    .build()
            } else {
                PackEncryptedParams.builder(trustPingResponseMsg, senderDid.uri)
                    .signFrom(receiverDid.uri)
                    .from(receiverDid.uri)
                    .build()
            }
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            EndpointMessage.MESSAGE_HEADER_ID to "${trustPingResponseMsg.id}.packed",
            EndpointMessage.MESSAGE_HEADER_THID to trustPing.id,
            EndpointMessage.MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
        ))
        log.info { "Receiver (${receiver.name}) sends TrustPing Response: ${packedEpm.prettyPrint()}" }

        pcon.state = ConnectionState.ACTIVE

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)

        if (mex.hasEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2))
            mex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2, trustPingEpm)

        return this
    }

    private fun receiveTrustPingResponse(): RFC0048TrustPingProtocolV2 {

        val trustPingResponseEpm = mex.last
        val trustPingResponseMsg = mex.last.body as Message
        trustPingResponseEpm.checkMessageType(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2)

        val trustPingResponse = TrustPingMessageV2.fromMessage(trustPingResponseMsg)

        val pcon = mex.getConnection()
        pcon.state = ConnectionState.ACTIVE
        pcon.theirDid = Did.fromSpec(trustPingResponse.from as String)
        mex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2, mex.last)

        return this
    }
}

class TrustPingMessageV2(
    val id: String,
    val type: String,
    val thid: String?,
    val pthid: String?,
    val from: String?,
    val to: List<String>?,
    val createdTime: OffsetDateTime?,
    val expiresTime: OffsetDateTime?,
    val comment: String?,
    val attachments: List<Attachment>?,
) {
    internal constructor(builder: Builder): this(
        id = builder.id,
        type = builder.type,
        thid = builder.thid,
        pthid = builder.pthid,
        from = builder.from,
        to = builder.to,
        createdTime = builder.createdTime,
        expiresTime = builder.expiresTime,
        comment = builder.comment,
        attachments = builder.attachments,
    )

    companion object {
        fun fromMessage(msg: Message): TrustPingMessageV2 {
            requireNotNull(msg.from) { "No from" }
            val createdTime = msg.createdTime?.run { dateTimeInstant(msg.createdTime!!) }
            val expiresTime = msg.expiresTime?.run { dateTimeInstant(msg.expiresTime!!) }
            val comment = msg.body["comment"] as? String
            return Builder(msg.id, msg.type)
                .thid(msg.thid)
                .pthid(msg.pthid)
                .from(msg.from)
                .to(msg.to)
                .createdTime(createdTime)
                .expiresTime(expiresTime)
                .comment(comment)
                .attachments(msg.attachments)
                .build()
        }
    }

    fun toMessage(): Message {
        val body = LinkedHashMap<String, Any>()
        comment?.also { body["comment"] = comment }
        return MessageBuilder(id, body, type)
            .thid(thid)
            .pthid(pthid)
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
            private set

        internal var pthid: String? = null
            private set

        internal var from: String? = null
            private set

        internal var to: List<String>? = null
            private set

        internal var createdTime: OffsetDateTime? = null
            private set

        internal var expiresTime: OffsetDateTime? = null
            private set

        internal var comment: String? = null
            private set

        internal var attachments: List<Attachment>? = null
            private set

        fun thid(thid: String?) = apply { this.thid = thid }
        fun pthid(pthid: String?) = apply { this.pthid = pthid }
        fun from(from: String?) = apply { this.from = from }
        fun to(to: List<String>?) = apply { this.to = to }
        fun createdTime(createdTime: OffsetDateTime?) = apply { this.createdTime = createdTime }
        fun expiresTime(expiresTime: OffsetDateTime?) = apply { this.expiresTime = expiresTime }
        fun comment(comment: String?) = apply { this.comment = comment }
        fun attachments(attachments: List<Attachment>?) = apply { this.attachments = attachments?.toList() }


        fun build(): TrustPingMessageV2 {
            return TrustPingMessageV2(this)
        }
    }
}

