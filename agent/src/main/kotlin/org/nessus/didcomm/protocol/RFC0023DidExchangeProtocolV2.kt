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
import org.didcommx.didcomm.protocols.routing.PROFILE_DIDCOMM_V2
import org.nessus.didcomm.did.DidDoc
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_MEDIA_TYPE
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_THID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_TYPE
import org.nessus.didcomm.protocol.MessageExchange.Companion.REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.RESPONDER_DID_DOCUMENT_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocolV2.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2
import org.nessus.didcomm.service.DID_DOCUMENT_MEDIA_TYPE
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V2
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V2
import org.nessus.didcomm.util.encodeJson
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * Nessus DIDComm RFC0023: DID Exchange Protocol 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0023-did-exchange
 */
class RFC0023DidExchangeProtocolV2(mex: MessageExchange): Protocol<RFC0023DidExchangeProtocolV2>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0023_DIDEXCHANGE_V2.uri

    companion object {
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2 = "${RFC0023_DIDEXCHANGE_V2.uri}/request"
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2 = "${RFC0023_DIDEXCHANGE_V2.uri}/response"
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V2 = "${RFC0023_DIDEXCHANGE_V2.uri}/complete"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.ACAPY, AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2 -> receiveDidExchangeRequest(to)
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2 -> receiveDidExchangeResponse(to)
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V2 -> receiveDidExchangeComplete(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun connect(invitee: Wallet? = null, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): RFC0023DidExchangeProtocolV2 {

        val requester = invitee ?: mex.getAttachment(WALLET_ATTACHMENT_KEY)
        checkNotNull(requester) { "No requester wallet" }

        val attachedInvitation = mex.getInvitation()
        val invitationKey = attachedInvitation?.invitationKey()
        checkNotNull(invitationKey) { "No invitation" }

        val invitation = requester.findInvitation { it.invitationKey() == invitationKey }
        checkNotNull(invitation) { "Requester has no such invitation" }

        val invitationV2 = invitation.actV2

        // sendDidExchangeRequest
        // awaitDidExchangeResponse
        // sendDidExchangeComplete
        // sendTrustPing
        // awaitTrustPingResponse

        sendDidExchangeRequest(requester)

        awaitDidExchangeResponse()

        sendDidExchangeComplete()

        mex.withProtocol(RFC0048_TRUST_PING_V2)
            .sendTrustPing()
            .awaitTrustPingResponse(timeout, unit)

        return this
    }

    fun sendDidExchangeRequest(requester: Wallet): RFC0023DidExchangeProtocolV2 {
        check(requester.agentType == AgentType.NESSUS) { "Requester must be Nessus" }

        val attachedInvitation = mex.getInvitation()
        val invitationKey = attachedInvitation?.invitationKey()
        checkNotNull(invitationKey) { "No invitation" }

        val invitation = requester.findInvitation { it.invitationKey() == invitationKey }
        checkNotNull(invitation) { "Requester has no such invitation" }

        // Register the response future with the message exchange
        mex.placeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2)

        val pcon = mex.getConnection()
        val recipientDid = invitation.recipientDidKey()
        val recipientServiceEndpoint = invitation.recipientServiceEndpoint()

        // Create the Requester Did & Document
        val requesterDid = pcon.myDid
        val requesterEndpointUrl = requester.endpointUrl
        val requesterDidDoc = diddocV2Service.createDidDocument(requesterDid, requesterEndpointUrl)
        log.info { "Requester (${requester.name}) creates Did Document: ${requesterDidDoc.encodeJson(true)}" }

        mex.putAttachment(REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(requesterDidDoc))

        val didDocAttach = diddocV2Service.createDidDocAttachment(requesterDidDoc)

        val didexReqId = "${UUID.randomUUID()}"
        val didexRequest = DidExchangeMessageV2.Builder(
                id = didexReqId,
                type = RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2,
                thid = didexReqId,
                pthid = invitation.id)
            .from(requesterDid.qualified)
            .to(listOf(recipientDid.qualified))
            .accept(listOf(PROFILE_DIDCOMM_V2))
            .attachments(listOf(didDocAttach))
            .build()

        val requestMsg = didexRequest.toMessage()
        mex.addMessage(EndpointMessage(requestMsg)).last
        log.info { "Requester (${requester.name}) creates DidEx Request: ${requestMsg.encodeJson(true)}" }

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(requestMsg, recipientDid.qualified)
                .signFrom(requesterDid.qualified)
                .from(requesterDid.qualified)
                .build()
        )
        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            MESSAGE_HEADER_ID to "${requestMsg.id}.packed",
            MESSAGE_HEADER_THID to requestMsg.thid,
            MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
            MESSAGE_HEADER_MEDIA_TYPE to Typ.Encrypted.typ
        ))
        log.info { "Requester (${requester.name}) sends DidEx Request: ${packedEpm.prettyPrint()}" }

        pcon.myRole = ConnectionRole.REQUESTER
        pcon.state = ConnectionState.REQUEST

        dispatchToEndpoint(recipientServiceEndpoint, packedEpm)
        return this
    }

    fun awaitDidExchangeResponse(): RFC0023DidExchangeProtocolV2 {
        mex.awaitEndpointMessage(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2)
        return this
    }

    private fun receiveDidExchangeRequest(responder: Wallet): Wallet {

        log.info { "Responder (${responder.name}) received DidEx Request" }

        val didexRequestEpm = mex.last
        val didexRequestMsg = mex.last.body as Message
        didexRequestEpm.checkMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2)

        val invitationId = mex.last.pthid
        val senderVerkey = didexRequestEpm.senderVerkey
        checkNotNull(senderVerkey) { "No sender verification key" }
        checkNotNull(invitationId) { "Must include the ID of the parent thread" }

        /**
         * Correlating requests to invitations
         *
         * An invitation is presented in one of two forms:
         *  - An explicit out-of-band invitation with its own @id.
         *  - An implicit invitation contained in a DID document's service attribute that conforms to the DIDComm conventions.
         */

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "Cannot find invitation for: $invitationId" }
        check(invitationId == invitation.id) { "Unexpected invitation id" }

        /**
         * Request processing
         *
         * After receiving the exchange request, the responder evaluates the provided DID and DID Doc according to the DID Method Spec.
         * The responder should check the information presented with the keys used in the wire-level message transmission to ensure they match.
         * The responder MAY look up the corresponding invitation identified in the request's ~thread.pthid to determine whether it should accept this exchange request.
         * If the responder wishes to continue the exchange, they will persist the received information in their wallet. They will then either update the provisional service information to rotate the key, or provision a new DID entirely. The choice here will depend on the nature of the DID used in the invitation.
         * The responder will then craft an exchange response using the newly updated or provisioned information.
         */

        val didexRequest = DidExchangeMessageV2.fromMessage(didexRequestMsg)
        val didDocAttachment = didexRequest.attachments?.firstOrNull { it.mediaType == DID_DOCUMENT_MEDIA_TYPE }
        checkNotNull(didDocAttachment) {"Cannot find attached did document"}

        val requesterDidDoc = diddocV2Service.extractDidDocAttachment(didDocAttachment)
        val docdidVerkey = requesterDidDoc.toDid().verkey
        check(senderVerkey == docdidVerkey) { "Did in Document does not match with senderVerkey: $senderVerkey != $docdidVerkey" }
        mex.putAttachment(REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(requesterDidDoc))

        val theirDid = requesterDidDoc.toDid()
        val theirEndpointUrl = requesterDidDoc.serviceEndpoint()
        // val theirLabel = body.selectJson("label")

        // Update the connection with their info
        val pcon = mex.getConnection()
        pcon.myRole = ConnectionRole.RESPONDER
        pcon.theirDid = theirDid
        pcon.theirRole = ConnectionRole.REQUESTER
        // pcon.theirLabel = theirLabel
        pcon.theirEndpointUrl = theirEndpointUrl
        pcon.state = ConnectionState.REQUEST

        // Register the complete future with the message exchange
        mex.placeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V2)

        if (mex.hasEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2))
            mex.completeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2, mex.last)

        sendDidExchangeResponse(responder)
        return responder
    }

    private fun sendDidExchangeResponse(responder: Wallet) {

        val didexThid = mex.last.thid
        mex.checkLastMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2)

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }

        val requesterDidDoc = mex.getAttachment(REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY)?.actV2
        checkNotNull(requesterDidDoc) { "No requester Did Document" }

        val requesterDid = requesterDidDoc.toDid()
        val requesterEndpointUrl = requesterDidDoc.serviceEndpoint()

        // Create the Responder Did & Document
        val responderEndpointUrl = responder.endpointUrl
        val responderDid = responder.createDid(DidMethod.KEY)
        val responderDidDoc = diddocV2Service.createDidDocument(responderDid, responderEndpointUrl)
        log.info { "Responder (${responder.name}) creates Did Document: ${responderDidDoc.encodeJson(true)}" }

        mex.putAttachment(RESPONDER_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(responderDidDoc))

        val didDocAttach = diddocV2Service.createDidDocAttachment(responderDidDoc)

        val didexResponse = DidExchangeMessageV2.Builder(
                id = "${UUID.randomUUID()}",
                type = RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2,
                thid = didexThid,
                pthid = invitation.id)
            .from(responderDid.qualified)
            .to(listOf(requesterDid.qualified))
            .accept(listOf(PROFILE_DIDCOMM_V2))
            .attachments(listOf(didDocAttach))
            .build()

        val responseMsg = didexResponse.toMessage()
        mex.addMessage(EndpointMessage(responseMsg)).last
        log.info { "Responder (${responder.name}) creates DidEx Response: ${responseMsg.encodeJson(true)}" }

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(responseMsg, requesterDid.qualified)
                .signFrom(responderDid.qualified)
                .from(responderDid.qualified)
                .build()
        )
        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            MESSAGE_HEADER_ID to "${responseMsg.id}.packed",
            MESSAGE_HEADER_THID to responseMsg.thid,
            MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
            MESSAGE_HEADER_MEDIA_TYPE to Typ.Encrypted.typ
        ))
        log.info { "Responder (${responder.name}) sends DidEx Response: ${packedEpm.prettyPrint()}" }

        val pcon = mex.getConnection()
        pcon.myDid = responderDid
        pcon.state = ConnectionState.RESPONSE

        log.info { "Responder (${responder.name}) Connection: ${pcon.prettyPrint()}" }

        dispatchToEndpoint(requesterEndpointUrl, packedEpm)
    }

    private fun receiveDidExchangeResponse(requester: Wallet): Wallet {

        log.info { "Requester (${requester.name}) received DidEx Response" }

        val didexResponseEpm = mex.last
        val didexResponseMsg = mex.last.body as Message
        didexResponseEpm.checkMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2)

        val invitationId = mex.last.pthid
        val senderVerkey = didexResponseEpm.senderVerkey
        checkNotNull(senderVerkey) { "No sender verification key" }
        checkNotNull(invitationId) { "Must include the ID of the parent thread" }

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation attached" }

        // Extract the Responder DIDDocument
        val didexResponse = DidExchangeMessageV2.fromMessage(didexResponseMsg)
        val didDocAttachment = didexResponse.attachments?.firstOrNull { it.mediaType == DID_DOCUMENT_MEDIA_TYPE }
        checkNotNull(didDocAttachment) { "No Did Document attachment" }

        val responderDidDoc = diddocV2Service.extractDidDocAttachment(didDocAttachment)
        val docdidVerkey = responderDidDoc.toDid().verkey
        check(invitationId == invitation.id) { "Unexpected invitation id" }
        check(senderVerkey == docdidVerkey) { "Did in Document does not match with senderVerkey: $senderVerkey != $docdidVerkey" }

        // Update the Connection with their information
        val theirDid = responderDidDoc.toDid()
        val theirEndpointUrl = responderDidDoc.serviceEndpoint()
        // val theirLabel = "${responderDidDoc.service[0].type} for ${requester.name}"

        val pcon = mex.getConnection()
        pcon.theirDid = theirDid
        pcon.theirLabel = null
        pcon.theirRole = ConnectionRole.RESPONDER
        pcon.theirEndpointUrl = theirEndpointUrl
        pcon.state = ConnectionState.RESPONSE

        log.info { "Requester (${requester.name}) Connection: ${pcon.prettyPrint()}" }

        mex.completeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2, mex.last)
        return requester
    }

    fun sendDidExchangeComplete(): RFC0023DidExchangeProtocolV2 {

        val requester = mex.getAttachment(WALLET_ATTACHMENT_KEY) as Wallet
        check(requester.agentType == AgentType.NESSUS) { "Requester must be Nessus" }

        val didexResponse = mex.last
        mex.checkLastMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V2)

        val pcon = mex.getConnection()
        val requesterDid = pcon.myDid
        val responderDid = pcon.theirDid
        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }

        val didexThid = didexResponse.thid
        val didexComplete = DidExchangeMessageV2.Builder(
                id = "${UUID.randomUUID()}",
                type = RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V2,
                thid = didexThid,
                pthid = invitation.id)
            .from(pcon.myDid.qualified)
            .to(listOf(pcon.theirDid.qualified))
            .build()

        val completeMsg = didexComplete.toMessage()
        mex.addMessage(EndpointMessage(completeMsg)).last
        log.info { "Requester (${requester.name}) creates DidEx Complete: ${completeMsg.encodeJson(true)}" }

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(completeMsg, responderDid.qualified)
                .signFrom(requesterDid.qualified)
                .from(requesterDid.qualified)
                .build()
        )
        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            MESSAGE_HEADER_ID to "${completeMsg.id}.packed",
            MESSAGE_HEADER_THID to completeMsg.thid,
            MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
            MESSAGE_HEADER_MEDIA_TYPE to Typ.Encrypted.typ
        ))
        log.info { "Requester (${requester.name}) sends DidEx Complete: ${packedEpm.prettyPrint()}" }

        pcon.state = ConnectionState.COMPLETED

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }

    private fun receiveDidExchangeComplete(responder: Wallet): Wallet {

        val invitationId = mex.last.pthid as String

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }
        check(invitationId == invitation.id) { "Unexpected invitation id" }

        val pcon = mex.getConnection()
        check(pcon.invitationKey == invitation.invitationKey()) { "Unexpected invitation key" }

        pcon.state = ConnectionState.COMPLETED

        mex.placeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V2)
        mex.completeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V2, mex.last)

        return responder
    }

    // Private ---------------------------------------------------------------------------------------------------------
}

class DidExchangeMessageV2(
    val id: String,
    val type: String,
    val thid: String,
    val pthid: String,
    val from: String?,
    val to: List<String>?,
    val accept: List<String>?,
    var attachments: List<Attachment>?,
) {
    internal constructor(builder: Builder): this(
        id = builder.id,
        type = builder.type,
        thid = builder.thid,
        pthid = builder.pthid,
        from = builder.from,
        to = builder.to,
        accept = builder.accept,
        attachments = builder.attachments,
    )

    @Suppress("UNCHECKED_CAST")
    companion object {
        fun fromMessage(msg: Message): DidExchangeMessageV2 {
            requireNotNull(msg.from) { "No from" }
            return Builder(msg.id, msg.type, msg.thid!!, msg.pthid!!)
                .from(msg.from)
                .to(msg.to)
                .accept(msg.body["accept"] as? List<String>)
                .attachments(msg.attachments)
                .build()
        }
    }

    fun toMessage(): Message {
        val body = LinkedHashMap<String, Any>()
        accept?.also { body["accept"] = accept }
        return MessageBuilder(id, body, type)
            .thid(thid)
            .pthid(pthid)
            .from(from)
            .to(to)
            .attachments(attachments)
            .build()
    }

    class Builder(
        val id: String,
        val type: String,
        val thid: String,
        val pthid: String) {

        internal var from: String? = null
            private set

        internal var to: List<String>? = null
            private set

        internal var accept: List<String>? = null
            private set

        internal var attachments: List<Attachment>? = null
            private set

        fun from(from: String?) = apply { this.from = from }
        fun to(to: List<String>?) = apply { this.to = to }
        fun accept(accept: List<String>?) = apply { this.accept = accept?.toList() }
        fun attachments(attachments: List<Attachment>?) = apply { this.attachments = attachments?.toList() }

        fun build(): DidExchangeMessageV2 {
            return DidExchangeMessageV2(this)
        }
    }
}

