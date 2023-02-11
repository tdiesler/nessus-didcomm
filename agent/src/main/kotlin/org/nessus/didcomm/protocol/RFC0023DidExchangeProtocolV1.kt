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
import org.nessus.didcomm.did.DidDoc
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.RESPONDER_DID_DOCUMENT_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocolV1.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V1
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.trimJson
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
class RFC0023DidExchangeProtocolV1(mex: MessageExchange): Protocol<RFC0023DidExchangeProtocolV1>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0023_DIDEXCHANGE_V1.uri

    companion object {
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1 = "${RFC0023_DIDEXCHANGE_V1.uri}/request"
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1 = "${RFC0023_DIDEXCHANGE_V1.uri}/response"
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V1 = "${RFC0023_DIDEXCHANGE_V1.uri}/complete"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.ACAPY, AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1 -> receiveDidExchangeRequest(to)
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1 -> receiveDidExchangeResponse(to)
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V1 -> receiveDidExchangeComplete(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun connect(requester: Wallet, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): RFC0023DidExchangeProtocolV1 {

        val attachedInvitation = mex.getInvitation()
        val invitationKey = attachedInvitation?.invitationKey()
        checkNotNull(invitationKey) { "No invitation" }

        val invitation = requester.findInvitation { it.invitationKey() == invitationKey }
        checkNotNull(invitation) { "Requester has no such invitation" }

        sendDidExchangeRequest(requester)

        awaitDidExchangeResponse()

        sendDidExchangeComplete()

        mex.withProtocol(RFC0048_TRUST_PING_V1)
            .sendTrustPing()
            .awaitTrustPingResponse(timeout, unit)

        return this
    }

    fun sendDidExchangeRequest(requester: Wallet): RFC0023DidExchangeProtocolV1 {
        check(requester.agentType == AgentType.NESSUS) { "Requester must be Nessus" }

        val attachedInvitation = mex.getInvitation()
        val invitationKey = attachedInvitation?.invitationKey()
        checkNotNull(invitationKey) { "No invitation" }

        val invitation = requester.findInvitation { it.invitationKey() == invitationKey }
        checkNotNull(invitation) { "Requester has no such invitation" }

        // Register the response future with the message exchange
        mex.placeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1)

        val pcon = mex.getConnection()
        val recipientDidKey = invitation.recipientDidKey()
        val recipientServiceEndpoint = invitation.recipientServiceEndpoint()

        // Create the Requester Did & Document
        val requesterEndpointUrl = requester.endpointUrl
        val requesterDidDoc = diddocV1Service.createDidDocument(pcon.myDid, requesterEndpointUrl)
        log.info { "Requester (${requester.name}) created Did Document: ${requesterDidDoc.encodeJson(true)}" }

        mex.putAttachment(REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(requesterDidDoc))

        val didexReqId = "${UUID.randomUUID()}"
        val didDocAttach = diddocV1Service.createDidDocAttachmentMap(requesterDidDoc, pcon.myDid)

        val didexRequest = """
                {
                    "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1",
                    "@id": "$didexReqId",
                    "~thread": {
                        "thid": "$didexReqId",
                        "pthid": "${invitation.id}"
                    },
                    "did": "${pcon.myDid.id}",
                    "label": "Invitee ${requester.name}",
                    "did_doc~attach": ${didDocAttach.encodeJson()}
                }
                """.trimJson()

        mex.addMessage(EndpointMessage(didexRequest))
        log.info { "Requester (${requester.name}) sends DidEx Request: ${didexRequest.prettyPrint()}" }

        val packedDidExRequest = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(didexRequest, pcon.myDid, recipientDidKey)

        val packedEpm = EndpointMessage(packedDidExRequest, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        pcon.myRole = ConnectionRole.REQUESTER
        pcon.state = ConnectionState.REQUEST

        dispatchToEndpoint(recipientServiceEndpoint, packedEpm)
        return this
    }

    fun awaitDidExchangeResponse(timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): RFC0023DidExchangeProtocolV1 {
        mex.awaitEndpointMessage(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1, timeout, unit)
        return this
    }

    fun sendDidExchangeComplete(): RFC0023DidExchangeProtocolV1 {

        val requester = mex.getAttachment(WALLET_ATTACHMENT_KEY) as Wallet
        check(requester.agentType == AgentType.NESSUS) { "Requester must be Nessus" }

        val didexResponse = mex.last
        mex.checkLastMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1)

        val pcon = mex.getConnection()
        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }

        val didexThid = didexResponse.thid
        val didexComplete = """
                {
                    "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V1",
                    "@id": "${UUID.randomUUID()}",
                    "~thread": {
                        "thid": "$didexThid",
                        "pthid": "${invitation.id}"
                    }
                }
                """.trimJson()
        mex.addMessage(EndpointMessage(didexComplete))
        log.info { "Requester (${requester.name}) sends DidEx Complete: ${didexComplete.prettyPrint()}" }

        val packedDidExComplete = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(didexComplete, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedDidExComplete, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)

        pcon.state = ConnectionState.COMPLETED
        return this
    }

    private fun receiveDidExchangeRequest(responder: Wallet): Wallet {

        log.info { "Responder (${responder.name}) received DidEx Request" }

        val didexRequest = mex.last
        didexRequest.checkMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1)

        val invitationId = mex.last.pthid
        val senderVerkey = didexRequest.senderVerkey
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

        val body = mex.last.bodyAsJson
        val didDocAttachment = body.selectJson("did_doc~attach")
        checkNotNull(didDocAttachment) {"Cannot find attached did document"}

        val (requesterDidDoc, _) = diddocV1Service.extractDidDocAttachment(didDocAttachment, null)
        val docdidVerkey = requesterDidDoc.publicKeyDid().verkey
        check(senderVerkey == docdidVerkey) { "Did in Document does not match with senderVerkey: $senderVerkey != $docdidVerkey" }
        mex.putAttachment(REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(requesterDidDoc))

        val theirDid = requesterDidDoc.publicKeyDid(0)
        val theirEndpointUrl = requesterDidDoc.serviceEndpoint(0)
        val theirLabel = body.selectJson("label")

        // Update the connection with their info
        val pcon = mex.getConnection()
        pcon.myRole = ConnectionRole.RESPONDER
        pcon.theirDid = theirDid
        pcon.theirRole = ConnectionRole.REQUESTER
        pcon.theirLabel = theirLabel
        pcon.theirEndpointUrl = theirEndpointUrl
        pcon.state = ConnectionState.REQUEST

        // Register the complete future with the message exchange
        mex.placeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V1)

        if (mex.hasEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1))
            mex.completeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1, mex.last)

        sendDidExchangeResponse(responder)

        return responder
    }

    private fun sendDidExchangeResponse(responder: Wallet) {

        val didexThid = mex.last.thid
        mex.checkLastMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1)

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }

        val requesterDidDoc = mex.getAttachment(REQUESTER_DID_DOCUMENT_ATTACHMENT_KEY)
        checkNotNull(requesterDidDoc) { "No requester Did Document" }

        val theirEndpointUrl = requesterDidDoc.serviceEndpoint()
        val recipientDidKey = invitation.recipientDidKey()

        // Create the Responder Did & Document
        val responderEndpointUrl = responder.endpointUrl
        val responderDid = responder.createDid(DidMethod.SOV)
        val responderDidDoc = diddocV1Service.createDidDocument(responderDid, responderEndpointUrl)
        log.info { "Responder (${responder.name}) created Did Document: ${responderDidDoc.encodeJson(true)}" }

        mex.putAttachment(RESPONDER_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(responderDidDoc))

        val didDocAttach = diddocV1Service.createDidDocAttachmentMap(responderDidDoc, recipientDidKey)

        val didexResponse = """
        {
            "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1",
            "@id": "${UUID.randomUUID()}",
            "~thread": {
                "thid": "$didexThid",
                "pthid": "${invitation.id}"
            },
            "did_doc~attach": ${didDocAttach.encodeJson()},
            "did": "${responderDid.id}"
        }
        """.trimJson()
        mex.addMessage(EndpointMessage(didexResponse))
        log.info { "Responder (${responder.name}) sends DidEx Response: ${didexResponse.prettyPrint()}" }

        val pcon = mex.getConnection()
        pcon.myDid = responderDid
        pcon.state = ConnectionState.RESPONSE

        log.info { "Responder (${responder.name}) Connection: ${pcon.prettyPrint()}" }

        val packedDidExResponse = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(didexResponse, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedDidExResponse, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(theirEndpointUrl, packedEpm)
    }

    private fun receiveDidExchangeResponse(requester: Wallet): Wallet {

        log.info { "Requester (${requester.name}) received DidEx Response" }

        val didexResponse = mex.last
        didexResponse.checkMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1)

        val invitationId = mex.last.pthid
        val senderVerkey = didexResponse.senderVerkey
        checkNotNull(senderVerkey) { "No sender verification key" }
        checkNotNull(invitationId) { "Must include the ID of the parent thread" }

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation attached" }
        val invitationDid = invitation.recipientDidKey()
        val invitationKey = invitation.invitationKey()

        // Extract the Responder DIDDocument
        val body = mex.last.bodyAsJson
        val didDocAttachment = body.selectJson("did_doc~attach")
        checkNotNull(didDocAttachment) { "No Did Document attachment" }
        val (responderDidDoc, signatoryDid) = diddocV1Service.extractDidDocAttachment(didDocAttachment, invitationKey)
        val docdidVerkey = responderDidDoc.publicKeyDid().verkey
        check(invitationId == invitation.id) { "Unexpected invitation id" }
        check(signatoryDid == invitationDid) { "Signatory Did does not match Invitation Did" }
        check(senderVerkey == docdidVerkey) { "Did in Document does not match with senderVerkey: $senderVerkey != $docdidVerkey" }

        // Update the Connection with their information
        val theirDid = responderDidDoc.publicKeyDid()
        val theirEndpointUrl = responderDidDoc.serviceEndpoint()
        val theirLabel = "${responderDidDoc.service[0].type} for ${requester.name}"

        val pcon = mex.getConnection()
        pcon.theirDid = theirDid
        pcon.theirLabel = theirLabel
        pcon.theirRole = ConnectionRole.RESPONDER
        pcon.theirEndpointUrl = theirEndpointUrl
        pcon.state = ConnectionState.RESPONSE

        log.info { "Requester (${requester.name}) Connection: ${pcon.prettyPrint()}" }

        mex.completeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE_V1, mex.last)

        return requester
    }

    private fun receiveDidExchangeComplete(responder: Wallet): Wallet {

        val invitationId = mex.last.pthid as String

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }
        check(invitationId == invitation.id) { "Unexpected invitation id" }

        val pcon = mex.getConnection()
        check(pcon.invitationKey == invitation.invitationKey()) { "Unexpected invitation key" }

        pcon.state = ConnectionState.COMPLETED

        mex.placeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1)
        mex.completeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V1, mex.last)

        return responder
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun awaitDidExchangeRequest(): EndpointMessage {
        return mex.awaitEndpointMessage(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1)
    }

    private fun awaitDidExchangeComplete(): EndpointMessage {
        return mex.awaitEndpointMessage(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE_V1)
    }

    private fun awaitTrustPing(timeout: Int, unit: TimeUnit): EndpointMessage {
        return mex.awaitEndpointMessage(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1, timeout, unit)
    }
}

