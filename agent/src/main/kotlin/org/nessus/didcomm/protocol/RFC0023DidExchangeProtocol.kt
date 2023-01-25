package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import mu.KotlinLogging
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionRole.REQUESTER
import org.nessus.didcomm.model.ConnectionRole.RESPONDER
import org.nessus.didcomm.model.ConnectionState.COMPLETED
import org.nessus.didcomm.model.ConnectionState.REQUEST
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITEE_WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITER_WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.REQUESTER_DIDDOC_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.RESPONDER_DIDDOC_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.toWalletModel
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
class RFC0023DidExchangeProtocol(mex: MessageExchange): Protocol<RFC0023DidExchangeProtocol>(mex) {

    override val protocolUri = RFC0023_DIDEXCHANGE.uri
    override val log = KotlinLogging.logger {}

    companion object {
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST = "${RFC0023_DIDEXCHANGE.uri}/request"
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE = "${RFC0023_DIDEXCHANGE.uri}/response"
        val RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE = "${RFC0023_DIDEXCHANGE.uri}/complete"
    }

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST -> receiveDidExchangeRequest(to)
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE -> receiveDidExchangeResponse(to)
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE -> receiveDidExchangeComplete(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun awaitDidExchangeRequest(timeout: Int, unit: TimeUnit): RFC0023DidExchangeProtocol {
        val invitation = mex.getAttachment(INVITATION_ATTACHMENT_KEY)
        checkNotNull(invitation) { "No attached invitation" }
        val futureId = "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST?invId=${invitation.id}"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.getAttachment(futureKey)
        if (future != null) {
            log.info {"Wait on future: ${futureKey.name}"}
            future.get(timeout.toLong(), unit)
        } else {
            log.info {"Future not found: ${futureKey.name}"}
        }
        return this
    }

    fun awaitDidExchangeResponse(timeout: Int, unit: TimeUnit): RFC0023DidExchangeProtocol {
        val didexThid = mex.last.thid as String
        val futureId = "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE?thid=$didexThid"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.getAttachment(futureKey)
        if (future != null) {
            log.info {"Wait on future: ${futureKey.name}"}
            future.get(timeout.toLong(), unit)
        } else {
            log.info {"Future not found: ${futureKey.name}"}
        }
        return this
    }

    fun awaitDidExchangeComplete(timeout: Int, unit: TimeUnit): RFC0023DidExchangeProtocol {
        val didexThid = mex.last.thid as String
        val futureId = "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE?thid=$didexThid"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.getAttachment(futureKey)
        if (future != null) {
            log.info {"Wait on future: ${futureKey.name}"}
            future.get(timeout.toLong(), unit)
        } else {
            log.info {"Future not found: ${futureKey.name}"}
        }
        return this
    }

    fun sendDidExchangeRequest(): RFC0023DidExchangeProtocol {

        val requester = mex.getAttachment(INVITEE_WALLET_ATTACHMENT_KEY)
        checkNotNull(requester)  { "No requester attachment" }

        val invId = mex.last.thid as String
        val invitation = requester.getInvitation(invId)
        checkNotNull(invitation) { "No invitation with id: $invId" }

        when(requester.agentType) {

            AgentType.ACAPY -> {
                sendDidExchangeRequestAcapy(requester, invitation)
            }

            AgentType.NESSUS -> {
                sendDidExchangeRequestNessus(requester, invitation)
            }
        }

        return this
    }

    fun sendDidExchangeResponse(): RFC0023DidExchangeProtocol {

        val didexThid = mex.last.thid as String
        check(mex.last.messageType == RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST) { "Unexpected last message: ${mex.last}" }

        val requester = mex.getAttachment(INVITEE_WALLET_ATTACHMENT_KEY)
        checkNotNull(requester) { "No responder wallet" }

        val responder = mex.getAttachment(INVITER_WALLET_ATTACHMENT_KEY)
        checkNotNull(responder) { "No responder wallet" }

        val invitation = mex.getAttachment(INVITATION_ATTACHMENT_KEY)
        checkNotNull(invitation) { "No invitation" }

        val requesterDidDoc = mex.getAttachment(REQUESTER_DIDDOC_ATTACHMENT_KEY)
        checkNotNull(requesterDidDoc) { "No requester Did Document" }

        val theirDid = requesterDidDoc.publicKeyDid(0)
        val theirEndpointUrl = requesterDidDoc.serviceEndpoint(0)
        val recipientDidKey = invitation.recipientDidKey()

        // Create the Responder Did & Document
        val responderDid = responder.createDid(DidMethod.SOV)
        val responderDidDoc = diddocService.createDidDocument(responderDid, responder.endpointUrl)
        log.info { "Responder Did Document: ${responderDidDoc.prettyPrint()}" }

        val responderDidDocAttach = diddocService.createAttachment(responderDidDoc, recipientDidKey)

        val didexResId = "${UUID.randomUUID()}"
        val didexResponse = """
        {
            "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE",
            "@id": "$didexResId",
            "~thread": {
                "thid": "$didexThid",
                "pthid": "${invitation.id}"
            },
            "did_doc~attach": $responderDidDocAttach,
            "did": "${responderDid.id}"
        }
        """.trimJson()
        mex.addMessage(EndpointMessage(didexResponse))
        log.info { "DidExchange Response: ${didexResponse.prettyPrint()}" }

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = responder.agentType,
            myDid = responderDid,
            theirDid = theirDid,
            theirLabel = "${responder.name}/${requester.name}",
            theirRole = REQUESTER,
            theirEndpointUrl = theirEndpointUrl,
            invitationKey = invitation.invitationKey(),
            state = REQUEST
        )

        mex.putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
        responder.toWalletModel().addConnection(pcon)
        log.info { "Connection: ${pcon.prettyPrint()}" }

        // Register the response future with the message exchange
        val futureId = "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE?thid=$didexThid"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        mex.putAttachment(futureKey, CompletableFuture<EndpointMessage>())
        log.info("Placed future: ${futureKey.name}")

        val packedDidExResponse = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(didexResponse, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedDidExResponse, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(theirEndpointUrl, packedEpm)
        return this
    }

    fun sendDidExchangeComplete(): RFC0023DidExchangeProtocol {

        val didexRequestId = mex.last.thid as String
        mex.expectedLastMessageType(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE)

        val requester = mex.getAttachment(INVITEE_WALLET_ATTACHMENT_KEY)
        checkNotNull(requester)  { "No requester attachment" }
        check(requester.agentType == AgentType.NESSUS) { "Send DidExchange Complete not supported for: ${requester.agentType} " }

        val pcon = mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No peer connection" }

        val invitationId = mex.last.pthid as String
        val invitation = requester.getInvitation(invitationId)
        checkNotNull(invitation) { "No invitation with id: $invitationId" }

        val didexComplete = """
        {
            "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE",
            "@id": "${UUID.randomUUID()}",
            "~thread": {
                "thid": "$didexRequestId",
                "pthid": "$invitationId"
            }
        }
        """.trimJson()
        log.info { "DidEx Complete: ${didexComplete.prettyPrint()}" }

        val packedDidExComplete = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(didexComplete, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedDidExComplete, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        val inviterServiceEndpoint = invitation.recipientServiceEndpoint()
        dispatchToEndpoint(inviterServiceEndpoint, packedEpm)

        pcon.state = COMPLETED

        return this
    }

    /**
     * Receive a DidExchange Request
     * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange#1-exchange-request
     *
     * - The @type attribute is a required string value that denotes that the received message is an exchange request
     * - The ~thread decorator MUST be included:
     *      - It MUST include the ID of the parent thread (pthid) such that the request can be correlated to the corresponding (implicit or explicit) invitation.
     *      - It MAY include the thid property. If thid is not defined it is implicitly defined as @id.
     * - The label attribute provides a suggested label for the DID being exchanged.
     * - The goal_code (optional) is a self-attested code the receiver may want to display to the user or use in automatically deciding what to do with the request message.
     * - The goal (optional) is a self-attested string that the receiver may want to display to the user about the context-specific goal of the request message.
     * - The did attribute MUST be included. It indicates the DID being exchanged.
     * - The did_doc~attach (optional), contains the DIDDoc associated with the did, if required.
     *      - If the did is resolvable (either an inline peer:did or a publicly resolvable DID), the did_doc~attach attribute should not be included.
     *      - If the DID is a did:peer DID, the DIDDoc must be as outlined in RFC 0627 Static Peer DIDs.
     */
    @Suppress("UNCHECKED_CAST")
    fun receiveDidExchangeRequest(responder: Wallet): RFC0023DidExchangeProtocol {

        val invitationId = mex.last.pthid
        checkNotNull(invitationId) { "Must include the ID of the parent thread" }

        val invitee = mex.getAttachment(INVITEE_WALLET_ATTACHMENT_KEY)?.toWalletModel()
        checkNotNull(invitee) { "No invitee wallet " }

        /**
         * Correlating requests to invitations
         *
         * An invitation is presented in one of two forms:
         *  - An explicit out-of-band invitation with its own @id.
         *  - An implicit invitation contained in a DID document's service attribute that conforms to the DIDComm conventions.
         */

        val invitation = mex.getAttachment(INVITATION_ATTACHMENT_KEY)
        val invitationDid = invitation?.recipientDidKey()
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

        val (requesterDidDoc, signatoryDid) = diddocService.extractFromAttachment(didDocAttachment)
        mex.putAttachment(REQUESTER_DIDDOC_ATTACHMENT_KEY, requesterDidDoc)

        // Register theirDid
        val theirDid = requesterDidDoc.publicKeyDid()
        if (!invitee.hasDid(theirDid.verkey))
            invitee.addDid(theirDid)

        if (keyStore.getKeyId(theirDid.verkey) == null)
            didService.registerWithKeyStore(theirDid)

        val futureId = "${RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST}?invId=${invitation.id}"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.removeAttachment(futureKey) as? CompletableFuture<EndpointMessage>
        if (future != null) {
            log.info {"Complete future: ${futureKey.name}"}
            future.complete(mex.last)
        } else {
            log.info {"Future not found: ${futureKey.name}"}
        }
        return this
    }

    @Suppress("UNCHECKED_CAST")
    fun receiveDidExchangeResponse(requester: Wallet): RFC0023DidExchangeProtocol {

        val didexThid = mex.last.thid as String
        val invitationId = mex.last.pthid as String
        val didexResponse = mex.last.bodyAsJson

        val responder = mex.getAttachment(INVITER_WALLET_ATTACHMENT_KEY)?.toWalletModel()
        val requesterDidDoc = mex.getAttachment(REQUESTER_DIDDOC_ATTACHMENT_KEY)
        checkNotNull(requesterDidDoc) { "No requester DidDocument" }
        checkNotNull(responder) { "No inviter wallet" }

        // Extract the Responder DIDDocument
        val didDocAttachment = didexResponse.selectJson("did_doc~attach")
        checkNotNull(didDocAttachment) { "No Did Document attachment" }
        val (responderDidDoc, signatoryDid) = diddocService.extractFromAttachment(didDocAttachment)
        mex.putAttachment(RESPONDER_DIDDOC_ATTACHMENT_KEY, responderDidDoc)

        val invitation = mex.getAttachment(INVITATION_ATTACHMENT_KEY)
        val invitationDid = invitation?.recipientDidKey()
        checkNotNull(invitation) { "No invitation attached" }
        check(invitationId == invitation.id) { "Unexpected invitation id" }
        check(signatoryDid == invitationDid) { "Signatory Did does not match Invitation Did" }

        // Create and attach the Connection
        val requesterDid = requesterDidDoc.publicKeyDid()
        val responderDid = responderDidDoc.publicKeyDid()
        val theirEndpointUrl = responderDidDoc.serviceEndpoint()

        // Register theirDid
        if (responderDid != invitationDid) {
            didService.registerWithKeyStore(responderDid)
            responder.addDid(responderDid)
        }

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = requester.agentType,
            myDid = requesterDid,
            theirDid = responderDid,
            theirLabel = "${responder.name}/${requester.name}",
            theirRole = RESPONDER,
            theirEndpointUrl = theirEndpointUrl,
            invitationKey = invitation.invitationKey(),
            state = REQUEST
        )

        mex.putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
        requester.toWalletModel().addConnection(pcon)
        log.info { "Connection: ${pcon.prettyPrint()}" }

        val futureId = "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE?thid=$didexThid"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.removeAttachment(futureKey) as? CompletableFuture<EndpointMessage>
        if (future != null) {
            log.info {"Complete future: ${futureKey.name}"}
            future.complete(mex.last)
        } else {
            log.info {"Future not found: ${futureKey.name}"}
        }
        return this
    }

    @Suppress("UNCHECKED_CAST")
    fun receiveDidExchangeComplete(responder: Wallet): RFC0023DidExchangeProtocol {

        val didexThid = mex.last.thid as String
        val invitationId = mex.last.pthid as String

        val invitation = mex.getAttachment(INVITATION_ATTACHMENT_KEY)
        checkNotNull(invitation) { "No invitation" }
        check(invitationId == invitation.id) { "Unexpected invitation id" }

        val pcon = mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }
        check(pcon.invitationKey == invitation.invitationKey()) { "Unexpected invitation key" }

        pcon.state = COMPLETED

        run {
            val futureId = "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE?thid=$didexThid"
            val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
            val future = mex.removeAttachment(futureKey) as? CompletableFuture<EndpointMessage>
            if (future != null) {
                log.info {"Complete future: ${futureKey.name}"}
                future.complete(mex.last)
            } else {
                log.info {"Future not found: ${futureKey.name}"}
            }
        }

        run {
            val futureId = "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING?wid=${responder.id}"
            val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
            RFC0048TrustPingProtocol.putAttachment(futureKey, CompletableFuture<EndpointMessage>())
            log.info("Placed future: ${futureKey.name}")
        }

        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendDidExchangeRequestAcapy(requester: Wallet, invitation: Invitation): EndpointMessage {
        // We expect AcaPy to auto-accept an invitation (for now)
        TODO("DidExchange Send Request not supported for AcaPy")
    }

    private fun sendDidExchangeRequestNessus(requester: Wallet, invitation: Invitation): EndpointMessage {

        val recipientDidKey = invitation.recipientDidKey()
        val theirServiceEndpoint = invitation.recipientServiceEndpoint()

        // Create the Requester Did & Document
        val myEndpointUrl = requester.endpointUrl
        val myDid = requester.createDid(DidMethod.SOV)
        val requesterDidDoc = diddocService.createDidDocument(myDid, myEndpointUrl)
        mex.putAttachment(REQUESTER_DIDDOC_ATTACHMENT_KEY, requesterDidDoc)
        log.info { "Requester Did Document: ${requesterDidDoc.prettyPrint()}" }

        val requesterDidDocAttach = diddocService.createAttachment(requesterDidDoc, myDid)

        val didexReqId = "${UUID.randomUUID()}"
        val didexRequest = """
        {
            "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST",
            "@id": "$didexReqId",
            "~thread": {
                "thid": "$didexReqId",
                "pthid": "${invitation.id}"
            },
            "label": "Accept Faber/Alice",
            "did": "${myDid.id}",
            "did_doc~attach": $requesterDidDocAttach
        }
        """.trimJson()
        mex.addMessage(EndpointMessage(didexRequest))
        log.info { "DidExchange Request: ${didexRequest.prettyPrint()}" }

        // Register the response future with the message exchange
        val futureId = "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE?thid=$didexReqId"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        mex.putAttachment(futureKey, CompletableFuture<EndpointMessage>())
        log.info("Placed future: ${futureKey.name}")

        val packedDidExRequest = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(didexRequest, myDid, recipientDidKey)

        val packedEpm = EndpointMessage(packedDidExRequest, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(theirServiceEndpoint, packedEpm)
        return EndpointMessage(didexRequest)
    }
}

