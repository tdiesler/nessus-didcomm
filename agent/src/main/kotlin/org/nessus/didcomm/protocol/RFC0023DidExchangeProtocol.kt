package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import org.hyperledger.aries.api.did_exchange.DidExchangeAcceptInvitationFilter
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.protocol.MessageExchange.Companion.MESSAGE_EXCHANGE_INVITEE_CONNECTION_ID_KEY
import org.nessus.didcomm.service.ConnectionState
import org.nessus.didcomm.service.InvitationService
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0023_DID_EXCHANGE
import org.nessus.didcomm.service.RFC0023DidDocument
import org.nessus.didcomm.util.decodeBase64Str
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent
import java.util.concurrent.TimeUnit

/**
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
class RFC0023DidExchangeProtocol(mex: MessageExchange): Protocol<RFC0023DidExchangeProtocol>(mex) {
    override val protocolUri = PROTOCOL_URI_RFC0023_DID_EXCHANGE.uri

    companion object {
        const val PROTOCOL_METHOD_ACCEPT_INVITATION = "/didexchange/accept-invitation"
        const val PROTOCOL_METHOD_RECEIVE_REQUEST = "/didexchange/receive-request"

        const val PROTOCOL_ROLE_REQUESTER = "Requester"
        const val PROTOCOL_ROLE_RESPONDER = "Responder"
    }

    override fun invokeMethod(to: Wallet, method: String): Boolean {
        when(method) {
            PROTOCOL_METHOD_ACCEPT_INVITATION -> acceptDidExchangeInvitation(to)
            PROTOCOL_METHOD_RECEIVE_REQUEST -> receiveDidExchangeRequest(to)
            else -> throw IllegalStateException("Unsupported protocol method: $method")
        }
        return true
    }

    /**
     * Accept a connection invitation
     */
    fun acceptDidExchangeInvitation(invitee: Wallet) {

        if (invitee.walletAgent == WalletAgent.ACAPY)
            return acceptInvitationAcapy(invitee)

        /*
            {
              "accept": "manual",
              "connection_id": "637ffc87-d243-48e8-9973-a1b395592737",
              "connection_protocol": "didexchange/1.0",
              "created_at": "2023-01-12T20:57:50.630574Z",
              "invitation_key": "27Mu97Csf5GcMtqWnjC56b2vJhgrZHszi41DwafP63m8",
              "invitation_mode": "once",
              "invitation_msg_id": "4dbe2000-1c26-4baa-b08a-32dc9877e867",
              "my_did": "AMBJ4YcfV9aRtFjG52uzXf",
              "request_id": "e02e53ba-3e2a-4075-9c86-6006cacc7d71",
              "rfc23_state": "request-sent",
              "routing_state": "none",
              "state": "request",
              "their_role": "inviter",
              "updated_at": "2023-01-12T20:57:50.681043Z"
            }
         */
        TODO("acceptInvitation")
    }

    fun awaitReceiveDidExchangeRequest(timeout: Int, unit: TimeUnit): RFC0023DidExchangeProtocol {

        val thid = messageExchange.messages
            .filter { it.protocolMethod == RFC0434OutOfBandProtocol.PROTOCOL_METHOD_CREATE_INVITATION }
            .map { it.threadId }
            .firstOrNull()
        checkNotNull(thid) { "Cannot find threadId for created invitation" }

        val future = messageExchange.getThreadIdFuture(thid)
        future?.get(timeout.toLong(), unit)

        return this
    }

    /**
     * Receive a connection request
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
    fun receiveDidExchangeRequest(responder: Wallet) {

        val epm = messageExchange.last
        val body = messageExchange.last.bodyAsJson

        val pthid = epm.parentThreadId
        checkNotNull(pthid) { "Must include the ID of the parent thread" }

        /**
         * Correlating requests to invitations
         *
         * An invitation is presented in one of two forms:
         *  - An explicit out-of-band invitation with its own @id.
         *  - An implicit invitation contained in a DID document's service attribute that conforms to the DIDComm conventions.
         */
        val invitationService = InvitationService.getService()
        val invitation = invitationService.getInvitation(pthid)
        checkNotNull(invitation) { "Cannot find invitation for: $pthid" }

        /**
         * Request processing
         *
         * After receiving the exchange request, the responder evaluates the provided DID and DID Doc according to the DID Method Spec.
         * The responder should check the information presented with the keys used in the wire-level message transmission to ensure they match.
         * The responder MAY look up the corresponding invitation identified in the request's ~thread.pthid to determine whether it should accept this exchange request.
         * If the responder wishes to continue the exchange, they will persist the received information in their wallet. They will then either update the provisional service information to rotate the key, or provision a new DID entirely. The choice here will depend on the nature of the DID used in the invitation.
         * The responder will then craft an exchange response using the newly updated or provisioned information.
         */

        val didDocAttach64 = body.selectJson("did_doc~attach.data.base64") as? String
        checkNotNull(didDocAttach64) {"Cannot find attached did document"}
        val didDocAttach = didDocAttach64.decodeBase64Str()
        log.info { "Attached Did Document: ${didDocAttach.prettyPrint()}" }

        val rfc0023DidDoc = gson.fromJson(didDocAttach, RFC0023DidDocument::class.java)
        check(rfc0023DidDoc.atContext == "https://w3id.org/did/v1") { "Unexpected @context: ${rfc0023DidDoc.atContext}" }

        val protected64 = body.selectJson("did_doc~attach.data.jws.protected") as? String
        val protected = protected64?.decodeBase64Str()
        log.info { "JWS protected: ${protected?.prettyPrint()}" }

        // Complete the threadId future waiting for this message
        messageExchange.completeThreadIdFuture(invitation.atId, rfc0023DidDoc)
    }


    // Private ---------------------------------------------------------------------------------------------------------

    private fun acceptInvitationAcapy(invitee: Wallet) {

        val responderConnectionId = messageExchange.getAttachment(MESSAGE_EXCHANGE_INVITEE_CONNECTION_ID_KEY)
        checkNotNull(responderConnectionId) { "No connectionId attachment"}

        val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
        acceptInvitationFilter.myEndpoint = "http://localhost:8030"
        acceptInvitationFilter.myLabel = "Accept Invitation"

        val responderClient = AriesAgent.walletClient(invitee)
        responderClient.didExchangeAcceptInvitation(responderConnectionId, acceptInvitationFilter).get()

        // Expect invitee connection in state 'active'
        messageExchange.awaitConnectionState(invitee, setOf(ConnectionState.ACTIVE))
    }
}

