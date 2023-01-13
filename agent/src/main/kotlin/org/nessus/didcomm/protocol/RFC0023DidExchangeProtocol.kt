package org.nessus.didcomm.protocol

import org.hyperledger.aries.api.did_exchange.DidExchangeAcceptInvitationFilter
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_CONTENT_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_DIRECTION
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ALIAS
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.protocol.MessageExchange.Companion.MESSAGE_EXCHANGE_CONNECTION_ID_KEY
import org.nessus.didcomm.service.ConnectionState
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0023_DID_EXCHANGE
import org.nessus.didcomm.service.PeerConnection
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent

/**
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
class RFC0023DidExchangeProtocol: Protocol() {
    override val protocolUri = PROTOCOL_URI_RFC0023_DID_EXCHANGE.uri

    companion object {
        const val PROTOCOL_METHOD_ACCEPT_INVITATION = "/didexchange/accept-invitation"
    }

    override fun sendTo(to: Wallet, mex: MessageExchange): Boolean {
        checkProtocol(mex)
        when(val protocolMethod = mex.last.protocolMethod) {
            PROTOCOL_METHOD_ACCEPT_INVITATION -> acceptInvitation(to, mex)
            else -> throw IllegalStateException("Unsupported protocol method: $protocolMethod")
        }
        return true
    }

    /**
     * Accept a connection invitation
     */
    fun acceptInvitation(invitee: Wallet, mex: MessageExchange) {

        if (invitee.walletAgent == WalletAgent.ACAPY)
            return acceptInvitationAcapy(invitee, mex)

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

    fun awaitConnectionRecord(invitee: Wallet, mex: MessageExchange, state: ConnectionState) {

        val connectionRecord = AriesAgent.awaitConnectionRecord(invitee) {
            it.invitationMsgId == mex.threadId && it.state.name == state.name
        }
        checkNotNull(connectionRecord) {"${invitee.alias} has no connection record in state 'active'"}
        log.info {"${invitee.alias} connection: ${connectionRecord.state}"}
        log.info("${invitee.alias}: {}", prettyGson.toJson(connectionRecord))

        val peerConnection = PeerConnection.fromAcapyRecord(connectionRecord)
        mex.putAttachment(MessageExchange.MESSAGE_EXCHANGE_PEER_CONNECTION_KEY, peerConnection)
        invitee.addPeerConnection(peerConnection)

        mex.addMessage(EndpointMessage(connectionRecord, mapOf(
            MESSAGE_DIRECTION to MessageDirection.INBOUND,
            MESSAGE_PROTOCOL_URI to protocolUri,
            MESSAGE_THREAD_ID to mex.threadId,
            MESSAGE_FROM_ID to invitee.id,
            MESSAGE_FROM_ALIAS to invitee.alias,
            MESSAGE_CONTENT_URI to connectionRecord.connectionProtocol,
        )))
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun acceptInvitationAcapy(invitee: Wallet, mex: MessageExchange) {

        val inviteeConnectionId = mex.getAttachment(MESSAGE_EXCHANGE_CONNECTION_ID_KEY)
        checkNotNull(inviteeConnectionId) { "No connectionId attachment"}

        val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
        acceptInvitationFilter.myEndpoint = "http://localhost:8030"
        acceptInvitationFilter.myLabel = "Accept Invitation"

        val inviteeClient = AriesAgent.walletClient(invitee)
        inviteeClient.didExchangeAcceptInvitation(inviteeConnectionId, acceptInvitationFilter).get()

        // Expect invitee connection in state 'active'
        awaitConnectionRecord(invitee, mex, ConnectionState.ACTIVE)
    }
}