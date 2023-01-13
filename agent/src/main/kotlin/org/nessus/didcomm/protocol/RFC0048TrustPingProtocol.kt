package org.nessus.didcomm.protocol

import org.hyperledger.aries.api.trustping.PingRequest
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_CONTENT_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_DIRECTION
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ALIAS
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_DID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0048_TRUST_PING
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingProtocol: Protocol() {
    override val protocolUri = PROTOCOL_URI_RFC0048_TRUST_PING.uri

    companion object {
        const val PROTOCOL_METHOD_SEND_PING = "/connections/send_ping"
    }

    /**
     * Send a basic message to a connection
     */
    fun sendPing(from: Wallet, conId: String, comment: String? = "ping"): MessageExchange {

        if (from.walletAgent == WalletAgent.ACAPY)
            return sendPingAcapy(from, conId, comment!!)

        TODO("sendPing")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendPingAcapy(from: Wallet, conId: String, comment: String): MessageExchange {

        val pcon = from.getPeerConnection(conId)
        checkNotNull(pcon) { "Unknown connection id: $conId" }

        val fromClient = AriesAgent.walletClient(from)
        val pingRequest = PingRequest.builder()
            .comment(comment)
            .build()
        val pingResponse = fromClient.connectionsSendPing(conId, pingRequest).get()
        val pingResponseJson = gson.toJson(pingResponse)
        val threadId = pingResponse.threadId

        return MessageExchange(EndpointMessage(pingResponseJson, mapOf(
            MESSAGE_DIRECTION to MessageDirection.INBOUND,
            MESSAGE_PROTOCOL_METHOD to PROTOCOL_METHOD_SEND_PING,
            MESSAGE_CONTENT_URI to "https://didcomm.org/trust_ping/1.0/ping_response",
            MESSAGE_PROTOCOL_URI to protocolUri,
            MESSAGE_THREAD_ID to threadId,
            MESSAGE_FROM_ALIAS to from.alias,
            MESSAGE_FROM_DID to pcon.myDid.qualified,
            MESSAGE_FROM_ID to from.id,
        )), threadId = threadId)
    }
}