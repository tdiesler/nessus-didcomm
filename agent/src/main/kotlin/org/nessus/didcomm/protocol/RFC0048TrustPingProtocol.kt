package org.nessus.didcomm.protocol

import org.hyperledger.aries.api.trustping.PingRequest
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_CONTENT_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_DIRECTION
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ALIAS
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol.Companion.PROTOCOL_METHOD_SEND_PING
import org.nessus.didcomm.service.RFC0048_TRUST_PING
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingProtocol(): Protocol() {
    override val protocolUri = RFC0048_TRUST_PING.uri

    companion object {
        const val PROTOCOL_METHOD_SEND_PING = "/connections/send_ping"

        val MESSAGE_TYPE_RFC0048_TRUST_PING = "${RFC0048_TRUST_PING.uri}/ping"
        val MESSAGE_TYPE_RFC0048_TRUST_PING_RESPONSE = "${RFC0048_TRUST_PING.uri}/ping_response"
    }

    /**
     * Send a basic message to a connection
     */
    fun sendPing(sender: Wallet, conId: String, comment: String? = "ping"): String {

        if (sender.agentType == AgentType.ACAPY)
            return sendPingAcapy(sender, conId, comment!!)

        TODO("sendPing")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendPingAcapy(sender: Wallet, conId: String, comment: String): String {

        val pcon = sender.getConnection(conId)
        checkNotNull(pcon) { "Unknown connection id: $conId" }

        val senderClient = sender.walletClient() as AriesClient
        val pingRequest = PingRequest.builder()
            .comment(comment)
            .build()
        val pingResponse = senderClient.connectionsSendPing(conId, pingRequest).get()
        return gson.toJson(pingResponse)
    }
}

class RFC0048TrustPingProtocolWrapper(mex: MessageExchange):
    ProtocolWrapper<RFC0048TrustPingProtocolWrapper, RFC0048TrustPingProtocol>(RFC0048TrustPingProtocol(), mex) {

    fun sendPing(sender: Wallet, conId: String, comment: String? = "ping"): RFC0048TrustPingProtocolWrapper {
        val pingResponse = protocol.sendPing(sender, conId, comment)
        val threadId = pingResponse.selectJson("threadId") as String
        mex.addMessage(EndpointMessage(
            pingResponse, mapOf(
                MESSAGE_THREAD_ID to threadId,
                MESSAGE_DIRECTION to MessageDirection.INBOUND,
                MESSAGE_PROTOCOL_METHOD to PROTOCOL_METHOD_SEND_PING,
                MESSAGE_CONTENT_URI to "https://didcomm.org/trust_ping/1.0/ping_response",
                MESSAGE_PROTOCOL_URI to protocol.protocolUri,
                MESSAGE_FROM_ALIAS to sender.alias,
                MESSAGE_FROM_ID to sender.id,
            )
        ))
        return this
    }
}
