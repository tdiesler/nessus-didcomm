package org.nessus.didcomm.protocol

import org.hyperledger.acy_py.generated.model.SendMessage
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_CONTENT_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_DIRECTION
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ALIAS
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_DID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0095_BASIC_MESSAGE
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
class RFC0095BasicMessageProtocol(mex: MessageExchange): Protocol<RFC0095BasicMessageProtocol>(mex) {
    override val protocolUri = PROTOCOL_URI_RFC0095_BASIC_MESSAGE.uri

    companion object {
        const val PROTOCOL_METHOD_SEND_MESSAGE = "/connections/send_message"
    }

    /**
     * Send a basic message to a connection
     */
    fun sendMessage(sender: Wallet, conId: String, message: String): MessageExchange {

        if (sender.walletAgent == WalletAgent.ACAPY)
            return sendMessageAcapy(sender, conId, message)

        TODO("sendMessage")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendMessageAcapy(sender: Wallet, conId: String, message: String): MessageExchange {

        val pcon = sender.getPeerConnection(conId)
        checkNotNull(pcon) { "Unknown connection id: $conId" }

        val fromClient = AriesAgent.walletClient(sender)
        val basicMessage = SendMessage.builder().content(message).build()
        fromClient.connectionsSendMessage(conId, basicMessage)

        messageExchange.addMessage(EndpointMessage(
            message, mapOf(
                MESSAGE_THREAD_ID to messageExchange.last.threadId,
                MESSAGE_DIRECTION to MessageDirection.OUTBOUND,
                MESSAGE_PROTOCOL_METHOD to PROTOCOL_METHOD_SEND_MESSAGE,
                MESSAGE_CONTENT_URI to "https://didcomm.org/basicmessage/1.0/message",
                MESSAGE_PROTOCOL_URI to protocolUri,
                MESSAGE_FROM_ALIAS to sender.alias,
                MESSAGE_FROM_DID to pcon.myDid.qualified,
                MESSAGE_FROM_ID to sender.id,
            )
        ))
        return messageExchange
    }
}