package org.nessus.didcomm.protocol

import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_TYPE
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
class RFC0095BasicMessageProtocol(): Protocol() {
    override val protocolUri = RFC0095_BASIC_MESSAGE.uri

    companion object {
        const val RFC0095_BASIC_MESSAGE_METHOD_SEND_MESSAGE = "/connections/send_message"
    }

    /**
     * Send a basic message to a connection
     */
    fun sendMessage(sender: Wallet, conId: String, message: String) {

        if (sender.agentType == AgentType.ACAPY)
            return sendMessageAcapy(sender, conId, message)

        TODO("sendMessage")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendMessageAcapy(sender: Wallet, conId: String, message: String) {

//        val pcon = sender.getConnection(conId)
//        checkNotNull(pcon) { "Unknown connection id: $conId" }
//
//        val fromClient = sender.walletClient() as AriesClient
//        val basicMessage = SendMessage.builder().content(message).build()
//        fromClient.connectionsSendMessage(conId, basicMessage)
    }
}

class RFC0095BasicMessageProtocolWrapper(mex: MessageExchange):
    ProtocolWrapper<RFC0095BasicMessageProtocolWrapper, RFC0095BasicMessageProtocol>(RFC0095BasicMessageProtocol(), mex) {

    fun sendMessage(sender: Wallet, conId: String, message: String): RFC0095BasicMessageProtocolWrapper {
        protocol.sendMessage(sender, conId, message)
        mex.addMessage(EndpointMessage(
            message, mapOf(
                MESSAGE_THID to mex.last.thid,
                MESSAGE_TYPE to "https://didcomm.org/basicmessage/1.0/message",
                MESSAGE_PROTOCOL_URI to protocol.protocolUri,
            )
        ))
        return this
    }
}

