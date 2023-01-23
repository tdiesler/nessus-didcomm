package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import org.hyperledger.acy_py.generated.model.SendMessage
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.toWallet
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import java.util.*

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
class RFC0095BasicMessageProtocol(mex: MessageExchange): Protocol<RFC0095BasicMessageProtocol>(mex) {

    override val protocolUri = RFC0095_BASIC_MESSAGE.uri

    companion object {
        val RFC0095_BASIC_MESSAGE_TYPE = "${RFC0095_BASIC_MESSAGE.uri}/message"
    }

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0095_BASIC_MESSAGE_TYPE -> receiveMessage(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendMessage(message: String, con: Connection? = null): RFC0095BasicMessageProtocol {

        val pcon = con ?: mex.getConnection()
        checkNotNull(pcon) { "No peer connection" }
        check(pcon.state == ConnectionState.ACTIVE) { "Connection not active: $pcon" }

        val sender = modelService.findWalletByVerkey(pcon.myDid.verkey)?.toWallet()
        checkNotNull(sender) { "No sender wallet" }

        when(sender.agentType) {
            AgentType.ACAPY -> sendMessageAcapy(sender, pcon, message)
            AgentType.NESSUS -> sendMessageNessus(sender, pcon, message)
        }

        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendMessageAcapy(sender: Wallet, pcon: Connection, message: String) {

        val fromClient = sender.walletClient() as AriesClient
        val basicMessage = SendMessage.builder().content(message).build()
        fromClient.connectionsSendMessage(pcon.id, basicMessage)

        val basicMsg = """
        {
            "@type": "$RFC0095_BASIC_MESSAGE_TYPE",
            "@id": "${UUID.randomUUID()}",
            "content": "$message",
            "sent_time": "$nowIso8601"
        }
        """.trimJson()

        MessageExchange(EndpointMessage(basicMsg))
    }

    private fun sendMessageNessus(sender: Wallet, pcon: Connection, message: String) {

        val basicMsg = """
        {
            "@type": "$RFC0095_BASIC_MESSAGE_TYPE",
            "@id": "${UUID.randomUUID()}",
            "sent_time": "$nowIso8601",
            "content": "$message"
        }
        """.trimJson()

        MessageExchange(EndpointMessage(basicMsg))

        val packedBasicMsg = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(basicMsg, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedBasicMsg, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
    }

    private fun receiveMessage(receiver: Wallet): RFC0095BasicMessageProtocol {

        val bodyJson = mex.last.bodyAsJson
        log.info { "Received basic message: ${bodyJson.prettyPrint()}" }

        return this
    }
}

