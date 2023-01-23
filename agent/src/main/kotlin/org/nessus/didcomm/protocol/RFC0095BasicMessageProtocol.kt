package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.toWallet
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.*
import java.util.concurrent.CompletableFuture

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
class RFC0095BasicMessageProtocol(mex: MessageExchange):
    Protocol<RFC0095BasicMessageProtocol>(mex) {
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

    fun sendMessage(message: String): RFC0095BasicMessageProtocol {

        val pcon = mex.getConnection()
        checkNotNull(pcon) { "No peer connection" }
        check(pcon.state == ConnectionState.ACTIVE) { "Connection not active: $pcon" }

        val basicMessage = buildBasicSendMessage(pcon.id, message)

        val packedPingRequest = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(basicMessage.bodyAsJson, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedPingRequest, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        // Start a new thread
        return dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
    }

    @Suppress("UNCHECKED_CAST")
    fun receiveMessage(receiver: Wallet): RFC0095BasicMessageProtocol {

        val bodyJson = mex.last.bodyAsJson
        log.info { "Received basic message: ${bodyJson.prettyPrint()}" }

        val futureKey = AttachmentKey(RFC0095_BASIC_MESSAGE_TYPE, CompletableFuture::class.java)
        val future = mex.removeAttachment(futureKey) as? CompletableFuture<EndpointMessage>
        if (future != null) {
            log.info {"Complete future: $futureKey"}
            future.complete(mex.last)
        }

        return this
    }

    /**
     * Send a basic message to a connection
     */
    fun buildBasicSendMessage(conId: String, message: String): EndpointMessage {

        val pcon: Connection? = modelService.getConnection(conId)
        checkNotNull(pcon) { "No peer connection" }
        check(pcon.state == ConnectionState.ACTIVE) { "Connection not active: $pcon" }

        val sender = modelService.findWalletByVerkey(pcon.myDid.verkey)?.toWallet()
        checkNotNull(sender) { "No sender wallet" }

        return if (sender.agentType == AgentType.ACAPY)
            sendMessageAcapy(sender, pcon, message)
        else
            sendMessageNessus(sender, pcon, message)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendMessageAcapy(sender: Wallet, pcon: Connection, message: String): EndpointMessage {

//        val pcon = sender.getConnection(conId)
//        checkNotNull(pcon) { "Unknown connection id: $conId" }
//
//        val fromClient = sender.walletClient() as AriesClient
//        val basicMessage = SendMessage.builder().content(message).build()
//        fromClient.connectionsSendMessage(conId, basicMessage)

        return EndpointMessage("""
            { "acapy-command": "/connections/{conn_id}/send-message"}
        """.trimJson())
    }

    private fun sendMessageNessus(sender: Wallet, pcon: Connection, message: String): EndpointMessage {

        val nowIso8601 = OffsetDateTime.now(ZoneOffset.UTC)

        val basicMsg = """
        {
            "@type": "$RFC0095_BASIC_MESSAGE_TYPE",
            "@id": "${UUID.randomUUID()}",
            "content": "$message",
            "sent_time": "$nowIso8601"
        }
        """.trimJson()
        return EndpointMessage(basicMsg)
    }
}

