package org.nessus.didcomm.protocol

import org.hyperledger.aries.api.trustping.PingRequest
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.toWallet
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.service.RFC0048_TRUST_PING
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.toWalletModel
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingProtocol(mex: MessageExchange): Protocol<RFC0048TrustPingProtocol>(mex) {

    override val protocolUri = RFC0048_TRUST_PING.uri

    companion object {
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING = "${RFC0048_TRUST_PING.uri}/ping"
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE = "${RFC0048_TRUST_PING.uri}/ping_response"
    }

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING -> receiveTrustPing(to)
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE -> receiveTrustPingResponse(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendTrustPing(con: Connection? = null): RFC0048TrustPingProtocol {

        // Assert attached connection
        val pcon = con ?: mex.getConnection()
        checkNotNull(pcon) { "No peer connection attached" }
        check(pcon.state.ordinal >= ConnectionState.COMPLETED.ordinal) { "Unexpected connection state: $pcon" }

        // Derive the sender from the connection
        val sender = modelService.findWalletByVerkey(pcon.myDid.verkey)?.toWallet()
        checkNotNull(sender) { "No sender wallet" }

        val pingMessage = when(sender.agentType) {
            AgentType.ACAPY -> sendTrustPingAcapy(sender, pcon)
            AgentType.NESSUS -> sendTrustPingNessus(sender, pcon)
        }

        // Start a new message exchange
        val pingMex = MessageExchange(pingMessage)
        val threadId = pingMessage.thid

        // Register the response future with the message exchange
        val futureId = "${RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE}/$threadId"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        pingMex.putAttachment(futureKey, CompletableFuture<EndpointMessage>())

        // Attach the Connection
        val pconKey = AttachmentKey(Connection::class.java)
        pingMex.putAttachment(pconKey, pcon)

        val rfc0048 = pingMex.withProtocol(RFC0048_TRUST_PING)

        if (sender.agentType == AgentType.NESSUS) {

            val packedTrustPing = RFC0019EncryptionEnvelope()
                .packEncryptedEnvelope(pingMex.last.bodyAsJson, pcon.myDid, pcon.theirDid)

            val packedEpm = EndpointMessage(packedTrustPing, mapOf(
                "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
            ))
            rfc0048.dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        }

        return rfc0048
    }

    fun awaitTrustPingResponse(timeout: Int, unit: TimeUnit): RFC0048TrustPingProtocol {
        val pingThreadId = mex.last.thid as String
        val futureId = "${RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE}/$pingThreadId"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.getAttachment(futureKey)
        if (future != null) {
            log.info {"Wait on future: $futureKey"}
            future.get(timeout.toLong(), unit)
        }
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendTrustPingAcapy(sender: Wallet, pcon: Connection): EndpointMessage {

        val senderClient = sender.walletClient() as AriesClient
        val pingRequest = PingRequest.builder().comment("ping").build()
        val pingResponse = senderClient.connectionsSendPing(pcon.id, pingRequest).get()

        val threadId = "${pingResponse.threadId}"
        val trustPing = """
        {
            "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING",
            "@id": "$threadId",
            "response_requested": True
        }
        """.trimJson()

        return EndpointMessage(trustPing)
    }

    private fun sendTrustPingNessus(sender: Wallet, pcon: Connection): EndpointMessage {

        val threadId = "${UUID.randomUUID()}"
        val trustPing = """
        {
            "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING",
            "@id": "$threadId",
            "response_requested": True
        }
        """.trimJson()

        return EndpointMessage(trustPing)
    }

    @Suppress("UNCHECKED_CAST")
    private fun receiveTrustPingResponse(requester: Wallet): RFC0048TrustPingProtocol {

        val threadId = mex.last.thid as String

        // Complete the future
        val futureId = "${RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE}/$threadId"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.removeAttachment(futureKey) as? CompletableFuture<EndpointMessage>
        if (future != null) {
            log.info {"Complete future: $futureKey"}
            future.complete(mex.last)
        }

        // Set the connection state to ACTIVE
        val pcon = mex.getConnection()
        checkNotNull(pcon) { "No peer connection" }
        pcon.state = ConnectionState.ACTIVE

        return this
    }

    @Suppress("UNCHECKED_CAST")
    private fun receiveTrustPing(responder: Wallet): RFC0048TrustPingProtocol {

        val threadId = mex.last.thid as String
        val recipientVerkey = mex.last.recipientVerkey
        checkNotNull(recipientVerkey) { "No recipient verkey" }

        val pcon = responder.toWalletModel().findConnectionByVerkey(recipientVerkey)
        checkNotNull(pcon) { "No peer connection" }
        check(pcon.state.ordinal >= ConnectionState.COMPLETED.ordinal) { "Unexpected connection state: $pcon" }

        val pingResponse = """
        {
          "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE",
          "@id": "${UUID.randomUUID()}",
          "~thread": { "thid": "$threadId" },
          "~timing": { "out_time": "$nowIso8601"},
          "comment": "Hi from ${responder.name}"
        }
        """.trimJson()

        // Complete the future
        val futureId = "${RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE}/$threadId"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        val future = mex.removeAttachment(futureKey) as? CompletableFuture<EndpointMessage>
        if (future != null) {
            log.info {"Complete future: $futureKey"}
            future.complete(mex.last)
        }

        // Set the connection state to ACTIVE
        pcon.state = ConnectionState.ACTIVE

        val packedTrustPing = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(pingResponse, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedTrustPing, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }
}
