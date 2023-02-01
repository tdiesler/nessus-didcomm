/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import mu.KotlinLogging
import org.hyperledger.aries.api.trustping.PingRequest
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.toWallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.service.RFC0048_TRUST_PING
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import java.util.*

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingProtocol(mex: MessageExchange): Protocol<RFC0048TrustPingProtocol>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0048_TRUST_PING.uri

    companion object {
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING = "${RFC0048_TRUST_PING.uri}/ping"
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE = "${RFC0048_TRUST_PING.uri}/ping_response"
    }

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING -> receiveTrustPing(to)
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE -> receiveTrustPingResponse()
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendTrustPing(connection: Connection? = null): RFC0048TrustPingProtocol {

        val pcon = connection ?: mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        val sender = modelService.findWalletByVerkey(pcon.myVerkey)?.toWallet()
        checkNotNull(sender) { "No sender wallet" }

        // Use the Connection's MessageExchange
        val myMex = MessageExchange.findByVerkey(pcon.myVerkey)
        val rfc0048 = myMex.withProtocol(RFC0048_TRUST_PING)

        when (sender.agentType) {

            AgentType.ACAPY -> {

                // Register the TrustPing Response future
                myMex.placeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE, pcon.id)

                val senderClient = sender.walletClient() as AriesClient
                val pingRequest = PingRequest.builder().comment("ping").build()
                log.info { "${sender.name} sends TrustPing: ${pingRequest.prettyPrint()}" }

                val pingResponse = senderClient.connectionsSendPing(pcon.id, pingRequest).get()
                val pingResponseJson = gson.toJson(pingResponse)
                log.info { "${sender.name} received TrustPing Response: ${pingResponseJson.prettyPrint()}" }

                val responseEpm = EndpointMessage(pingResponseJson)
                myMex.addMessage(responseEpm)

                myMex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE, pcon.id, responseEpm)
            }

            AgentType.NESSUS -> {

                // Register the TrustPing Response future
                myMex.placeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE, pcon.id)

                val trustPing = """
                    {
                        "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING",
                        "@id": "${UUID.randomUUID()}",
                        "response_requested": True
                    }
                    """.trimJson()

                myMex.addMessage(EndpointMessage(trustPing))
                log.info { "${sender.name} sends TrustPing: ${trustPing.prettyPrint()}" }

                val packedTrustPing = RFC0019EncryptionEnvelope()
                    .packEncryptedEnvelope(trustPing, pcon.myDid, pcon.theirDid)

                val packedEpm = EndpointMessage(packedTrustPing, mapOf(
                    "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
                ))

                dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
            }
        }

        return rfc0048
    }

    fun awaitTrustPingResponse(): RFC0048TrustPingProtocol {
        val pcon = mex.connection
        mex.awaitEndpointMessage(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE, pcon.id)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    /**
     * Receives a Trust Ping and automatically sends the response
     */
    private fun receiveTrustPing(receiver: Wallet): RFC0048TrustPingProtocol {

        val pingId = mex.last.id
        val trustPingEpm = mex.last

        val pcon = mex.connection

        val pingResponse = """
        {
          "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE",
          "@id": "${UUID.randomUUID()}",
          "~thread": { "thid": "$pingId" },
          "~timing": { "out_time": "$nowIso8601"},
          "comment": "Hi from ${receiver.name}"
        }
        """.trimJson()

        val pingResponseEpm = EndpointMessage(pingResponse)
        mex.addMessage(pingResponseEpm)

        val packedTrustPing = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(pingResponse, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedTrustPing, mapOf(
            "Content-Type" to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)

        pcon.state = ConnectionState.ACTIVE

        if (mex.hasEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING, pcon.id))
            mex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING, pcon.id, trustPingEpm)

        return this
    }

    private fun receiveTrustPingResponse(): RFC0048TrustPingProtocol {

        val pcon = mex.connection
        pcon.state = ConnectionState.ACTIVE
        mex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE, pcon.id, mex.last)

        return this
    }
}
