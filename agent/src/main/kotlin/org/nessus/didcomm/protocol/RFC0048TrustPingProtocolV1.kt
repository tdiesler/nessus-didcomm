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
import org.hyperledger.aries.api.connection.ConnectionFilter
import org.hyperledger.aries.api.trustping.PingRequest
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_MEDIA_TYPE
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V1
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.AcapyWallet
import org.nessus.didcomm.wallet.toConnectionRole
import org.nessus.didcomm.wallet.toConnectionState
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingProtocolV1(mex: MessageExchange): Protocol<RFC0048TrustPingProtocolV1>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0048_TRUST_PING_V1.uri

    companion object {
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1 = "${RFC0048_TRUST_PING_V1.uri}/ping"
        val RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1 = "${RFC0048_TRUST_PING_V1.uri}/ping_response"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.ACAPY, AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1 -> receiveTrustPing(to)
            RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1 -> receiveTrustPingResponse()
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendTrustPing(connection: Connection? = null): RFC0048TrustPingProtocolV1 {

        val pcon = connection ?: mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        val sender = modelService.findWalletByVerkey(pcon.myVerkey)
        checkNotNull(sender) { "No sender wallet" }

        // Use the Connection's MessageExchange
        val myMex = MessageExchange.findByVerkey(pcon.myVerkey)
        val rfc0048 = myMex.withProtocol(RFC0048_TRUST_PING_V1)

        when (sender.agentType) {

            AgentType.ACAPY -> {

                // Register the TrustPing Response future
                myMex.placeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1)

                val senderClient = (sender as AcapyWallet).walletClient() as AriesClient
                val pingRequest = PingRequest.builder().comment("ping").build()
                log.info { "${sender.name} sends TrustPing: ${pingRequest.prettyPrint()}" }

                val pingResponse = senderClient.connectionsSendPing(pcon.id, pingRequest).get()
                val pingResponseJson = gson.toJson(pingResponse)
                log.info { "${sender.name} received TrustPing Response: ${pingResponseJson.prettyPrint()}" }

                val responseEpm = EndpointMessage(pingResponseJson)
                myMex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1, responseEpm)
            }

            AgentType.NESSUS -> {

                // Register the TrustPing Response future
                myMex.placeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1)

                val trustPing = """
                    {
                        "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1",
                        "@id": "${UUID.randomUUID()}",
                        "response_requested": True
                    }
                    """.trimJson()

                myMex.addMessage(EndpointMessage(trustPing))
                log.info { "${sender.name} sends TrustPing: ${trustPing.prettyPrint()}" }

                val packedTrustPing = RFC0019EncryptionEnvelope()
                    .packEncryptedEnvelope(trustPing, pcon.myDid, pcon.theirDid)

                val packedEpm = EndpointMessage(packedTrustPing, mapOf(
                    MESSAGE_HEADER_MEDIA_TYPE to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
                ))

                dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
            }
        }

        return rfc0048
    }

    fun awaitTrustPingResponse(timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): RFC0048TrustPingProtocolV1 {
        mex.awaitEndpointMessage(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1, timeout, unit)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    /**
     * Receives a Trust Ping and automatically sends the response
     */
    private fun receiveTrustPing(receiver: Wallet): RFC0048TrustPingProtocolV1 {

        val pingId = mex.last.id
        val trustPingEpm = mex.last

        val pcon = mex.getConnection()

        val pingResponse = """
        {
          "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1",
          "@id": "${UUID.randomUUID()}",
          "~thread": { "thid": "$pingId" },
          "~timing": { "out_time": "${dateTimeNow()}"},
          "comment": "Hi from ${receiver.name}"
        }
        """.trimJson()

        val pingResponseEpm = EndpointMessage(pingResponse)
        mex.addMessage(pingResponseEpm)

        val packedTrustPing = RFC0019EncryptionEnvelope()
            .packEncryptedEnvelope(pingResponse, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage(packedTrustPing, mapOf(
            MESSAGE_HEADER_MEDIA_TYPE to RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
        ))

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)

        pcon.state = ConnectionState.ACTIVE

        if (mex.hasEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1))
            mex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1, trustPingEpm)

        return this
    }

    private fun receiveTrustPingResponse(): RFC0048TrustPingProtocolV1 {

        val pcon = mex.getConnection()

        fixupTheirConnection(pcon.invitationKey)

        pcon.state = ConnectionState.ACTIVE
        mex.completeEndpointMessageFuture(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1, mex.last)

        return this
    }

    private fun fixupTheirConnection(invitationKey: String) {

        val theirMex = MessageExchange.findByInvitationKey(invitationKey).firstOrNull { it != mex }
        val theirWallet = theirMex?.getAttachment(MessageExchange.WALLET_ATTACHMENT_KEY)

        if (theirWallet?.agentType == AgentType.ACAPY) {
            val walletClient = (theirWallet as AcapyWallet).walletClient() as AriesClient
            val filter = ConnectionFilter.builder().invitationKey(invitationKey).build()
            val conRecord = walletClient.connections(filter).get().firstOrNull()
            checkNotNull(conRecord) { "No connection for invitationKey: $invitationKey" }

            val myCon = mex.getConnection()

            val theirDid = myCon.theirDid
            val theirCon = theirMex.getAttachment(CONNECTION_ATTACHMENT_KEY) ?: run {

                // Create and attach the Connection
                val pcon = Connection(
                    id = conRecord.connectionId,
                    agent = theirWallet.agentType,
                    invitationKey = invitationKey,
                    myDid = theirDid,
                    myRole = myCon.theirRole,
                    myLabel = myCon.theirLabel as String,
                    myEndpointUrl = myCon.theirEndpointUrl as String,
                    theirDid = myCon.myDid,
                    theirRole = conRecord.theirRole.toConnectionRole(),
                    theirLabel = myCon.myLabel,
                    theirEndpointUrl = myCon.myEndpointUrl,
                    state = conRecord.state.toConnectionState()
                )

                theirWallet.addConnection(pcon)
                theirMex.setConnection(pcon)
                pcon
            }

            check(theirCon.agent == AgentType.ACAPY) { "Unexpected connection agent" }
            check(theirCon.id == conRecord.connectionId) { "Unexpected connection id" }
            check(theirDid.id == conRecord.myDid) { "Unexpected connection did" }

            theirCon.myDid = theirDid
            theirCon.myRole = myCon.theirRole
            theirCon.myLabel = myCon.theirLabel as String
            theirCon.myEndpointUrl = myCon.theirEndpointUrl as String
            theirCon.theirDid = myCon.myDid
            theirCon.theirRole = conRecord.theirRole.toConnectionRole()
            theirCon.theirLabel = myCon.myLabel
            theirCon.theirEndpointUrl = myCon.myEndpointUrl
            theirCon.state = conRecord.state.toConnectionState()

            // Register theirDid
            registerTheirDid(theirWallet, theirDid)
        }
    }

    private fun registerTheirDid(theirWallet: AcapyWallet, theirDid: Did) {

        if (!theirWallet.hasDid(theirDid.verkey))
            theirWallet.addDid(theirDid)

        if (keyStore.getKeyId(theirDid.verkey) == null)
            didService.registerWithKeyStore(theirDid)
    }
}
