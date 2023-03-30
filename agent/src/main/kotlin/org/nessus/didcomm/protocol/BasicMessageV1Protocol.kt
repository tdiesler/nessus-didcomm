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
import org.hyperledger.acy_py.generated.model.SendMessage
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.model.AcapyWallet
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EncryptionEnvelopeV1.Companion.ENCRYPTED_ENVELOPE_V1_MEDIA_TYPE
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_MEDIA_TYPE
import org.nessus.didcomm.service.BASIC_MESSAGE_PROTOCOL_V1
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.trimJson
import java.util.UUID

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
class BasicMessageV1Protocol(mex: MessageExchange): Protocol<BasicMessageV1Protocol>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = BASIC_MESSAGE_PROTOCOL_V1.uri

    companion object {
        val BASIC_MESSAGE_TYPE_V1 = "${BASIC_MESSAGE_PROTOCOL_V1.uri}/message"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.ACAPY, AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            BASIC_MESSAGE_TYPE_V1 -> receiveMessage()
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendMessage(message: String, connection: Connection? = null): BasicMessageV1Protocol {

        val pcon = connection ?: mex.getAttachment(MessageExchange.CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        check(pcon.state == ConnectionState.ACTIVE) { "Connection not active: $pcon" }

        val sender = modelService.findWalletByVerkey(pcon.myDid.verkey)
        checkNotNull(sender) { "No sender wallet" }

        val rfc0095 = when(sender.agentType) {
            AgentType.ACAPY -> sendMessageAcapy(sender, pcon, message)
            AgentType.NESSUS -> sendMessageNessus(sender, pcon, message)
        }

        return rfc0095
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun sendMessageAcapy(sender: Wallet, pcon: Connection, message: String): BasicMessageV1Protocol {

        // Use my previous MessageExchange
        val myMex = MessageExchange.findByVerkey(pcon.myVerkey)
        checkNotNull(myMex) { "No message exchange for: ${pcon.myVerkey}" }

        val protocol = myMex.withProtocol(BASIC_MESSAGE_PROTOCOL_V1)

        val fromClient = (sender as AcapyWallet).walletClient() as AriesClient
        val basicMessage = SendMessage.builder().content(message).build()
        fromClient.connectionsSendMessage(pcon.id, basicMessage)

        val basicMsg = """
        {
            "@type": "$BASIC_MESSAGE_TYPE_V1",
            "@id": "${UUID.randomUUID()}",
            "content": "$message",
            "sent_time": "${dateTimeNow()}"
        }
        """.trimJson()

        myMex.addMessage(EndpointMessage.Builder(basicMsg).outbound().build())

        return protocol
    }

    @Suppress("UNUSED_PARAMETER")
    private fun sendMessageNessus(sender: Wallet, pcon: Connection, message: String): BasicMessageV1Protocol {

        // Use my previous MessageExchange
        val myMex = MessageExchange.findByVerkey(pcon.myVerkey)
        checkNotNull(myMex) { "No message exchange for: ${pcon.myVerkey}" }

        val protocol = myMex.withProtocol(BASIC_MESSAGE_PROTOCOL_V1)

        val basicMsg = """
        {
            "@type": "$BASIC_MESSAGE_TYPE_V1",
            "@id": "${UUID.randomUUID()}",
            "sent_time": "${dateTimeNow()}",
            "content": "$message"
        }
        """.trimJson()

        myMex.addMessage(EndpointMessage.Builder(basicMsg).outbound().build())

        val packedBasicMsg = EncryptionEnvelopeV1()
            .packEncryptedEnvelope(basicMsg, pcon.myDid, pcon.theirDid)

        val packedEpm = EndpointMessage.Builder(packedBasicMsg, mapOf(
            MESSAGE_HEADER_MEDIA_TYPE to ENCRYPTED_ENVELOPE_V1_MEDIA_TYPE
        )).outbound().build()

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)

        return protocol
    }

    private fun receiveMessage(): BasicMessageV1Protocol {

        val bodyJson = mex.last.bodyAsJson
        log.info { "Received basic message: ${bodyJson.prettyPrint()}" }

        return this
    }
}

