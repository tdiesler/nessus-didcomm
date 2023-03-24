/*-
 * #%L
 * Nessus DIDComm :: ITests
 * %%
 * Copyright (C) 2022 Nessus
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
package org.nessus.didcomm.itest.protocol

import io.kotest.core.annotation.EnabledIf
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.itest.ACAPY_OPTIONS
import org.nessus.didcomm.itest.AbstractIntegrationTest
import org.nessus.didcomm.itest.AcaPyOnlyCondition
import org.nessus.didcomm.itest.Alice
import org.nessus.didcomm.itest.Faber
import org.nessus.didcomm.itest.NESSUS_OPTIONS
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.BasicMessageV1Protocol.Companion.BASIC_MESSAGE_TYPE_V1
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.service.BASIC_MESSAGE_PROTOCOL_V1
import org.nessus.didcomm.service.DIDEXCHANGE_PROTOCOL_V1
import org.nessus.didcomm.service.MessageDispatcher
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V1
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V1
import org.nessus.didcomm.util.selectJson
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
@EnabledIf(AcaPyOnlyCondition::class)
class BasicMessageV1IntegrationTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_AliceNessus() {

        /** Setup a message listener */

        val basicMessageFuture = CompletableFuture<EndpointMessage>()
        val listener: MessageDispatcher = { epm ->
            dispatchService.invoke(epm)?.also {
                if (it.last.type == BASIC_MESSAGE_TYPE_V1) {
                    basicMessageFuture.complete(it.last)
                }
            }
        }

        startNessusEndpoint(NESSUS_OPTIONS, listener).use {

            /** Create the wallets */

            val faber = Wallet.Builder(Faber.name)
                .options(ACAPY_OPTIONS)
                .agentType(AgentType.ACAPY)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .options(NESSUS_OPTIONS)
                .agentType(AgentType.NESSUS)
                .build()

            try {

                val mex = MessageExchange()
                    .withProtocol(OUT_OF_BAND_PROTOCOL_V1)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(DIDEXCHANGE_PROTOCOL_V1)
                    .connect(alice)

                    .getMessageExchange()

                val aliceFaber = mex.getConnection()
                aliceFaber.state shouldBe ACTIVE

                val aliceMessage = "Your hovercraft is full of eels"
                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V1)
                    .sendMessage(aliceMessage, aliceFaber)

                // Find the reverse connection
                val faberAlice = faber.findConnection{ it.myVerkey == aliceFaber.theirVerkey }
                checkNotNull(faberAlice) { "No Faber/Alice connection" }

                val faberMessage = "I have an Elk under my Sombrero"
                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V1)
                    .sendMessage(faberMessage, faberAlice)

                val receivedMessage = basicMessageFuture.get(5, TimeUnit.SECONDS)
                receivedMessage.bodyAsJson.selectJson("content") shouldBe faberMessage

            } finally {
                removeWallet(alice)
                removeWallet(faber)
            }
        }
    }

    @Test
    fun test_FaberAlice_CodeSample() {

        /** Start the Nessus endpoint */

        startNessusEndpoint(NESSUS_OPTIONS).use {

            /** Create the wallets */

            val faber = Wallet.Builder(Faber.name)
                .options(ACAPY_OPTIONS)
                .agentType(AgentType.ACAPY)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .agentType(AgentType.NESSUS)
                .build()

            try {

                /** Establish a peer connection */

                val mex = MessageExchange()
                    .withProtocol(OUT_OF_BAND_PROTOCOL_V1)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(DIDEXCHANGE_PROTOCOL_V1)
                    .sendDidExchangeRequest(alice)
                    .awaitDidExchangeResponse()
                    .sendDidExchangeComplete()

                    .withProtocol(TRUST_PING_PROTOCOL_V1)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .getMessageExchange()

                /** Verify connection state */

                val peerConnection = mex.getConnection()
                peerConnection.state shouldBe ACTIVE

                /** Send a basic message */
                val userMessage = "Your hovercraft is full of eels."

                mex.withProtocol(BASIC_MESSAGE_PROTOCOL_V1)
                    .sendMessage(userMessage)

                /** Verify message exchange state */

                val epm: EndpointMessage = mex.last
                epm.type shouldBe BASIC_MESSAGE_TYPE_V1
                epm.bodyAsJson.selectJson("content") shouldBe userMessage

            } finally {
                removeWallet(alice)
                removeWallet(faber)
            }
        }
    }
}
