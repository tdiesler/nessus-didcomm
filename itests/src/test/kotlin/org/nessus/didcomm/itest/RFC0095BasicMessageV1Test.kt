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
package org.nessus.didcomm.itest

import io.kotest.core.annotation.EnabledIf
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocolV1.Companion.RFC0095_BASIC_MESSAGE_TYPE_V1
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V1
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE_V1
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V1
import org.nessus.didcomm.util.selectJson
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
@EnabledIf(AcaPyOnlyCondition::class)
class RFC0095BasicMessageV1Test : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_AliceNessus() {

        /** Setup a message listener */

        val basicMessageFuture = CompletableFuture<EndpointMessage>()
        val listener: MessageListener = { epm ->
            dispatchService.invoke(epm)?.also {
                if (it.last.type == RFC0095_BASIC_MESSAGE_TYPE_V1) {
                    basicMessageFuture.complete(it.last)
                }
            }
        }

        startNessusEndpoint(NESSUS_OPTIONS_01, listener).use {

            /** Create the wallets */

            val faber = Wallet.Builder(Faber.name)
                .options(ACAPY_OPTIONS_01)
                .agentType(AgentType.ACAPY)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .options(NESSUS_OPTIONS_01)
                .agentType(AgentType.NESSUS)
                .build()

            try {

                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V1)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(RFC0023_DIDEXCHANGE_V1)
                    .connect(alice)

                    .getMessageExchange()

                val aliceFaber = mex.getConnection()
                aliceFaber.state shouldBe ACTIVE

                val aliceMessage = "Your hovercraft is full of eels"
                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V1)
                    .sendMessage(aliceMessage, aliceFaber)

                // Find the reverse connection
                val faberAlice = faber.findConnection{ it.myVerkey == aliceFaber.theirVerkey }
                checkNotNull(faberAlice) { "No Faber/Alice connection" }

                val faberMessage = "I have an Elk under my Sombrero"
                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V1)
                    .sendMessage(faberMessage, faberAlice)

                val receivedMessage = basicMessageFuture.get(5, TimeUnit.SECONDS)
                receivedMessage.bodyAsJson.selectJson("content") shouldBe faberMessage

            } finally {
                removeWallet(Alice.name)
                removeWallet(Faber.name)
            }
        }
    }

    @Test
    fun test_FaberAlice_CodeSample() {

        /** Start the Nessus endpoint */

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            /** Create the wallets */

            val faber = Wallet.Builder(Faber.name)
                .options(ACAPY_OPTIONS_01)
                .agentType(AgentType.ACAPY)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .agentType(AgentType.NESSUS)
                .build()

            try {

                /** Establish a peer connection */

                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V1)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(RFC0023_DIDEXCHANGE_V1)
                    .sendDidExchangeRequest(alice)
                    .awaitDidExchangeResponse()
                    .sendDidExchangeComplete()

                    .withProtocol(RFC0048_TRUST_PING_V1)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .getMessageExchange()

                /** Verify connection state */

                val peerConnection = mex.getConnection()
                peerConnection.state shouldBe ACTIVE

                /** Send a basic message */
                val userMessage = "Your hovercraft is full of eels."

                mex.withProtocol(RFC0095_BASIC_MESSAGE_V1)
                    .sendMessage(userMessage)

                /** Verify message exchange state */

                val epm: EndpointMessage = mex.last
                epm.type shouldBe RFC0095_BASIC_MESSAGE_TYPE_V1
                epm.bodyAsJson.selectJson("content") shouldBe userMessage

            } finally {
                removeWallet(Alice.name)
                removeWallet(Faber.name)
            }
        }
    }
}
