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

import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocolV1.Companion.RFC0095_BASIC_MESSAGE_TYPE_V1
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE_V1
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V1
import org.nessus.didcomm.util.selectJson
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
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

            val faber = getWalletByAlias(Faber.name) ?: fail("No Inviter")

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
                    .connect(alice).getMessageExchange()

                val aliceFaber = mex.getConnection()
                assertEquals(ACTIVE, aliceFaber.state)

                val aliceMessage = "Ich habe Sauerkraut in meinen Lederhosen"
                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V1)
                    .sendMessage(aliceMessage, aliceFaber)

                // Find the reverse connection
                val faberAlice = faber.findConnection{ it.myVerkey == aliceFaber.theirVerkey }
                checkNotNull(faberAlice) { "No Faber/Alice connection" }

                val faberMessage = "I have an Elk under my Sombrero"
                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V1)
                    .sendMessage(faberMessage, faberAlice)

                val receivedMessage = basicMessageFuture.get(5, TimeUnit.SECONDS)
                assertEquals(faberMessage, receivedMessage.bodyAsJson.selectJson("content"))

            } finally {
                faber.removeConnections()
                removeWallet(Alice.name)
            }
        }
    }

    @Test
    fun test_FaberAlice_CodeSample() {

        /** Start the Nessus endpoint */

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            /** Create the wallets */

            val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

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
                    .connect(alice)
                    .getMessageExchange()

                /** Verify connection state */

                val peerConnection = mex.getConnection()

                assertNotNull(peerConnection, "No peer connection")
                assertEquals(ACTIVE, peerConnection.state)

                /** Send a basic message */
                val userMessage = "Your hovercraft is full of eels."

                mex.withProtocol(RFC0095_BASIC_MESSAGE_V1)
                    .sendMessage(userMessage)

                /** Verify message exchange state */

                val epm: EndpointMessage = mex.last
                assertEquals("https://didcomm.org/basicmessage/1.0/message", epm.type)
                assertEquals(userMessage, epm.bodyAsJson.selectJson("content"))

            } finally {
                faber.removeConnections()
                removeWallet(Alice.name)
            }
        }
    }
}
