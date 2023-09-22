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
package org.nessus.didcomm.test.protocol

import io.kotest.matchers.shouldBe
import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.BasicMessageProtocolV2.Companion.BASIC_MESSAGE_TYPE_V2
import org.nessus.didcomm.service.BASIC_MESSAGE_PROTOCOL_V2
import org.nessus.didcomm.service.MessageReceiver
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.Holder

/**
 * Nessus DIDComm: Basic Message 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0095-basic-message
 */
class BasicMessageV2ProtocolTest : AbstractAgentTest() {

    @Test
    fun test_BasicMessages() {

        /** Setup a message listener */

        val messageHolder = Holder<Message>(null)
        val listener: MessageReceiver = { epm ->
            receiverService.invoke(epm).also {
                if (it.type == BASIC_MESSAGE_TYPE_V2) {
                    messageHolder.value = it
                }
            }
        }

        startNessusEndpoint(listener).use {

            /** Create the wallets */

            val faber = Wallet.Builder(Faber.name)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .build()

            try {

                val mex = MessageExchange()
                    .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
                    .createOutOfBandInvitation(faber)
                    .receiveOutOfBandInvitation(alice, inviterAlias = faber.alias)

                    .withProtocol(TRUST_PING_PROTOCOL_V2)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .getMessageExchange()

                val aliceAcme = mex.getConnection()
                aliceAcme.state shouldBe ACTIVE

                // Find the reverse connection
                val acmeAlice = faber.findConnection{ it.myVerkey == aliceAcme.theirVerkey }
                checkNotNull(acmeAlice) { "No Faber/Alice connection" }

                val aliceMessage = "Your hovercraft is full of eels"
                val acmeMessage = "I have an Elk under my Sombrero"

                /**
                 * Send a Plaintext Message
                 */

                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendPlaintextMessage(aliceMessage, aliceAcme)

                messageHolder.value!!.body["content"] shouldBe aliceMessage

                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendPlaintextMessage(acmeMessage, acmeAlice)

                messageHolder.value!!.body["content"] shouldBe acmeMessage

                /**
                 * Send a Signed Message
                 */

                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendSignedMessage(aliceMessage, aliceAcme)

                messageHolder.value!!.body["content"] shouldBe aliceMessage

                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendSignedMessage(acmeMessage, acmeAlice)

                messageHolder.value!!.body["content"] shouldBe acmeMessage

                /**
                 * Send an Encrypted Message
                 */

                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendEncryptedMessage(aliceMessage, aliceAcme)

                messageHolder.value!!.body["content"] shouldBe aliceMessage

                MessageExchange().withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendEncryptedMessage(acmeMessage, acmeAlice)

                messageHolder.value!!.body["content"] shouldBe acmeMessage

            } finally {
                removeWallet(alice)
                removeWallet(faber)
            }
        }
    }
}
