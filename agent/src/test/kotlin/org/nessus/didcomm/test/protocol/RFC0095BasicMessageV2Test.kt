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

import org.didcommx.didcomm.message.Message
import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocolV2.Companion.RFC0095_BASIC_MESSAGE_TYPE_V2
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V2
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE_V2
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Acme
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.NESSUS_OPTIONS_01
import org.nessus.didcomm.util.Holder
import kotlin.test.assertEquals

/**
 * Nessus DIDComm RFC0095: Basic Message 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0095-basic-message
 */
class RFC0095BasicMessageV2Test : AbstractDidCommTest() {

    @Test
    fun test_BasicMessages() {

        /** Setup a message listener */

        val messageHolder = Holder<Message>(null)
        val listener: MessageListener = { epm ->
            dispatchService.invoke(epm)?.also {
                if (it.last.type == RFC0095_BASIC_MESSAGE_TYPE_V2) {
                    messageHolder.content = it.last.body as Message
                }
            }
        }

        startNessusEndpoint(NESSUS_OPTIONS_01, listener).use {

            /** Create the wallets */

            val acme = Wallet.Builder(Acme.name)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .build()

            try {

                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V2)
                    .createOutOfBandInvitation(acme)
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(RFC0023_DIDEXCHANGE_V2)
                    .connect(alice)

                    .getMessageExchange()

                val aliceFaber = mex.getConnection()
                assertEquals(ACTIVE, aliceFaber.state)

                // Find the reverse connection
                val faberAlice = acme.findConnection{ it.myVerkey == aliceFaber.theirVerkey }
                checkNotNull(faberAlice) { "No Faber/Alice connection" }

                val aliceMessage = "Your hovercraft is full of eels"
                val faberMessage = "I have an Elk under my Sombrero"

                /**
                 * Send a Plaintext Message
                 */

                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V2)
                    .sendPlaintextMessage(aliceMessage, aliceFaber)

                assertEquals(aliceMessage, messageHolder.content!!.body["content"])

                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V2)
                    .sendPlaintextMessage(faberMessage, faberAlice)

                assertEquals(faberMessage, messageHolder.content!!.body["content"])

                /**
                 * Send a Signed Message
                 */

                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V2)
                    .sendSignedMessage(aliceMessage, aliceFaber)

                assertEquals(aliceMessage, messageHolder.content!!.body["content"])

                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V2)
                    .sendSignedMessage(faberMessage, faberAlice)

                assertEquals(faberMessage, messageHolder.content!!.body["content"])

                /**
                 * Send an Encrypted Message
                 */

                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V2)
                    .sendEncryptedMessage(aliceMessage, aliceFaber)

                assertEquals(aliceMessage, messageHolder.content!!.body["content"])

                MessageExchange().withProtocol(RFC0095_BASIC_MESSAGE_V2)
                    .sendEncryptedMessage(faberMessage, faberAlice)

                assertEquals(faberMessage, messageHolder.content!!.body["content"])

            } finally {
                removeWallet(Alice.name)
                removeWallet(Acme.name)
            }
        }
    }
}
