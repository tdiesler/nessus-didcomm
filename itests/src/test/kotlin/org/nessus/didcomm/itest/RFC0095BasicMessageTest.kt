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
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.service.ConnectionState
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0095_BASIC_MESSAGE
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
class RFC0095BasicMessageTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_AliceAcapy() {

        /** Create the wallets */

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        val alice = Wallet.Builder(Alice.name)
            .walletAgent(WalletAgent.ACAPY)
            .walletType(WalletType.IN_MEMORY)
            .build()

        try {

            /** Establish a peer connection */

            val peerConnection = faber.getProtocol(PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1)
                .createOutOfBandInvitation(faber)
                .dispatchTo(alice)
                .getPeerConnection()

            assertNotNull(peerConnection, "No peer connection")
            assertEquals(ConnectionState.ACTIVE, peerConnection.state)

            val userMessage = "Your hovercraft is full of eels."
            val mex = alice.getProtocol(PROTOCOL_URI_RFC0095_BASIC_MESSAGE)
                .sendMessage(alice, peerConnection.id, userMessage)

            val epm: EndpointMessage = mex.last
            assertEquals(userMessage, epm.body)
            assertEquals("https://didcomm.org/basicmessage/1.0/message", epm.contentUri)

        } finally {
            removeWallet(alice)
        }
    }
}
