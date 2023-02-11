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
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V1
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V1
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.fail

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_AliceNessus() {

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            /** Create the wallets */

            val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

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
                assertEquals(AgentType.NESSUS, aliceFaber.agent)

                // Send an explicit trust ping
                MessageExchange()
                    .withProtocol(RFC0048_TRUST_PING_V1)
                    .sendTrustPing(aliceFaber)
                    .awaitTrustPingResponse()

                // Send a reverse trust ping
                val faberAlice = faber.findConnection{ it.myVerkey == aliceFaber.theirVerkey }
                assertNotNull(faberAlice, "No Faber/Alice Connection")
                assertEquals(AgentType.ACAPY, faberAlice.agent)

                MessageExchange()
                    .withProtocol(RFC0048_TRUST_PING_V1)
                    .sendTrustPing(faberAlice)
                    .awaitTrustPingResponse()

            } finally {
                faber.removeConnections()
                removeWallet(Alice.name)
            }
        }
    }
}
