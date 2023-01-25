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
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0048_TRUST_PING
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import java.util.concurrent.TimeUnit
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

        /** Create the wallets */

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .build()

        try {
            endpointService.startEndpoint(alice).use {

                val aliceFaber = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .acceptConnectionFrom(alice)
                    .getConnection()

                assertNotNull(aliceFaber)
                assertEquals(ConnectionState.ACTIVE, aliceFaber.state)

                // Send an explicit trust ping
                MessageExchange()
                    .withProtocol(RFC0048_TRUST_PING)
                    .sendTrustPing(aliceFaber)
                    .awaitTrustPingResponse(5, TimeUnit.SECONDS)

                // Send a reverse trust ping
                val faberAlice = faber.findConnection(aliceFaber.invitationKey)
                MessageExchange()
                    .withProtocol(RFC0048_TRUST_PING)
                    .sendTrustPing(faberAlice)
                    .awaitTrustPing(alice,5, TimeUnit.SECONDS)
            }

        } finally {
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }
}
