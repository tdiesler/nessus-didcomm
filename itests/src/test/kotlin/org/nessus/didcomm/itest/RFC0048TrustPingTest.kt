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
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_WRAPPER
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import kotlin.test.fail

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_AliceAcapy() {

        /** Create the wallets */

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .build()

        try {
            endpointService.startEndpoint(alice).use {

                /** Establish a peer connection */

                MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_WRAPPER)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .acceptConnectionFrom(alice)
                    .getConnection()
            }

        } finally {
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }
}
