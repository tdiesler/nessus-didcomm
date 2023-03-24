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
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.DIDEXCHANGE_PROTOCOL_V1
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V1
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V1

/**
 * Aries RFC 0048: Trust Ping Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
 */
@EnabledIf(AcaPyOnlyCondition::class)
class TrustPingV1IntegrationTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_AliceNessus() {

        startNessusEndpoint(NESSUS_OPTIONS).use {

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
                aliceFaber.myAgent shouldBe AgentType.NESSUS.value

                // Send an explicit trust ping
                MessageExchange()
                    .withProtocol(TRUST_PING_PROTOCOL_V1)
                    .sendTrustPing(aliceFaber)
                    .awaitTrustPingResponse()

                // Send a reverse trust ping
                val faberAlice = faber.findConnection{ it.myVerkey == aliceFaber.theirVerkey }
                faberAlice?.myAgent shouldBe AgentType.ACAPY.value

                MessageExchange()
                    .withProtocol(TRUST_PING_PROTOCOL_V1)
                    .sendTrustPing(faberAlice)
                    .awaitTrustPingResponse()

            } finally {
                removeWallet(alice)
                removeWallet(faber)
            }
        }
    }
}
