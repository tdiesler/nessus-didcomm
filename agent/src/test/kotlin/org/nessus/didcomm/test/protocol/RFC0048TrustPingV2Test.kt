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
import io.kotest.matchers.shouldNotBe
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V2
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.test.NESSUS_OPTIONS_01

/**
 * Nessus DIDComm RFC0048: Trust Ping Protocol 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0048-trust-ping
 */
class RFC0048TrustPingV2Test : AbstractAgentTest() {

    @Test
    fun test_FaberAcapy_AliceNessus() {

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            /** Create the wallets */

            val faber = Wallet.Builder(Faber.name)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .build()

            try {
                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V2)
                    .createOutOfBandInvitation(faber)
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(RFC0048_TRUST_PING_V2)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .getMessageExchange()

                val aliceAcme = mex.getConnection()
                aliceAcme.state shouldBe ACTIVE

                // Send an explicit trust ping
                MessageExchange()
                    .withProtocol(RFC0048_TRUST_PING_V2)
                    .sendTrustPing(aliceAcme)
                    .awaitTrustPingResponse()

                // Send a reverse trust ping
                val acmeAlice = faber.findConnection{ it.myVerkey == aliceAcme.theirVerkey }
                acmeAlice shouldNotBe null

                MessageExchange()
                    .withProtocol(RFC0048_TRUST_PING_V2)
                    .sendTrustPing(acmeAlice)
                    .awaitTrustPingResponse()

            } finally {
                removeWallet(alice)
                removeWallet(faber)
            }
        }
    }
}
