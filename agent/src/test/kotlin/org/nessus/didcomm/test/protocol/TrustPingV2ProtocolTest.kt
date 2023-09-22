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
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber

/**
 * Nessus DIDComm: Trust Ping Protocol 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0048-trust-ping
 */
class TrustPingV2ProtocolTest: AbstractAgentTest() {

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
    }

    @Before
    fun beforeEach() {
        Wallet.Builder(Faber.name).build()
        Wallet.Builder(Alice.name).build()
    }

    @After
    fun afterEach() {
        removeWallets()
    }

    @Test
    fun trustPing_DidKey() {

        val faber = walletByName(Faber.name)
        val alice = walletByName(Alice.name)

        val mex = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(faber)
            .receiveOutOfBandInvitation(
                inviterAlias = faber.alias,
                invitee = alice)

            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .getMessageExchange()

        val aliceFaber = mex.getConnection()
        aliceFaber.state shouldBe ACTIVE
        aliceFaber.myLabel shouldBe alice.alias
        aliceFaber.theirLabel shouldBe faber.alias

        // Send an explicit trust ping
        MessageExchange()
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing(aliceFaber)
            .awaitTrustPingResponse()

        // Send a reverse trust ping
        val faberAlice = faber.findConnection{ it.myVerkey == aliceFaber.theirVerkey }
        faberAlice?.state shouldBe ACTIVE
        faberAlice?.myLabel shouldBe faber.alias
        faberAlice?.theirLabel shouldBe alice.alias

        MessageExchange()
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing(faberAlice)
            .awaitTrustPingResponse()
    }
}
