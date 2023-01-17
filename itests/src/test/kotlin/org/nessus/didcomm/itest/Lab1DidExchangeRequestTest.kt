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
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import java.util.concurrent.CountDownLatch
import kotlin.test.fail


/**
 * Aries RFC 0434: Out-of-Band Protocol 1.1
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
 *
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 *
 * DIDComm - Out Of Band Messages
 * https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
 */
class Lab1DidExchangeRequestTest : AbstractIntegrationTest() {

    @Test
    fun test_AliceNessus_invites_FaberAcapy() {

        val alice = Wallet.Builder(Alice.name)
            .walletAgent(WalletAgent.NESSUS)
            .walletType(WalletType.IN_MEMORY)
            .build()

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        try {
            val mex = MessageExchange()

            val latch = CountDownLatch(1)
            val listener: MessageListener = {
                mex.addMessage(EndpointMessage(it.body, it.headers))
                latch.countDown()
                true
            }

            endpointService.startEndpoint(listener).use {

                val aliceClient = AriesAgent.walletClient(alice)
                val faberClient = AriesAgent.walletClient(faber)

                /**
                 * Faber creates an Invitation against a non-public Did
                 */

                /**
                 * Alice receives that Invitation (somehow)
                 */

                /**
                 * Alice creates a DIDExchange request
                 */

                /**
                 * Faber receives that DIDExchange request and auto-accepts it
                 */

                /**
                 * Alice ...
                 */
            }

        } finally {
            faber.removePeerConnections()
            removeWallet(alice)
        }
    }
}
