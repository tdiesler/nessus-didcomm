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
package org.nessus.didcomm.itest.lab

import org.junit.jupiter.api.Test
import org.nessus.didcomm.itest.ACAPY_OPTIONS_01
import org.nessus.didcomm.itest.ACAPY_OPTIONS_02
import org.nessus.didcomm.itest.AbstractIntegrationTest
import org.nessus.didcomm.itest.Alice
import org.nessus.didcomm.itest.Faber
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.StorageType
import org.nessus.didcomm.wallet.Wallet
import java.util.concurrent.CountDownLatch

class Lab1DidExchangeTest : AbstractIntegrationTest() {

    @Test
    fun testOnboardWallets() {

        val faber = Wallet.Builder(Faber.name)
            .options(ACAPY_OPTIONS_01)
            .agentType(AgentType.ACAPY)
            .storageType(StorageType.INDY)
            .mayExist(true)
            .build()

        val alice = Wallet.Builder(Alice.name)
            .options(ACAPY_OPTIONS_02)
            .agentType(AgentType.ACAPY)
            .storageType(StorageType.INDY)
            .build()

        val mex = MessageExchange()
        val latch = CountDownLatch(1)
        val listener: MessageListener = {
            mex.addMessage(it)
            latch.countDown()
            true
        }

        try {
            endpointService.startEndpoint(listener).use {

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
            removeWallet(alice)
        }
    }
}
