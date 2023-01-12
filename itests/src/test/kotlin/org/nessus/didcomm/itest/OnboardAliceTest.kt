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
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertNull

/**
 * Onboard Alice in_memory with did:key
 * https://github.com/tdiesler/nessus-didcomm/issues/11
 */
class OnboardAliceTest : AbstractIntegrationTest() {

    @Test
    fun testOnboardAlice() {

        val alice = Wallet.Builder(Alice.name)
            .walletAgent(WalletAgent.ACAPY)
            .walletType(WalletType.IN_MEMORY)
            .build()
        try {

            val pubDid = alice.publicDid
            assertNull(pubDid)

        } finally {
            removeWallet(alice)
        }
    }
}
