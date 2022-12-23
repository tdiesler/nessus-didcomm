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

import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.aries.AriesAgentService
import org.nessus.didcomm.agent.aries.AriesWalletService
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.walletService
import org.nessus.didcomm.wallet.DIDMethod
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertNull

/**
 * Onboard Alice in_memory with did:key
 * https://github.com/tdiesler/nessus-didcomm/issues/11
 */
class OnboardAliceTest : AbstractAriesTest() {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.addService(AriesAgentService())
            ServiceRegistry.addService(AriesWalletService())
        }
    }

    @Test
    fun testOnboardAlice() {

        val maybeAlice = getWalletByName(ALICE)
        val alice = maybeAlice ?: NessusWallet.builder(ALICE)
            .walletType(WalletType.IN_MEMORY)
            .didMethod(DIDMethod.KEY)
            .build()

        try {

            val pubDid = alice.publicDid
            assertNull(pubDid)

        } finally {
            if (maybeAlice == null)
                walletService().removeWallet(alice.walletId)
        }
    }
}
