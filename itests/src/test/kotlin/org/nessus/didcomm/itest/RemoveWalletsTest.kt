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
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.service.ARIES_AGENT_SERVICE_KEY
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.ServiceRegistry.walletService
import org.nessus.didcomm.service.WALLET_SERVICE_KEY
import org.nessus.didcomm.wallet.NessusWalletService

class RemoveWalletsTest : AbstractIntegrationTest() {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.putService(ARIES_AGENT_SERVICE_KEY, AriesAgentService())
            ServiceRegistry.putService(WALLET_SERVICE_KEY, NessusWalletService())
        }
    }

    @Test
    fun removeWallets() {
        walletService().getWallets()
            .filter { it.walletName != Government.name }
            .forEach { walletService().removeWallet(it.walletId) }
    }
}
