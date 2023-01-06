/*-
 * #%L
 * Nessus DIDComm :: Core
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
package org.nessus.didcomm.test.wallet

import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WALLET_SERVICE_KEY
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.NessusWalletFactory
import org.nessus.didcomm.wallet.NessusWalletService
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class NessusWalletTest {

    private val log = KotlinLogging.logger {}

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.putService(WALLET_SERVICE_KEY, NessusWalletService())
        }
    }

    @Test
    fun create_wallet_with_DidKey() {

        val faber: NessusWallet = NessusWalletFactory("Faber1")
            .walletAgent(WalletAgent.NESSUS)
            .create()

        assertEquals("Faber1", faber.walletName)
        assertEquals(WalletAgent.NESSUS, faber.walletAgent)
        assertEquals(WalletType.IN_MEMORY, faber.walletType)

        val faberDid = faber.createDid(seed="00000000000000000000000Endorser1")

        assertEquals("did:key:z6Mkr54o55jYrJJCHqoFSgeoH6RWZd6ur7P1BNgAN5Wku97K", faberDid.qualified)
        assertEquals("CcokUqV7WkojBLxYm7gxRzsWk3q4SE8eVMmEXoYjyvKw", faberDid.verkey)

        val keyStore = KeyStoreService.getService()
        assertNotNull(keyStore.load(faberDid.qualified, KeyType.PUBLIC))
        assertNotNull(keyStore.load(faberDid.verkey, KeyType.PUBLIC))
    }
}
