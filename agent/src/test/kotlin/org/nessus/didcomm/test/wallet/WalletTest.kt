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
import org.junit.jupiter.api.Test
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.StorageType
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class WalletTest: AbstractDidCommTest() {

    @Test
    fun create_wallet_with_DidKey() {

        val faber: Wallet = Wallet.Builder("Faber1")
            .build()

        assertEquals("Faber1", faber.name)
        assertEquals(AgentType.NESSUS, faber.agentType)
        assertEquals(StorageType.IN_MEMORY, faber.storageType)

        val faberDid = faber.createDid(seed= Faber.seed)

        assertEquals(Faber.didkey, faberDid.qualified)
        assertEquals(Faber.verkey, faberDid.verkey)

        val keyStore = KeyStoreService.getService()
        assertNotNull(keyStore.load(faberDid.qualified, KeyType.PUBLIC))
        assertNotNull(keyStore.load(faberDid.verkey!!, KeyType.PUBLIC))

        walletService.removeWallet(faber.id)
    }
}
