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
package org.nessus.didcomm.test.json

import io.kotest.matchers.result.shouldBeSuccess
import org.junit.jupiter.api.Assertions.assertEquals
import org.nessus.didcomm.json.model.WalletData
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.WalletRole

class WalletRpcTest: AbstractJsonRpcTest() {

    @Test
    fun createFindRemoveWallet() {

        // Create Trustee wallet

        val gov: Wallet = createWallet("Government", WalletRole.TRUSTEE)
        log.info { gov }

        val data = WalletData.fromWallet(gov)
        assertEquals("Government", data.alias)
        assertEquals(WalletRole.TRUSTEE, data.walletRole)

        // Find wallet

        var res = rpcService.dispatchRpcCommand("/wallet/find", WalletData(alias = "gov").toJson())
        val found = res.shouldBeSuccess() as? Wallet
        assertEquals(gov.id, found?.id)

        // List wallets

        res = rpcService.dispatchRpcCommand("/wallet/list", WalletData().toJson())
        val wallets = res.shouldBeSuccess() as List<*>
        assertEquals(1, wallets.size)
        assertEquals(gov.id, (wallets[0] as Wallet).id)

        // Remove wallet

        removeWallet(gov)
    }
}
