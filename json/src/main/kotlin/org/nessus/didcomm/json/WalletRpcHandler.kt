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
package org.nessus.didcomm.json

import kotlinx.serialization.json.Json
import org.nessus.didcomm.json.model.WalletData
import org.nessus.didcomm.model.Wallet

object WalletRpcHandler: AbstractRpcHandler() {

    fun createWallet(payload: String): Wallet {
        val data = Json.decodeFromString<WalletData>(payload)
        return walletService.createWallet(data.toWalletConfig())
    }

    fun findWallet(payload: String): Wallet? {
        val data = Json.decodeFromString<WalletData>(payload)
        checkNotNull(data.alias) { "No wallet alias" }
        return walletService.findWallet(data.alias)
    }

    fun listWallets(payload: String): List<Wallet> {
        val data = Json.decodeFromString<WalletData>(payload)
        val wallets = walletService.wallets.toMutableList()
        if (data.walletRole != null)
            wallets.retainAll{ it.walletRole == data.walletRole }
        return wallets
    }

    fun removeWallet(payload: String): Boolean {
        val data = Json.decodeFromString<WalletData>(payload)
        checkNotNull(data.id) { "No wallet id" }
        walletService.findWallet(data.id)?.also { wallet ->
            return walletService.removeWallet(wallet.id)
        }
        return false
    }
}
