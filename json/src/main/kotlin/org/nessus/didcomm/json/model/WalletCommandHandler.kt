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
package org.nessus.didcomm.json.model

import kotlinx.serialization.json.Json
import mu.KotlinLogging
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.WalletRole
import org.nessus.didcomm.service.WalletService

object WalletCommandHandler {
    private val log = KotlinLogging.logger {}

    private val walletService get() = WalletService.getService()

    fun createWallet(callerId: String, payload: String): Wallet {
        val data = Json.decodeFromString<WalletData>(payload)
        if (data.walletRole == WalletRole.TRUSTEE) {
            check(walletService.wallets.isEmpty() && callerId.isEmpty()) { "The TRUSTEE wallet must be the first to create" }
            return walletService.createWallet(data.toWalletConfig())
        }
        val walletRole = data.walletRole ?: WalletRole.CLIENT
        val callerRole = walletService.findWallet(callerId)?.walletRole
        checkNotNull(callerRole) { "No caller role" }
        check(callerRole.ordinal <= WalletRole.ENDORSER.ordinal) { "$callerRole cannot create $walletRole wallet" }
        return walletService.createWallet(data.toWalletConfig())
    }

    fun findWallet(callerId: String, payload: String): Wallet? {
        val data = Json.decodeFromString<WalletData>(payload)
        checkNotNull(data.alias) { "No wallet alias" }
        return walletService.findWallet(data.alias)
    }

    fun listWallets(callerId: String, payload: String): List<Wallet> {
        val data = Json.decodeFromString<WalletData>(payload)
        return walletService.findWallets(data.alias)
    }

    fun removeWallet(callerId: String, payload: String): Boolean {
        val data = Json.decodeFromString<WalletData>(payload)
        val callerRole = walletService.findWallet(callerId)?.walletRole
        checkNotNull(data.id) { "No wallet id" }
        checkNotNull(callerRole) { "No caller role" }
        walletService.findWallet(data.id)?.also { wallet ->
            val walletRole = wallet.walletRole
            check(callerId == wallet.id || callerRole.ordinal < walletRole.ordinal) { "$callerRole cannot remove $walletRole wallet" }
            return walletService.removeWallet(wallet.id)
        }
        return false
    }
}
