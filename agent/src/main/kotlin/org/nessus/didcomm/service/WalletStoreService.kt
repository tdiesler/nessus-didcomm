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
package org.nessus.didcomm.service

import id.walt.servicematrix.ServiceProvider
import org.nessus.didcomm.model.WalletModel
import org.nessus.didcomm.wallet.Wallet

class WalletStoreService: NessusBaseService() {
    override val implementation get() = serviceImplementation<WalletStoreService>()

    companion object: ServiceProvider {
        private val implementation = WalletStoreService()
        override fun getService() = implementation
    }

    private val modelService get() = DataModelService.getService()
    private val walletStorage: MutableMap<String, Wallet> = mutableMapOf()

    fun addWallet(wallet: Wallet) {
        check(getWallet(wallet.id) == null) { "Wallet already exists: ${wallet.name}" }
        walletStorage[wallet.id] = wallet
        modelService.addWallet(WalletModel.fromWallet(wallet))
    }

    fun getWallet(walletId: String): Wallet? {
        return walletStorage[walletId]
    }

    fun removeWallet(walletId: String): Wallet? {
        val wallet = walletStorage.remove(walletId)
        modelService.removeWallet(walletId)
        return wallet
    }

    // Private ---------------------------------------------------------------------------------------------------------

}