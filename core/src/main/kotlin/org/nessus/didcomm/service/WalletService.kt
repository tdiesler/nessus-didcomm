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

import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletRegistry

interface WalletService : Service {

    companion object {
        val type = WalletService::class.java
        private val registry = WalletRegistry()
    }

    override val type: Class<WalletService>
        get() = Companion.type

    fun createWallet(walletName: String?, config: Map<String, Any?>): NessusWallet

    fun putWallet(wallet: NessusWallet) {
        registry.putWallet(wallet)
    }

    fun removeWallet(id: String) {
        registry.removeWallet(id)
    }

    fun getWallets(): Set<NessusWallet> {
        return registry.getWallets()
    }

    fun getWallet(id: String): NessusWallet? {
        return registry.getWallet(id)
    }

    fun getWalletByName(name: String): NessusWallet? {
        return registry.getWalletByName(name)
    }

    fun publicDid(wallet: NessusWallet): String?


    // -----------------------------------------------------------------------------------------------------------------

}
