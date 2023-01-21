/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
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
import org.nessus.didcomm.model.AgentModel
import org.nessus.didcomm.model.WalletModel

class ModelManagerService : NessusBaseService() {
    override val implementation get() = serviceImplementation<ModelManagerService>()

    companion object: ServiceProvider {
        private val implementation = ModelManagerService()
        override fun getService() = implementation
    }

    val model = AgentModel()
    val modelAsJson: String get() = model.asJson

    fun addWallet(wallet: WalletModel) {
        check(findWalletByName(wallet.name) == null) { "Wallet already exists: ${wallet.name}" }
        model.addWallet(wallet)
    }

    fun removeWallet(id: String): WalletModel? {
        return model.removeWallet(id)
    }

    /**
     * List wallets by (id, name)
     */
    fun listWallets(): List<Pair<String, String>> {
        return model.wallets
            .map { w -> Pair(w.id, w.name) }
            .sortedBy { it.second }
            .toList()
    }

    fun getWallet(id: String): WalletModel? {
        return model.walletsMap[id]
    }

    fun findWalletByName(name: String): WalletModel? {
        return model.wallets.firstOrNull { it.name == name }
    }


}
