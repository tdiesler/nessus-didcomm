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
import mu.KotlinLogging
import org.nessus.didcomm.model.AgentModel
import org.nessus.didcomm.model.WalletModel

class DataModelService : NessusBaseService() {
    override val implementation get() = serviceImplementation<DataModelService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = DataModelService()
        override fun getService() = implementation
    }

    val model = AgentModel()
    val modelAsJson: String get() = model.asJson
    val wallets get() = model.wallets

    fun addWallet(wallet: WalletModel) {
        check(findWalletByName(wallet.name) == null) { "Wallet already exists: ${wallet.name}" }
        log.info {"Add: $wallet" }
        model.addWallet(wallet)
    }

    fun getWallet(id: String): WalletModel? {
        return model.walletsMap[id]
    }

    fun findWallet(predicate: (w: WalletModel) -> Boolean): WalletModel? {
        return wallets.firstOrNull(predicate)
    }

    fun findWallets(predicate: (w: WalletModel) -> Boolean): List<WalletModel> {
        return wallets.filter(predicate)
    }

    fun findWalletByName(name: String): WalletModel? {
        return findWallet { it.name.lowercase() == name.lowercase() }
    }

    fun findWalletByVerkey(verkey: String): WalletModel? {
        return findWallet { it.findDid { d -> d.verkey == verkey } != null }
    }

    fun removeWallet(id: String): WalletModel? {
        model.removeWallet(id)?.run {
            log.info {"Removed: $this" }
            return this
        }
        return null
    }
}
