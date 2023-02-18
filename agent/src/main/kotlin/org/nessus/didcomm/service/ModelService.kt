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
import org.nessus.didcomm.model.Wallet

class ModelService : AbstractBaseService() {
    override val implementation get() = serviceImplementation<ModelService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = ModelService()
        override fun getService() = implementation
    }

    val model = AgentModel()
    val modelAsJson: String get() = model.asJson
    val wallets get() = model.wallets

    fun addWallet(wallet: Wallet) {
        check(findWalletByName(wallet.name) == null) { "Wallet already exists: ${wallet.name}" }
        log.info {"Add Wallet: $wallet" }
        model.addWallet(wallet)
    }

    fun getWallet(id: String): Wallet? {
        return model.walletsMap[id]
    }

    fun findWallet(predicate: (w: Wallet) -> Boolean): Wallet? {
        return wallets.firstOrNull(predicate)
    }

    fun findWalletByName(name: String): Wallet? {
        return findWallet { it.name.lowercase() == name.lowercase() }
    }

    fun findWalletByDid(did: String): Wallet? {
        return findWallet { it.findDid { d -> d.qualified == did } != null }
    }

    fun findWalletByVerkey(verkey: String): Wallet? {
        return findWallet { it.findDid { d -> d.verkey == verkey } != null }
    }

    fun removeWallet(id: String): Wallet? {
        model.removeWallet(id)?.run {
            log.info {"Removed Wallet: ${shortString()}" }
            return this
        }
        return null
    }
}
