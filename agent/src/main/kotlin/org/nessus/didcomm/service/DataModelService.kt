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
import org.nessus.didcomm.model.InvitationState
import org.nessus.didcomm.model.WalletModel

class DataModelService : NessusBaseService() {
    override val implementation get() = serviceImplementation<DataModelService>()

    companion object: ServiceProvider {
        private val implementation = DataModelService()
        override fun getService() = implementation
    }

    val model = AgentModel()
    val modelAsJson: String get() = model.asJson

    fun addWallet(wallet: WalletModel) {
        check(findWalletByName(wallet.name) == null) { "Wallet already exists: ${wallet.name}" }
        log.info {"Add: $wallet" }
        model.addWallet(wallet)
    }

    fun getWallet(id: String): WalletModel? {
        return model.walletsMap[id]
    }

    fun listWallets(): List<WalletModel> {
        return model.wallets.sortedBy { it.name }
    }

    fun removeWallet(id: String): WalletModel? {
        val wallet = getWallet(id)
        if (wallet != null) {
            log.info {"Remove: $wallet" }
            model.removeWallet(id)
        }
        return wallet
    }

    fun findWalletByName(name: String): WalletModel? {
        return model.wallets.firstOrNull { it.name == name }
    }

    fun findWalletByVerkey(verkey: String): WalletModel? {
        return model.wallets.firstOrNull {
            it.dids.firstOrNull { did -> did.verkey == verkey } != null
        }
    }

    fun findWalletByInvitation(id: String, state: InvitationState): WalletModel? {
        return model.wallets.firstOrNull {
            val invi = it.getInvitation(id)
            invi?.state == state
        }
    }

}
