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

package org.nessus.didcomm.model

import mu.KotlinLogging
import org.nessus.didcomm.model.Wallet.WalletConfig
import org.nessus.didcomm.service.DidOptions
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.WalletPlugin
import java.util.UUID

class NessusWallet(
    id: String,
    name: String,
    agentType: AgentType,
    storageType: StorageType,
    walletRole: WalletRole,
    endpointUrl: String,
    routingKeys: List<String>? = null,
    options: Map<String, String>? = null,
): Wallet(id, name, agentType, storageType, walletRole, endpointUrl, routingKeys, options) {

    override val walletPlugin get() = NessusWalletPlugin()

    // Private ---------------------------------------------------------------------------------------------------------
}

class NessusWalletPlugin: WalletPlugin {
    val log = KotlinLogging.logger {}

    companion object {
        fun getEndpointUrl(endpointUrl: String? = null): String {
            return endpointUrl ?: let {
                val userHost = System.getenv("NESSUS_USER_HOST") ?: "localhost"
                val userPort = System.getenv("NESSUS_USER_PORT") ?: "9000"
                "http://$userHost:$userPort"
            }
        }
    }

    override fun createWallet(config: WalletConfig): NessusWallet {
        val walletId = "${UUID.randomUUID()}"
        val walletName = config.name
        val agentType = AgentType.NESSUS
        val storageType = config.storageType ?: StorageType.IN_MEMORY
        val walletRole = config.walletRole ?: WalletRole.USER
        val endpointUrl = getEndpointUrl(config.endpointUrl)
        val routingKeys = config.routingKeys
        return NessusWallet(walletId, walletName, agentType, storageType, walletRole, endpointUrl, routingKeys, options = config.options)
    }

    override fun removeWallet(wallet: Wallet) {
        // Nothing to do
    }

    override fun createDid(wallet: Wallet, method: DidMethod?, keyAlias: String?, options: DidOptions?): Did {
        val didService = DidService.getService()
        return didService.createDid(method ?: DidMethod.KEY, keyAlias, options)
    }

    override fun getPublicDid(wallet: Wallet): Did? {
        return wallet.internalPublicDid
    }

    override fun setPublicDid(wallet: Wallet, did: Did?) {
        wallet.internalPublicDid = did
    }

    override fun removeConnections(wallet: Wallet) {
        wallet.removeConnections()
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
