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
import org.nessus.didcomm.service.DidOptions
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.WalletPlugin
import java.util.UUID

class NessusWallet(
    id: String,
    name: String,
    agentType: AgentType,
    storageType: StorageType,
    endpointUrl: String,
    options: Map<String, String> = mapOf(),
): Wallet(id, name, agentType, storageType, endpointUrl, options) {

    override val walletPlugin get() = NessusWalletPlugin()

    // Private ---------------------------------------------------------------------------------------------------------
}

class NessusWalletPlugin: WalletPlugin {
    val log = KotlinLogging.logger {}

    companion object {
        fun getEndpointUrl(options: Map<String, Any> = mapOf()): String {
            return options["endpointUrl"] as? String ?: let {
                val agentHost = System.getenv("NESSUS_AGENT_HOST") ?: "localhost"
                val userHost = System.getenv("NESSUS_USER_HOST") ?: agentHost
                val userPort = System.getenv("NESSUS_USER_PORT") ?: "9000"
                "http://$userHost:$userPort"
            }
        }
    }

    override fun createWallet(config: Wallet.WalletConfig): NessusWallet {
        val walletId = "${UUID.randomUUID()}"
        val walletName = config.name
        val agentType = AgentType.NESSUS
        val endpointUrl = getEndpointUrl(config.options)
        val storageType = config.storageType ?: StorageType.IN_MEMORY
        return NessusWallet(walletId, walletName, agentType, storageType, endpointUrl, options = config.options)
    }

    override fun removeWallet(wallet: Wallet) {
        // Nothing to do
    }

    override fun createDid(wallet: Wallet, method: DidMethod?, keyAlias: String?, options: DidOptions?): Did {
        val didService = DidService.getService()
        return didService.createDid(method ?: DidMethod.KEY, keyAlias, options)
    }

    override fun publicDid(wallet: Wallet): Did? {
        return null
    }

    override fun removeConnections(wallet: Wallet) {
        wallet.removeConnections()
    }

    // Private ---------------------------------------------------------------------------------------------------------
}