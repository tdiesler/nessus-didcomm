/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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
package org.nessus.didcomm.wallet

import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.NessusDidService
import org.nessus.didcomm.service.WalletPlugin
import java.util.UUID

class NessusWalletPlugin: WalletPlugin {
    val log = KotlinLogging.logger {}

    companion object {
        fun getNessusEndpointUrl(options: Map<String, Any>): String {
            val hostname = options["NESSUS_HOSTNAME"] ?: System.getenv("NESSUS_HOSTNAME") ?: "localhost"
            val userPort = options["NESSUS_USER_PORT"] ?: System.getenv("NESSUS_USER_PORT") ?: "8130"
            return "http://$hostname:$userPort"
        }
    }

    override fun createWallet(config: WalletConfig): NessusWallet {
        val walletId = "${UUID.randomUUID()}"
        val walletName = config.name
        val agentType = AgentType.NESSUS
        val endpointUrl = getNessusEndpointUrl(config.options)
        val storageType = config.storageType ?: StorageType.IN_MEMORY
        return NessusWallet(walletId, walletName, agentType, storageType, endpointUrl, options = config.options)
    }

    override fun removeWallet(wallet: Wallet) {
        // Nothing to do
    }

    override fun createDid(wallet: Wallet, method: DidMethod?, keyAlias: String?): Did {
        return NessusDidService.getService().createDid(method ?: DidMethod.KEY, keyAlias)
    }

    override fun publicDid(wallet: Wallet): Did? {
        return null
    }

    override fun removeConnections(wallet: Wallet) {
        wallet.removeConnections()
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
