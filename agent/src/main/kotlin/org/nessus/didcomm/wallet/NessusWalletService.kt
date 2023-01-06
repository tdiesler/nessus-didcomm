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
package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.WalletService

class NessusWalletService : WalletService {

    private val log = KotlinLogging.logger {}

    private val plugins = mapOf(
        WalletAgent.ACAPY to AriesWalletPlugin(),
        WalletAgent.NESSUS to NessusWalletPlugin()
    )

    override fun createWallet(config: Map<String, Any?>): NessusWallet {
        val walletName = config["walletName"] as? String
        val walletAgent = config["walletAgent"] as? WalletAgent ?: WalletAgent.ACAPY
        val nessusWallet = walletPlugin(walletAgent).createWallet(config)
        log.info("{}: {}", walletName, nessusWallet)
        putWallet(nessusWallet)
        return nessusWallet
    }

    override fun createDid(wallet: NessusWallet, method: DidMethod?, algorithm: KeyAlgorithm?, seed: String?): Did {
        return walletPlugin(wallet.walletAgent).createDid(wallet, method, algorithm, seed)
    }

    override fun publicDid(wallet: NessusWallet): Did? {
        return walletPlugin(wallet.walletAgent).publicDid(wallet)
    }

    override fun removeWallet(id: String) {
        val wallet = getWallet(id)
        if (wallet != null) {
            walletPlugin(wallet.walletAgent).removeWallet(wallet)
            super.removeWallet(id)
        }
    }

    // -----------------------------------------------------------------------------------------------------------------

    private fun walletPlugin(walletAgent: WalletAgent): WalletPlugin {
        return plugins[walletAgent] as WalletPlugin
    }
}

abstract class WalletPlugin {

    val log = KotlinLogging.logger {}

    abstract fun createWallet(config: Map<String, Any?>): NessusWallet

    abstract fun removeWallet(wallet: NessusWallet)

    abstract fun createDid(
        wallet: NessusWallet,
        method: DidMethod?,
        algorithm: KeyAlgorithm? = null,
        seed: String? = null): Did

    abstract fun publicDid(wallet: NessusWallet): Did?
}

