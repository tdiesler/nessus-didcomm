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
import id.walt.servicematrix.BaseService
import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.nessus.didcomm.did.Did

class WalletException(msg: String) : Exception(msg)

class WalletService() : BaseService() {
    override val implementation get() = WalletService.implementation

    private val log = KotlinLogging.logger {}

    private val walletStore = WalletStore()

    private val plugins = mapOf(
        WalletAgent.ACAPY to AriesWalletPlugin(),
        WalletAgent.NESSUS to NessusWalletPlugin()
    )

    companion object: ServiceProvider {
        private val implementation = WalletService()
        override fun getService() = implementation
    }

    fun createWallet(config: NessusWallet.Builder): NessusWallet {
        val walletName = config.walletName
        val walletAgent = config.walletAgent ?: WalletAgent.ACAPY
        val nessusWallet = walletPlugin(walletAgent).createWallet(config)
        log.info("{}: {}", walletName, nessusWallet)
        putWallet(nessusWallet)
        return nessusWallet
    }

    fun putWallet(wallet: NessusWallet) {
        walletStore.putWallet(wallet)
    }

    fun removeWallet(id: String) {
        val wallet = getWallet(id)
        if (wallet != null) {
            walletPlugin(wallet.walletAgent).removeWallet(wallet)
            walletStore.removeWallet(id)
        }
    }

    fun getWallets(): Set<NessusWallet> {
        return walletStore.getWallets()
    }

    fun getWallet(id: String): NessusWallet? {
        return walletStore.getWallet(id)
    }

    fun getWalletByName(name: String): NessusWallet? {
        return walletStore.getWalletByName(name)
    }

    fun createDid(wallet: NessusWallet, method: DidMethod?, algorithm: KeyAlgorithm?, seed: String?): Did {
        return walletPlugin(wallet.walletAgent).createDid(wallet, method, algorithm, seed)
    }

    fun publicDid(wallet: NessusWallet): Did? {
        return walletPlugin(wallet.walletAgent).publicDid(wallet)
    }

    // -----------------------------------------------------------------------------------------------------------------

    private fun walletPlugin(walletAgent: WalletAgent): WalletPlugin {
        return plugins[walletAgent] as WalletPlugin
    }
}

abstract class WalletPlugin {

    val log = KotlinLogging.logger {}

    abstract fun createWallet(config: NessusWallet.Builder): NessusWallet

    abstract fun removeWallet(wallet: NessusWallet)

    abstract fun createDid(
        wallet: NessusWallet,
        method: DidMethod?,
        algorithm: KeyAlgorithm? = null,
        seed: String? = null): Did

    abstract fun publicDid(wallet: NessusWallet): Did?
}

