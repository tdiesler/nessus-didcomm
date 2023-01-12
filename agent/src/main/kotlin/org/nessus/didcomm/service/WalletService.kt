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

import id.walt.crypto.KeyAlgorithm
import id.walt.servicematrix.BaseService
import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.hyperledger.aries.api.multitenancy.CreateWalletTokenRequest
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.wallet.AriesWalletPlugin
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.NessusWalletPlugin
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletConfig
import org.nessus.didcomm.wallet.WalletType

class WalletService : BaseService() {
    override val implementation get() = serviceImplementation<WalletService>()

    private val log = KotlinLogging.logger {}

    private val walletStore get() = WalletStoreService.getService()

    private val plugins = mapOf(
        WalletAgent.ACAPY to AriesWalletPlugin(),
        WalletAgent.NESSUS to NessusWalletPlugin()
    )

    companion object: ServiceProvider {
        private val implementation = WalletService()
        override fun getService() = implementation
    }

    init {
        // Initialize wallets from ACAPy
        val adminClient = AriesAgent.adminClient()
        adminClient.multitenancyWallets(null).get().forEach {
            val walletId = it.walletId
            val alias = it.settings.walletName
            val walletType = WalletType.valueOf(it.settings.walletType.name)
            val tokReq = CreateWalletTokenRequest.builder().build()
            val tokRes = adminClient.multitenancyWalletToken(walletId, tokReq).get()
            val wallet = Wallet(walletId, alias, WalletAgent.ACAPY, walletType, authToken=tokRes.token)
            addWallet(wallet)
        }
    }

    fun createWallet(config: WalletConfig): Wallet {
        val maybeWallet = findByAlias(config.alias)
        val walletAgent = config.walletAgent ?: WalletAgent.NESSUS
        val walletType = config.walletType ?: WalletType.IN_MEMORY
        if (config.mayExist && maybeWallet != null) {
            check(maybeWallet.walletAgent == walletAgent) {"Wallet ${config.alias} exists, with other agent: ${maybeWallet.walletAgent}"}
            check(maybeWallet.walletType == walletType)  {"Wallet ${config.alias} exists, with other type: ${maybeWallet.walletType}"}
            return maybeWallet
        }
        val wallet = walletPlugin(walletAgent).createWallet(config)
        addWallet(wallet)
        return wallet
    }

    fun addWallet(wallet: Wallet) {
        check(findByAlias(wallet.alias) == null) {"Wallet already exists: ${wallet.alias}"}
        log.info {"Add: $wallet" }
        walletStore.addWallet(wallet)
    }

    fun removeWallet(id: String): Wallet? {
        val wallet = getWallet(id)
        if (wallet != null) {
            log.info {"Remove: $wallet" }
            walletPlugin(wallet.walletAgent).removeWallet(wallet)
            return walletStore.removeWallet(id)
        }
        return null
    }

    fun getWallets(): List<Wallet> {
        return walletStore.wallets
    }

    fun getWallet(id: String): Wallet? {
        return walletStore.getWallet(id)
    }

    fun findByAlias(alias: String): Wallet? {
        return walletStore.findByAlias(alias)
    }

    /**
     * Create a Did for the given wallet
     *
     * Nessus Dids are created locally and have their associated keys in the {@see KeyStoreService}
     */
    fun createDid(wallet: Wallet, method: DidMethod?, algorithm: KeyAlgorithm?, seed: String?): Did {
        return walletPlugin(wallet.walletAgent).createDid(wallet, method, algorithm, seed)
    }

    /**
     * List Dids registered with the given wallet
     */
    fun listDids(wallet: Wallet): List<Did> {
        return walletPlugin(wallet.walletAgent).listDids(wallet)
    }

    fun addPeerConnection(wallet: Wallet, con: PeerConnection) {
        walletStore.addPeerConnection(wallet.id, con)
    }

    fun listPeerConnections(wallet: Wallet): List<PeerConnection> {
        return walletStore.listPeerConnections(wallet.id)
    }

    /**
     * Get the (optional) public Did for the given wallet
     */
    fun publicDid(wallet: Wallet): Did? {
        return walletPlugin(wallet.walletAgent).publicDid(wallet)
    }

    /**
     * List supported protocols for the given agent type
     */
    fun listProtocols(agent: WalletAgent): List<String> {
        return walletPlugin(agent).listSupportedProtocols()
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun walletPlugin(walletAgent: WalletAgent): WalletPlugin {
        return plugins[walletAgent] as WalletPlugin
    }
}

abstract class WalletPlugin {

    val log = KotlinLogging.logger {}

    abstract fun createWallet(config: WalletConfig): Wallet

    abstract fun removeWallet(wallet: Wallet)

    abstract fun createDid(
        wallet: Wallet,
        method: DidMethod?,
        algorithm: KeyAlgorithm? = null,
        seed: String? = null): Did

    abstract fun listSupportedProtocols(): List<String>

    abstract fun publicDid(wallet: Wallet): Did?

    abstract fun listDids(wallet: Wallet): List<Did>
}

