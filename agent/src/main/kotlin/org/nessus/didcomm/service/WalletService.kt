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

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import mu.KotlinLogging
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.NessusWalletPlugin
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.Wallet.WalletConfig
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.io.path.isReadable

object WalletService: ObjectService<WalletService>() {
    private val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    val wallets get() = modelService.wallets

    private val modelService get() = ModelService.getService()
    private val didService get() = DidService.getService()

    fun createWallet(config: WalletConfig): Wallet {
        val maybeWallet = findWallet(config.name)
        val agentType = config.agentType
        val storageType = config.storageType
        if (maybeWallet != null) {
            check(maybeWallet.agentType == agentType) {"Wallet ${config.name} exists, with other agent: ${maybeWallet.agentType}"}
            check(maybeWallet.storageType == storageType)  {"Wallet ${config.name} exists, with other type: ${maybeWallet.storageType}"}
            return maybeWallet
        }

        // Verify routing keys
        config.routingKeys?.forEach {
            val mediatorDid = didService.loadOrResolveDid(it)
            checkNotNull(mediatorDid) { "Cannot resolve mediator Did: $it" }
        }

        val wallet = when(config.agentType) {
            else -> NessusWalletPlugin().createWallet(config)
        }

        addWallet(wallet)
        return wallet
    }

    fun addWallet(wallet: Wallet) {
        modelService.addWallet(wallet)
    }

    fun getWallet(id: String): Wallet {
        return modelService.getWallet(id)
    }

    fun findWallet(alias: String): Wallet? {
        val tst = alias.lowercase()
        return modelService.findWallet {
            it.id.lowercase().startsWith(tst) || it.name.lowercase().startsWith(tst)
        }
    }

    fun findWallets(alias: String?): List<Wallet> {
        val tst = alias?.lowercase()
        return wallets.filter {
            tst == null || it.id.lowercase().startsWith(tst) || it.name.lowercase().startsWith(tst)
        }
    }

    fun removeWallet(id: String): Boolean {
        modelService.getWallet(id)?.also { wallet ->
            wallet.dids.forEach { didService.deleteDid(it) }
            wallet.walletPlugin.removeWallet(wallet)
            modelService.removeWallet(wallet.id)
            return true
        }
        return false
    }

    /**
     * Create a Did for the given wallet
     *
     * Nessus Dids are created locally and have their associated keys in the {@see KeyStoreService}
     */
    fun createDid(wallet: Wallet, method: DidMethod? = null, keyAlias: String? = null, options: DidOptions? = null): Did {
        val auxOptions = options ?: when(method) {
            DidMethod.PEER -> DidPeerOptions(numalgo = 2, wallet.endpointUrl, wallet.routingKeys)
            else -> DidOptions(wallet.endpointUrl, wallet.routingKeys)
        }
        val did = wallet.walletPlugin.createDid(wallet, method, keyAlias, auxOptions)
        wallet.addDid(did)
        return did
    }

    fun getPublicDid(wallet: Wallet): Did? {
        return wallet.walletPlugin.getPublicDid(wallet)
    }

    fun setPublicDid(wallet: Wallet, did: Did?) {
        wallet.walletPlugin.setPublicDid(wallet, did)
    }

    fun removeConnections(wallet: Wallet) {
        wallet.walletPlugin.removeConnections(wallet)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    @Suppress("UNCHECKED_CAST")
    private fun readSieraConfig(): Map<String, Any>? {
        val mapper = ObjectMapper(YAMLFactory()).registerKotlinModule()

        val homeDir = System.getenv("HOME")
        val configPath = Paths.get("$homeDir/.config/siera/config.yaml")

        return if (configPath.isReadable()) {
            Files.newBufferedReader(configPath).use {
                val config = mapper.readValue(it, Map::class.java)
                return config["configurations"] as Map<String, Any>
            }
        } else null
    }
}

interface WalletPlugin {

    fun createWallet(config: WalletConfig): Wallet

    fun removeWallet(wallet: Wallet)

    fun createDid(wallet: Wallet, method: DidMethod?, keyAlias: String? = null, options: DidOptions? = null): Did

    fun getPublicDid(wallet: Wallet): Did?
    fun setPublicDid(wallet: Wallet, did: Did?)

    fun removeConnections(wallet: Wallet)
}

