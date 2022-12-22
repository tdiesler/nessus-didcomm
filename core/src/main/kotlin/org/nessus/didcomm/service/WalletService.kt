package org.nessus.didcomm.service

import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletException
import org.nessus.didcomm.wallet.WalletRegistry

interface WalletService : Service {

    companion object {
        val type = WalletService::class.java
        private val registry = WalletRegistry()
    }

    override val type: Class<WalletService>
        get() = Companion.type

    fun createWallet(config: Map<String, Any?>): NessusWallet

    fun putWallet(wallet: NessusWallet) {
        registry.putWallet(wallet)
    }

    fun removeWallet(id: String) {
        registry.removeWallet(id)
    }

    fun getWallets(): Set<NessusWallet> {
        return registry.getWallets()
    }

    fun getWallet(id: String): NessusWallet? {
        return registry.getWallet(id)
    }

    fun getWalletByName(name: String): NessusWallet? {
        return registry.getWalletByName(name)
    }

    fun publicDid(wallet: NessusWallet): String?


    // -----------------------------------------------------------------------------------------------------------------

    // [TODO] remove
    fun assertConfigValue(config: Map<String, Any?>, key: String) : Any {
        return config[key] ?: throw WalletException("No config value for: $key")
    }

    // [TODO] remove
    fun getConfigValue(config: Map<String, Any?>, key: String) : Any? {
        return config[key]
    }

}
