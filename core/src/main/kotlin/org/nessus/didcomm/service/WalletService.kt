package org.nessus.didcomm.service

import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletException
import org.nessus.didcomm.wallet.WalletRegistry

interface WalletService : Service {

    companion object {
        val type: Class<WalletService> = WalletService::class.java
        val registry = WalletRegistry()
    }

    override val type: Class<WalletService>
        get() = Companion.type

    fun assertConfigValue(config: Map<String, Any?>, key: String) : Any {
        return config[key] ?: throw WalletException("No config value for: $key")
    }

    fun getConfigValue(config: Map<String, Any?>, key: String) : Any? {
        return config[key]
    }

    fun hasConfigValue(config: Map<String, Any?>, key: String) : Boolean {
        return config[key] != null
    }

    fun createWallet(config: Map<String, Any?>): NessusWallet

    fun publicDid(wallet: NessusWallet): String?

    fun closeAndRemove(wallet: NessusWallet?)
}
