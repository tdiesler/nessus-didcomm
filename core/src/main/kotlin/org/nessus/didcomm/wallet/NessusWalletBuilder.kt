package org.nessus.didcomm.wallet

import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WalletService

class NessusWalletBuilder(val name: String) {

    private var ledgerRole: LedgerRole? = null
    private var selfRegister: Boolean = false
    private var trusteeWallet: NessusWallet? = null

    fun ledgerRole(ledgerRole: LedgerRole): NessusWalletBuilder {
        this.ledgerRole = ledgerRole
        return this
    }

    fun selfRegisterNym(): NessusWalletBuilder {
        this.selfRegister = true
        return this
    }

    fun trusteeWallet(trusteeWallet: NessusWallet): NessusWalletBuilder {
        this.trusteeWallet = trusteeWallet
        return this
    }

    fun build(): NessusWallet {
        val walletService = ServiceRegistry.getService(WalletService.type)
        val config: Map<String, Any?> = mapOf(
            "walletName" to name,
            "ledgerRole" to ledgerRole,
            "selfRegister" to selfRegister,
            "trusteeWallet" to trusteeWallet,
        )
        return walletService.createWallet(config)
    }
}
