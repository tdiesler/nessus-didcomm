package org.nessus.didcomm.wallet

import org.nessus.didcomm.service.walletService

class NessusWalletBuilder(private val walletName: String) {

    private var ledgerRole: LedgerRole? = null
    private var trusteeWallet: NessusWallet? = null

    fun ledgerRole(ledgerRole: LedgerRole): NessusWalletBuilder {
        this.ledgerRole = ledgerRole
        return this
    }

    fun trusteeWallet(trusteeWallet: NessusWallet): NessusWalletBuilder {
        this.trusteeWallet = trusteeWallet
        return this
    }

    fun build(): NessusWallet {
        val config: Map<String, Any?> = mapOf(
            "ledgerRole" to ledgerRole,
            "trusteeWallet" to trusteeWallet,
        )
        return walletService().createWallet(walletName, config)
    }
}
