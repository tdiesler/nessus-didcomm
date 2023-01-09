package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidService
import org.nessus.didcomm.did.DidService.DEFAULT_KEY_ALGORITHM

class NessusWalletPlugin: WalletPlugin() {

    override fun createWallet(config: NessusWallet.Builder): NessusWallet {
        val walletId = createUUID()
        val walletAgent = WalletAgent.NESSUS
        val walletName = config.walletName
        val walletType = config.walletType ?: WalletType.IN_MEMORY
        return NessusWallet(walletId, walletAgent, walletType, walletName)
    }

    override fun removeWallet(wallet: NessusWallet) {
        // Nothing to do
    }

    override fun createDid(
        wallet: NessusWallet,
        method: DidMethod?,
        algorithm: KeyAlgorithm?,
        seed: String?
    ): Did {
        return DidService.createDid(
            method ?: DidMethod.KEY,
            algorithm ?: DEFAULT_KEY_ALGORITHM,
            seed?.toByteArray(Charsets.UTF_8)
        )
    }

    override fun publicDid(wallet: NessusWallet): Did? {
        return null
    }

    // -----------------------------------------------------------------------------------------------------------------
}