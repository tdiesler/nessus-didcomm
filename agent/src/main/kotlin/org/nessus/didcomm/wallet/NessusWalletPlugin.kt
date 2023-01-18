package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.EndpointService
import org.nessus.didcomm.service.WalletPlugin
import org.nessus.didcomm.service.WalletServicePlugin
import org.nessus.didcomm.service.WalletStoreService
import java.util.*

class NessusWalletPlugin: WalletServicePlugin, WalletPlugin {
    val log = KotlinLogging.logger {}

    override fun createWallet(config: WalletConfig): Wallet {
        val walletId = "${UUID.randomUUID()}"
        val agentType = AgentType.NESSUS
        val walletAlias = config.alias
        val storageType = config.storageType ?: StorageType.IN_MEMORY
        val endpointUrl = config.endpointUrl ?: EndpointService.getService().endpointUrl
        return Wallet(walletId, walletAlias, agentType, storageType, endpointUrl, options = config.walletOptions)
    }

    override fun removeWallet(wallet: Wallet) {
        // Nothing to do
    }

    override fun createDid(
        wallet: Wallet,
        method: DidMethod?,
        algorithm: KeyAlgorithm?,
        seed: String?
    ): Did {
        return DidService.getService().createDid(
            method ?: DidMethod.KEY,
            algorithm ?: DEFAULT_KEY_ALGORITHM,
            seed?.toByteArray()
        )
    }

    override fun publicDid(wallet: Wallet): Did? {
        return null
    }

    override fun listDids(wallet: Wallet): List<Did> {
        return WalletStoreService.getService().listDids(wallet.id)
    }

    override fun removeConnections(wallet: Wallet) {
        // nothing to do
    }

    // Private ---------------------------------------------------------------------------------------------------------
}