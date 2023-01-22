package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.WalletPlugin
import org.nessus.didcomm.service.WalletServicePlugin
import java.util.*

class NessusWalletPlugin: WalletServicePlugin, WalletPlugin {
    val log = KotlinLogging.logger {}

    override fun getEndpointUrl(wallet: Wallet): String {
        val hostname = wallet.options["NESSUS_HOSTNAME"] ?: System.getenv("NESSUS_HOSTNAME") ?: "localhost"
        val userPort = wallet.options["NESSUS_USER_PORT"] ?: System.getenv("NESSUS_USER_PORT") ?: "8130"
        return "http://$hostname:$userPort"
    }

    override fun createWallet(config: WalletConfig): Wallet {
        val walletId = "${UUID.randomUUID()}"
        val agentType = AgentType.NESSUS
        val walletName = config.name
        val storageType = config.storageType ?: StorageType.IN_MEMORY
        return Wallet(walletId, walletName, agentType, storageType, options = config.walletOptions)
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
        return wallet.toWalletModel().listDids()
    }

    override fun removeConnections(wallet: Wallet) {
        // nothing to do
    }

    // Private ---------------------------------------------------------------------------------------------------------
}