package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.protocol.Protocol
import org.nessus.didcomm.service.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.EndpointService
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1
import org.nessus.didcomm.service.ProtocolId
import org.nessus.didcomm.service.WalletPlugin
import org.nessus.didcomm.service.WalletStoreService
import java.util.*

class NessusWalletPlugin: WalletPlugin() {

    override fun createWallet(config: WalletConfig): Wallet {
        val walletId = "${UUID.randomUUID()}"
        val walletAgent = WalletAgent.NESSUS
        val walletAlias = config.alias
        val walletType = config.walletType ?: WalletType.IN_MEMORY
        val endpointUrl = config.endpointUrl ?: EndpointService.getService().endpointUrl
        return Wallet(walletId, walletAlias, walletAgent, walletType, endpointUrl)
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

    override fun <T: Protocol> getProtocol(id: ProtocolId<T>): T? {
        TODO("Not yet implemented")
    }

    override fun listSupportedProtocols(): List<String> {
        return listOf(PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1.name)
    }

    override fun listDids(wallet: Wallet): List<Did> {
        return WalletStoreService.getService().listDids(wallet.id)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}