
package org.nessus.didcomm.wallet

import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WalletService

class WalletException(msg: String) : Exception(msg)

/**
 * A NessusWallet gives acces to wallet information as known by the agent.
 */
data class NessusWallet(
    val walletId: String,
    val walletName: String,
    val accessToken: String? = null,
) {
    // [TODO] override toString with redacted values

    fun publicDid() {
        val walletService = ServiceRegistry.getService(WalletService.type)
        walletService.publicDid(this)
    }
}
