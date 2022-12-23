
package org.nessus.didcomm.wallet

import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.service.walletService

class WalletException(msg: String) : Exception(msg)

/**
 * A NessusWallet gives acces to wallet information as known by the agent.
 */
class NessusWallet(
    val walletId: String,
    val walletName: String,
    val accessToken: String? = null,
) {
    companion object {
        fun builder(name: String): NessusWalletBuilder {
            return NessusWalletBuilder(name)
        }
    }

    val publicDid: String?
        get() = walletService().publicDid(this)

    // [TODO] override toString with redacted values

    // -----------------------------------------------------------------------------------------------------------------

}
