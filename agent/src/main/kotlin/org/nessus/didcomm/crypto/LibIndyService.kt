package org.nessus.didcomm.crypto

import org.hyperledger.indy.sdk.LibIndy
import org.hyperledger.indy.sdk.wallet.Wallet
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.util.gson

object LibIndyService {

    init {
        // Surefire seems to shadow DYLD_LIBRARY_PATH
        (System.getenv("DYLD_LIBRARY_PATH") ?: System.getenv("LIBINDY_LIBRARY_PATH"))?.run {
            LibIndy.init(this)
        }
    }

    private val indyWallets: MutableMap<String, Wallet> = mutableMapOf()

    fun createAnOpenWallet(alias: String): Wallet {
        val config = walletConfigForAlias(alias)
        Wallet.createWallet(config.first, config.second).get()
        indyWallets[alias] = Wallet.openWallet(config.first, config.second).get()
        return indyWallets[alias] as Wallet
    }

    fun createAndStoreDid(wallet: Wallet, seed: String): Did {
        val seedConfig = gson.toJson(mapOf("seed" to seed))
        val didResult = org.hyperledger.indy.sdk.did.Did.createAndStoreMyDid(wallet, seedConfig).get()
        return Did.fromSpec("did:sov:${didResult.did}", didResult.verkey)
    }

    fun closeAndDeleteWallet(alias: String) {
        indyWallets.remove(alias)?.run {
            this.closeWallet()
            val config = walletConfigForAlias(alias)
            Wallet.deleteWallet(config.first, config.second).get()
        }
    }

    private fun walletConfigForAlias(alias: String): Pair<String, String> {
        return Pair(
            gson.toJson(mapOf("id" to alias)),
            gson.toJson(mapOf("key" to alias + "Key"))
        )
    }
}
