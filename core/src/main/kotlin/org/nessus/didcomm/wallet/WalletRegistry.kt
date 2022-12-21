package org.nessus.didcomm.wallet

class WalletRegistry {

    private val walletsCache: MutableMap<String, NessusWallet> = mutableMapOf()

    fun walletNames(): Set<String> {
        return walletsCache.keys
    }

    fun putWallet(wallet: NessusWallet) {
        walletsCache[wallet.walletId] = wallet
    }

    fun removeWallet(walletId: String) {
        walletsCache.remove(walletId)
    }

    fun wallets(): Set<NessusWallet> {
        return walletsCache.values.toSet()
    }

    fun getWallet(walletId: String): NessusWallet? {
        return walletsCache[walletId]
    }

    fun getWalletName(walletId: String): String? {
        return getWallet(walletId)?.walletName
    }

    fun getWalletByName(walletName: String): NessusWallet? {
        return walletsCache.values.firstOrNull { w -> w.walletName == walletName }
    }
}
