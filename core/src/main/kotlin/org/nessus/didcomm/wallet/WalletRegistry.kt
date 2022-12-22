package org.nessus.didcomm.wallet

class WalletRegistry {

    private val walletsStore: MutableMap<String, NessusWallet> = mutableMapOf()

    fun putWallet(wallet: NessusWallet) {
        walletsStore[wallet.walletId] = wallet
    }

    fun removeWallet(id: String) {
        walletsStore.remove(id)
    }

    fun getWallets(): Set<NessusWallet> {
        return walletsStore.values.toSet()
    }

    fun getWallet(id: String): NessusWallet? {
        return walletsStore[id]
    }

    fun getWalletByName(name: String): NessusWallet? {
        return walletsStore.values.firstOrNull { w -> w.walletName == name }
    }
}
