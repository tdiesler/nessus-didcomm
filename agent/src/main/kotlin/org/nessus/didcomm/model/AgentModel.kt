package org.nessus.didcomm.model

import org.nessus.didcomm.util.gson

class AgentModel {

    internal val walletsMap: MutableMap<String, WalletModel> = mutableMapOf()

    val wallets get() = walletsMap.values

    val asJson get() = gson.toJson(mapOf(
        "wallets" to wallets.sortedBy { it.name }))

    fun addWallet(wallet: WalletModel) {
        check(!walletsMap.containsKey(wallet.id)) { "Wallet already exists: ${wallet.id}" }
        walletsMap[wallet.id] = wallet
    }

    fun removeWallet(id: String): WalletModel? {
        return walletsMap.remove(id)
    }
}

