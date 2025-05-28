package io.nessus.identity.service

object ServiceManager {

    val walletService = run {
        val holder = ConfigProvider.requireHolderConfig()
        WalletService.build(holder.walletApi)
    }
}