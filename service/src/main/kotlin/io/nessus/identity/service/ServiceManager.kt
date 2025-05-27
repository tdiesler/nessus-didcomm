package io.nessus.identity.service

object ServiceManager {

    val walletService = WalletService.build(ConfigProvider.config.walletApi)
}