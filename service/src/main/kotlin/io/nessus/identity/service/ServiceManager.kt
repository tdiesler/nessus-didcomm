package io.nessus.identity.service

object ServiceManager {

    val walletService = run {
        val serviceConfig = ConfigProvider.requireServiceConfig()
        WalletService.build(serviceConfig.walletApiUrl)
    }
}