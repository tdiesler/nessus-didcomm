package org.nessus.didcomm.itest

import mu.KotlinLogging
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WalletService

abstract class AbstractAriesTest {

    val log = KotlinLogging.logger {}

    fun walletService(): WalletService {
        return ServiceRegistry.getService(WalletService.type)
    }
}
