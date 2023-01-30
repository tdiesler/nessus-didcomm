package org.nessus.didcomm.cli.cmd

import org.nessus.didcomm.service.WalletService

abstract class BaseCommand {

    val walletService get() = WalletService.getService()
}
