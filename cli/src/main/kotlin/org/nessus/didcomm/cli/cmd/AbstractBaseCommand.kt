package org.nessus.didcomm.cli.cmd

import org.nessus.didcomm.cli.CLIService
import org.nessus.didcomm.service.CamelEndpointService
import org.nessus.didcomm.service.DataModelService
import org.nessus.didcomm.service.WalletService

abstract class AbstractBaseCommand {

    val cliService get() = CLIService.getService()
    val endpointService get() = CamelEndpointService.getService()
    val modelService get() = DataModelService.getService()
    val walletService get() = WalletService.getService()
}
