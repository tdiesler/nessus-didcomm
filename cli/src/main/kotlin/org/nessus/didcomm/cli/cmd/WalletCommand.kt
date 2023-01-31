package org.nessus.didcomm.cli.cmd

import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.toWalletModel
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.util.concurrent.Callable

@Command(
    name = "wallet",
    description = ["Wallet related commands"],
    mixinStandardHelpOptions = true,
    subcommands = [
        WalletCreate::class,
        WalletList::class,
        WalletRemove::class,
    ]
)
class WalletCommand: AbstractBaseCommand()

@Command(name = "create")
class WalletCreate: AbstractBaseCommand(), Callable<Int> {

    @Option(names = ["-n", "--name" ], required = true, description = ["The wallet name"])
    var name: String? = null

    @Option(names = ["-a", "--agent" ], description = ["The agent type (default=Nessus)"], defaultValue = "Nessus")
    var agent: String? = null

    override fun call(): Int {
        val wallet = Wallet.Builder(name!!)
            .agentType(AgentType.fromValue(agent!!))
            .build().toWalletModel()
        println("Created: ${wallet.asString()}")
        return 0
    }
}

@Command(name = "list")
class WalletList: AbstractBaseCommand(), Callable<Int> {

    override fun call(): Int {
        walletService.wallets.forEach {
            println( it.toWalletModel().asString() )
        }
        return 0
    }
}

@Command(name = "remove")
class WalletRemove: AbstractBaseCommand(), Callable<Int> {

    @Option(names = ["-n", "--name" ], required = true, description = ["The wallet name"])
    var name: String? = null

    override fun call(): Int {
        modelService.findWalletByName(name!!)?.run {
            walletService.removeWallet(id)
            println("Removed: ${asString()}")
        }
        return 0
    }
}

