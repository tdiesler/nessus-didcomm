package org.nessus.didcomm.cli.cmd

import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.util.concurrent.Callable

fun Wallet.displayString(): String {
    return "$name [agent=${agentType.value}, url=$endpointUrl]"
}

@Command(
    name = "wallet",
    description = ["Wallet related commands"],
    subcommands = [
        WalletCreate::class,
        WalletList::class,
        WalletRemove::class,
    ]
)
class WalletCommand: BaseCommand()

@Command(name = "create")
class WalletCreate: BaseCommand(), Callable<Int> {

    @Option(names = ["-n", "--name" ], required = true, description = ["The wallet name"])
    var name: String? = null

    @Option(names = ["-t", "--type" ], description = ["The agent type (default=Nessus)"], defaultValue = "Nessus")
    var type: String? = null

    override fun call(): Int {
        val wallet = Wallet.Builder(name!!)
            .agentType(AgentType.fromValue(type!!))
            .build()
        println("Created: ${wallet.displayString()}")
        return 0
    }
}

@Command(name = "list")
class WalletList: BaseCommand(), Callable<Int> {

    override fun call(): Int {
        walletService.listWallets().forEach {
            println( it.displayString() )
        }
        return 0
    }
}

@Command(name = "remove")
class WalletRemove: BaseCommand(), Callable<Int> {

    @Option(names = ["-n", "--name" ], required = true, description = ["The wallet name"])
    var name: String? = null

    override fun call(): Int {
        walletService.findByName(name!!)?.run {
            walletService.removeWallet(id)
            println("Removed: ${displayString()}")
        }
        return 0
    }
}

