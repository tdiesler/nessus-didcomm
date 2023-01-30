package org.nessus.didcomm.cli

import org.nessus.didcomm.cli.cmd.BaseCommand
import org.nessus.didcomm.cli.cmd.WalletCommand
import picocli.CommandLine
import picocli.CommandLine.Command
import kotlin.system.exitProcess

@Command(
    name = "nessus-cli", description = ["Nessus DidComm CLI"],
    version = ["1.0"],
    subcommands = [
        WalletCommand::class,
        QuitCommand::class,
    ],
    mixinStandardHelpOptions = true,
)

class NessusCli {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            exitProcess(NessusCli().repl())
        }
        internal var cmdln = CommandLine(NessusCli())
        internal var inputTokens: List<String> = listOf()
    }

    fun repl(): Int {
        cmdln.execute("--help")
        while (true) {
            print("\n>> ")
            val line = readln()
            if (line in listOf("q", "quit"))
                break
            cmdln = CommandLine(NessusCli())
            inputTokens = line.split(' ')
            runCatching {
                cmdln.execute(*inputTokens.toTypedArray())
            }
        }
        return 0
    }
}

@Command(name = "quit", description = ["Quit the CLI"])
class QuitCommand: BaseCommand()


