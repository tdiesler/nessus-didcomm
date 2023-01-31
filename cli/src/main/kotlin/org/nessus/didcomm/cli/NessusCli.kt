package org.nessus.didcomm.cli

import org.nessus.didcomm.cli.cmd.AbstractBaseCommand
import org.nessus.didcomm.cli.cmd.AgentCommand
import org.nessus.didcomm.cli.cmd.WalletCommand
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.ParameterException
import kotlin.system.exitProcess

@Command(
    name = "nessus-cli", description = ["Nessus DidComm CLI"], version = ["1.0"],
    mixinStandardHelpOptions = true,
    subcommands = [
        AgentCommand::class,
        WalletCommand::class,
        QuitCommand::class,
    ],
)

class NessusCli {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            NessusCli().execute("--help")
            exitProcess(NessusCli().repl())
        }
    }

    val cmdln
        get() = CommandLine(NessusCli())

    fun repl(): Int {
        while (true) {
            print("\n>> ")
            val line = readln()
            if (line in listOf("q", "quit"))
                break
            execute(line)
        }
        return 0
    }

    fun execute(args: String): Result<Any> {
        val toks = args.split(' ').toTypedArray()
        val result = runCatching {
            val parseResult = cmdln.parseArgs(*toks)
            cmdln.executionStrategy.execute(parseResult)
        }
        result.onFailure {
            when(val ex = result.exceptionOrNull()) {
                is ParameterException -> { cmdln.parameterExceptionHandler.handleParseException(ex, toks)}
                else -> ex?.run { System.err.println(ex.message) }
            }
        }
        return result
    }
}

@Command(name = "quit", description = ["Quit the CLI"])
class QuitCommand: AbstractBaseCommand()


