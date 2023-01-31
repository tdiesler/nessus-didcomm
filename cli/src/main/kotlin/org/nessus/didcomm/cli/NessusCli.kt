package org.nessus.didcomm.cli

import org.nessus.didcomm.cli.cmd.*
import org.nessus.didcomm.service.ServiceMatrixLoader
import picocli.CommandLine
import picocli.CommandLine.*
import kotlin.system.exitProcess

@Command(
    name = "nessus-cli", description = ["Nessus DidComm CLI"], version = ["1.0"],
    mixinStandardHelpOptions = true,
    subcommands = [
        AgentCommands::class,
        RFC0023Commands::class,
        RFC0434Commands::class,
        WalletCommands::class,
        QuitCommand::class,
    ],
)

class NessusCli {

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            ServiceMatrixLoader.loadServiceDefinitions()
            NessusCli().execute("--help")
            exitProcess(NessusCli().repl())
        }
        val defaultCommandLine get() = CommandLine(NessusCli())
    }

    fun repl(): Int {
        while (true) {
            print("\n>> ")
            val line = readln()
            if (line in listOf("q", "quit"))
                break
            execute(line, replCommandLine())
        }
        return 0
    }

    fun execute(args: String, cmdLine: CommandLine? = null): Result<Any> {
        val cmdln = cmdLine ?: defaultCommandLine
        val toks = args.split(' ').toTypedArray()
        val parseResult = runCatching { cmdln.parseArgs(*toks) }
        parseResult.onFailure {
            val ex = parseResult.exceptionOrNull() as ParameterException
            cmdln.parameterExceptionHandler.handleParseException(ex, toks)
            return parseResult
        }
        val execResult = runCatching {
            cmdln.executionStrategy.execute(parseResult.getOrNull())
        }
        execResult.onFailure {
            val ex = execResult.exceptionOrNull() as ExecutionException
            cmdln.executionExceptionHandler.handleExecutionException(ex, cmdln, parseResult.getOrNull())
        }
        return execResult
    }

    // A CommandLine that doesn't throw ExecutionException
    private fun replCommandLine(): CommandLine {
        val cmdln = defaultCommandLine
        cmdln.executionExceptionHandler = IExecutionExceptionHandler { ex, _, _ ->
            val exitCode = 1
            ex.printStackTrace()
            exitCode
        }
        return cmdln
    }
}

@Command(name = "quit", description = ["Quit the CLI"])
class QuitCommand: AbstractBaseCommand()


