/*-
 * #%L
 * Nessus DIDComm :: CLI
 * %%
 * Copyright (C) 2022 - 2023 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
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
        RFC0048TrustPingCommand::class,
        RFC0095BasicMessageCommand::class,
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
        val toks = smartSplit(args).toTypedArray()
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

    private fun smartSplit(args: String): List<String> {
        var auxstr: String? = null
        val result = mutableListOf<String>()
        val startQuote = { t: String -> t.startsWith("'") || t.startsWith('"') }
        val endQuote = { t: String -> t.endsWith("'") || t.endsWith('"') }
        args.split(' ').forEach {
            when {
                startQuote(it) -> {
                    auxstr = it.drop(1)
                }
                endQuote(it) -> {
                    result.add("$auxstr $it".dropLast(1))
                    auxstr = null
                }
                else -> {
                    when {
                        auxstr != null -> { auxstr += " $it" }
                        else -> { result.add(it) }
                    }
                }
            }
        }
        return result.toList()
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


