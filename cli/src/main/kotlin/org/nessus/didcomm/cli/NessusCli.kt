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

import org.nessus.didcomm.cli.cmd.AgentCommands
import org.nessus.didcomm.cli.cmd.QuitCommand
import org.nessus.didcomm.cli.cmd.RFC0023Commands
import org.nessus.didcomm.cli.cmd.RFC0048TrustPingCommand
import org.nessus.didcomm.cli.cmd.RFC0095BasicMessageCommand
import org.nessus.didcomm.cli.cmd.RFC0434Commands
import org.nessus.didcomm.cli.cmd.ShowCommands
import org.nessus.didcomm.cli.cmd.WalletCommands
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.service.ServiceMatrixLoader
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.ExecutionException
import picocli.CommandLine.Help.Column
import picocli.CommandLine.Help.TextTable
import picocli.CommandLine.IExecutionExceptionHandler
import picocli.CommandLine.IHelpSectionRenderer
import picocli.CommandLine.Model
import picocli.CommandLine.Model.UsageMessageSpec.SECTION_KEY_COMMAND_LIST
import picocli.CommandLine.ParameterException
import kotlin.system.exitProcess

@Command(
    name = "didcomm", description = ["Nessus DIDComm-V2 CLI"], version = ["1.0"],
    mixinStandardHelpOptions = true,
    usageHelpWidth = 160,
    subcommands = [
        AgentCommands::class,
        RFC0023Commands::class,
        RFC0048TrustPingCommand::class,
        RFC0095BasicMessageCommand::class,
        RFC0434Commands::class,
        ShowCommands::class,
        WalletCommands::class,
        QuitCommand::class,
    ],
)

class NessusCli {

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            ServiceMatrixLoader.loadServiceDefinitions()
            exitProcess(NessusCli().repl())
        }

        val defaultCommandLine: CommandLine
            get() = run {
                val cmdln = CommandLine(NessusCli())
                cmdln.helpSectionMap[SECTION_KEY_COMMAND_LIST] = CommandListRenderer();
                cmdln
            }
    }

    val cliService get() = CLIService.getService()

    fun repl(): Int {
        while (true) {
            showPrompt()
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

    // Private ---------------------------------------------------------------------------------------------------------

    internal class CommandListRenderer : IHelpSectionRenderer {

        // https://github.com/remkop/picocli/blob/main/picocli-examples/src/main/java/picocli/examples/customhelp

        override fun render(help: CommandLine.Help): String {

            val spec: Model.CommandSpec = help.commandSpec()

            // prepare layout: two columns
            // the left column overflows, the right column wraps if text is too long
            val columnWidth = 25
            val textTable: TextTable = TextTable.forColumns(
                help.colorScheme(),
                Column(25, 2, Column.Overflow.SPAN),
                Column(80, 2, Column.Overflow.SPAN)
            )
            textTable.isAdjustLineBreaksForWideCJKCharacters = spec.usageMessage().adjustLineBreaksForWideCJKCharacters()
            for (subcommand in spec.subcommands().values) {
                addHierarchy(subcommand, textTable, "")
                textTable.addRowValues("")
            }
            return textTable.toString()
        }

        private fun addHierarchy(cmd: CommandLine, textTable: TextTable, indent: String) {
            // create comma-separated list of command name and aliases
            var names = cmd.commandSpec.names().toString()
            names = names.substring(1, names.length - 1) // remove leading '[' and trailing ']'

            // command description is taken from header or description
            val description = description(cmd.commandSpec.usageMessage())

            // add a line for this command to the layout
            textTable.addRowValues(indent + names, description)

            // add its subcommands (if any)
            for (sub in cmd.subcommands.values) {
                addHierarchy(sub, textTable, "$indent  ")
            }
        }

        private fun description(usageMessage: Model.UsageMessageSpec): String {
            if (usageMessage.header().isNotEmpty()) {
                return usageMessage.header().get(0)
            }
            return if (usageMessage.description().isNotEmpty()) {
                usageMessage.description().get(0)
            } else ""
        }
    }

    private fun showPrompt() {
        val wallet = cliService.getAttachment(WALLET_ATTACHMENT_KEY)
        val prompt = wallet?.run { "${name}>>" } ?: ">>"
        print("\n$prompt ")
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


