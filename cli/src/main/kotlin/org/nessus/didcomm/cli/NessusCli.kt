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

import id.walt.common.resolveContent
import mu.KotlinLogging
import org.fusesource.jansi.AnsiConsole
import org.jline.console.CmdLine
import org.jline.console.impl.SystemRegistryImpl
import org.jline.console.impl.SystemRegistryImpl.UnknownCommandException
import org.jline.keymap.KeyMap
import org.jline.reader.Binding
import org.jline.reader.EOFError
import org.jline.reader.EndOfFileException
import org.jline.reader.LineReader
import org.jline.reader.LineReaderBuilder
import org.jline.reader.MaskingCallback
import org.jline.reader.ParsedLine
import org.jline.reader.Parser
import org.jline.reader.Parser.ParseContext
import org.jline.reader.Reference
import org.jline.reader.UserInterruptException
import org.jline.reader.impl.DefaultParser
import org.jline.terminal.Terminal
import org.jline.terminal.TerminalBuilder
import org.jline.widget.TailTipWidgets
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.protocol.MessageExchange.Companion.DID_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.ServiceMatrixLoader
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.IExecutionExceptionHandler
import picocli.CommandLine.ParameterException
import picocli.shell.jline3.PicocliCommands
import kotlin.system.exitProcess

@Command(
    name = "didcomm", description = ["Nessus DIDComm CLI"],
    mixinStandardHelpOptions = false,
    usageHelpWidth = 160,
    subcommands = [
        AgentCommands::class,
        ClearScreenCommand::class,
        ConnectionCommands::class,
        DidCommands::class,
        CommandsCommand::class,
        InvitationCommands::class,
        MessageCommands::class,
        RFC0048TrustPingCommand::class,
        RFC0095BasicMessageCommand::class,
        RFC0434Commands::class,
        RunScriptCommand::class,
        VariableCommands::class,
        VCCommands::class,
        WalletCommands::class,
    ]
)
class NessusCli {
    val log = KotlinLogging.logger { }

    companion object {

        @JvmStatic
        fun main(args: Array<String>) {
            ServiceMatrixLoader.loadServiceDefinitions()
            exitProcess(NessusCli().runTerminal(args))
        }

        val defaultCommandLine get() = run {
            val log = KotlinLogging.logger { }
            val cmdln = CommandLine(NessusCli())
            cmdln.executionExceptionHandler = IExecutionExceptionHandler { ex, _, _ ->
                log.error(ex) { }
                println(ex.message)
                1
            }
            cmdln
        }
    }

    val cliService get() = CLIService.getService()

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
            val pres = parseResult.getOrNull()
            val exitCode = cmdln.executionStrategy.execute(pres)
            check(exitCode == 0) { "Unexpected exit code: $exitCode" }
        }
        execResult.onFailure {
            cmdln.executionExceptionHandler.handleExecutionException(it as Exception, cmdln, parseResult.getOrNull())
        }
        return execResult
    }

    // Private ---------------------------------------------------------------------------------------------------------

    internal class CommandsFactory(private val terminal: Terminal) : CommandLine.IFactory {

        @Suppress("UNCHECKED_CAST")
        override fun <K> create(clazz: Class<K>): K {
            return when(clazz) {
                ClearScreenCommand::class.java -> ClearScreenCommand(terminal) as K
                else -> CommandLine.defaultFactory().create(clazz) as K
            }
        }
    }

    private fun runTerminal(args: Array<String>): Int {
        val version = resolveContent("class:version.txt")
        AnsiConsole.systemInstall()
        try {
            TerminalBuilder.builder().build().use { terminal ->

                // Set up picocli commands
                val factory = CommandsFactory(terminal)
                val cmdln = CommandLine(NessusCli(), factory)
                val commands = object : PicocliCommands(cmdln) {
                    override fun name(): String {
                        return "Commands"
                    }
                }

                val topSpec = cmdln.commandSpec
                println(topSpec.usageMessage().description()[0])
                println("Version: $version")

                class MultilineParser : Parser {
                    override fun parse(line: String, cursor: Int, context: ParseContext?): ParsedLine {
                        if (ParseContext.ACCEPT_LINE == context && line.endsWith("\\"))
                            throw EOFError(-1, cursor, "Multiline")
                        return DefaultParser().parse(line.replace("\\\n", ""), cursor, context)
                    }
                }

                val parser = MultilineParser()
                val systemRegistry = SystemRegistryImpl(parser, terminal, null, null)
                systemRegistry.setCommandRegistries(commands)

                val reader: LineReader = LineReaderBuilder.builder()
                    .variable(LineReader.LIST_MAX, 50) // max tab completion candidates
                    .completer(systemRegistry.completer())
                    .terminal(terminal)
                    .parser(parser)
                    .build()

                val commandDescription = { cl: CmdLine -> systemRegistry.commandDescription(cl) }
                TailTipWidgets(reader, commandDescription, 5, TailTipWidgets.TipType.COMPLETER).disable()
                val keyMap = reader.keyMaps["main"] as KeyMap<Binding>
                keyMap.bind(Reference("tailtip-toggle"), KeyMap.alt("s"))

                fun prompt(): String {
                    val ctxWallet = cliService.findContextWallet()
                    return ctxWallet?.run { "${name}>> " } ?: ">> "
                }

                fun rightPrompt(): String? {
                    val ctxConn = cliService.findContextConnection()
                    if (ctxConn?.state == ConnectionState.ACTIVE) {
                        return "\n[Conn:${ctxConn.id.substring(0..6)}]"
                    }
                    cliService.getAttachment(DID_ATTACHMENT_KEY)?.run {
                        return "\n[${uri.substring(0.."did:$method:".length + 6)}]"
                    }
                    cliService.getAttachment(INVITATION_ATTACHMENT_KEY)?.run {
                        return "\n[Invi:${invitationKey().substring(0..6)}]"
                    }
                    return null
                }

                if (args.isNotEmpty()) {
                    check(args.size == 1) { "Multiple arguments not supported: $args" }
                    val command = "run ${args[0]}"
                    println("\n${prompt()}$command")
                    systemRegistry.execute(command)
                }

                // Start the shell and process input until the user quits with Ctrl-D
                while (true) {
                    try {
                        systemRegistry.cleanUp()
                        val line = reader.readLine("\n${prompt()}", rightPrompt(), null as MaskingCallback?, null)
                        systemRegistry.execute(line)
                    } catch (e: Exception) {
                        when(e) {
                            is UnknownCommandException -> { println(e.message) }
                            is UserInterruptException -> {}
                            is EndOfFileException -> return 0
                        }
                    }
                }
            }
        } finally {
            AnsiConsole.systemUninstall()
        }
    }

    private fun smartSplit(args: String): List<String> {
        val result = mutableListOf<String>()
        val option = Regex("^-(.+)")
        val quoteStart = Regex("^'(.+)")
        val quoteEnd = Regex("(.+)'$")
        val toks = args.split(Regex("\\s")).toMutableList()
        while (toks.isNotEmpty()) {
            val tok = toks.removeAt(0)
            if (option.matches(tok)) {
                result.add(tok)
                val buffer = StringBuffer()
                while(toks.isNotEmpty() && !option.matches(toks[0])) {
                    val aux = toks.removeAt(0)
                    buffer.append(" $aux")
                }
                if (buffer.isNotEmpty())
                    result.add("$buffer".trim())
            } else if (quoteStart.matches(tok)) {
                val buffer = StringBuffer(tok.drop(1))
                while(!quoteEnd.matches(toks[0])) {
                    val aux = toks.removeAt(0)
                    buffer.append(" $aux")
                }
                val aux = toks.removeAt(0)
                buffer.append(" $aux".dropLast(1))
                result.add("$buffer")
            } else {
                result.add(tok)
            }
        }
        log.debug { "Command split: $result" }
        return result.toList()
    }
}


