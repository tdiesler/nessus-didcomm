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
import org.nessus.didcomm.cli.model.ConnectionCommands
import org.nessus.didcomm.cli.model.DidCommands
import org.nessus.didcomm.cli.model.InvitationCommands
import org.nessus.didcomm.cli.model.MessageCommands
import org.nessus.didcomm.cli.model.WalletCommands
import org.nessus.didcomm.cli.protocol.ProtocolCommands
import org.nessus.didcomm.cli.protocol.VerifiableCredentialCommands
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.MessageExchange.Companion.DID_ATTACHMENT_KEY
import org.nessus.didcomm.model.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.ServiceMatrixLoader
import org.nessus.didcomm.util.Holder
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.IExecutionExceptionHandler
import picocli.CommandLine.ParameterException
import picocli.shell.jline3.PicocliCommands
import kotlin.system.exitProcess

@Command(
    name = "didcomm", description = ["Nessus DIDComm CLI"],
    mixinStandardHelpOptions = true,
    usageHelpWidth = 160,
    subcommands = [
        AgentCommands::class,
        ClearScreenCommand::class,
        ConnectionCommands::class,
        HelpTreeCommand::class,
        DidCommands::class,
        InvitationCommands::class,
        MessageCommands::class,
        ProtocolCommands::class,
        RunCommand::class,
        VarCommands::class,
        VerifiableCredentialCommands::class,
        WalletCommands::class,
    ]
)
class NessusCli {

    companion object {
        val log = KotlinLogging.logger { }

        val headless get() = _headless.value == true

        @JvmStatic
        fun main(args: Array<String>) {
            val nessusCli = NessusCli()

            ServiceMatrixLoader.loadServiceDefinitions()

            val command = args.joinToString(separator = " ")
            _headless.value = command.startsWith("run --headless")

            if (args.isNotEmpty()) {
                nessusCli.execute(command).onFailure {
                    when(it) {
                        is RuntimeException -> throw it
                        else -> throw IllegalStateException(it)
                    }
                }
            }

            if (!headless)
                exitProcess(nessusCli.runTerminal())
        }

        val defaultCommandLine get() = run {
            val cmdln = CommandLine(NessusCli())
            cmdln.executionExceptionHandler = IExecutionExceptionHandler { ex, _, _ ->
                log.error(ex) { }
                println(ex.message)
                1
            }
            cmdln
        }

        private val _headless = Holder(false)
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

    private fun runTerminal(): Int {
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
                println("\n" + topSpec.usageMessage().description()[0])
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
                    return ctxWallet?.run { "${alias}>> " } ?: ">> "
                }

                fun rightPrompt(): String? {
                    val ctxWallet = cliService.findContextWallet()
                    val ctxConn = ctxWallet?.currentConnection
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

                // Start the shell and process input until the user quits with Ctrl-D
                while (true) {
                    try {
                        systemRegistry.cleanUp()
                        val line = reader.readLine("\n${prompt()}", rightPrompt(), null as MaskingCallback?, null)
                        systemRegistry.execute(cliService.replaceVars(line))
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

    fun smartSplit(args: String): List<String> {
        val result = mutableListOf<String>()
        val shortOption = Regex("^-[a-z|-]+")
        val longOption = Regex("^--[a-z|-]+")
        val longOptionEqual = Regex("^--[a-z|-]+(=(.+))")
        val singleQuoteStart = Regex("^'(.+)")
        val singleQuoteEnd = Regex("(.+)'$")
        val doubleQuoteStart = Regex("^\"(.+)")
        val doubleQuoteEnd = Regex("(.+)\"$")
        val toks = args.split(Regex("\\s")).toMutableList()
        val option = { t: String -> shortOption.matches(t) || longOption.matches(t) || longOptionEqual.matches(t)}
        while (toks.isNotEmpty()) {
            val tok = toks.removeAt(0)
            if (option(tok)) {
                val buffer = StringBuffer()
                if (longOptionEqual.matches(tok)) {
                    val sub = tok.split("=", limit = 2)
                    check(sub.size == 2) { "Unexpected sub token: $sub" }
                    result.add(sub[0])
                    buffer.append(sub[1])
                } else {
                    result.add(tok)
                }
                while(toks.isNotEmpty() && !option(toks[0])) {
                    val aux = toks.removeAt(0)
                    buffer.append(" $aux")
                }
                if (buffer.isNotEmpty())
                    result.add("$buffer".trim())
            } else if (singleQuoteStart.matches(tok)) {
                val buffer = StringBuffer(tok.drop(1))
                while(!singleQuoteEnd.matches(toks[0])) {
                    val aux = toks.removeAt(0)
                    buffer.append(" $aux")
                }
                val aux = toks.removeAt(0)
                buffer.append(" $aux".dropLast(1))
                result.add("$buffer")
            } else if (doubleQuoteStart.matches(tok)) {
                val buffer = StringBuffer(tok.drop(1))
                while(!doubleQuoteEnd.matches(toks[0])) {
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


