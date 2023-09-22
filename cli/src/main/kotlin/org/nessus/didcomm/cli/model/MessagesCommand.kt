package org.nessus.didcomm.cli.model

import id.walt.common.prettyPrint
import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.model.MessageDirection
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import kotlin.math.max

@Command(
    name = "message",
    description = ["Message related commands"],
    mixinStandardHelpOptions = true)
class MessageCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List connection messages"], mixinStandardHelpOptions = true)
    fun listMessages(
        @Option(names = ["-w", "--wallet"], description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["-n", "--tail"], description = ["Optional number of (tail) messages"], defaultValue = "12")
        msgCount: Int,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ): Int {
        val ctxWallet = cliService.findContextWallet(walletAlias)

        val pcon = ctxWallet?.currentConnection
        if (pcon == null) {
            echo("No connection for: ${ctxWallet?.alias}")
            return 0
        }

        val mex = MessageExchange.findByConnectionId(pcon.id)
        if (mex == null) {
            echo("No message exchange for: ${pcon.shortString()}")
            return 0
        }

        val size = mex.messages.size
        val start = max(0, size - msgCount)
        val msgs = mex.messages.subList(start, size)
        val idxAndDirection = { i: Int, m: EndpointMessage -> when(m.messageDirection) {
            MessageDirection.IN -> "[$i] <<"
            MessageDirection.OUT -> "[$i] >>"
            else -> "[$i] .."
        }}
        if (verbose)
            echoList(msgs.mapIndexed { idx, epm -> "${idxAndDirection(idx, epm)} ${epm.prettyPrint()}" })
        else
            echoList(msgs.mapIndexed { idx, epm -> "${idxAndDirection(idx, epm)} ${epm.shortString()}" })
        return 0
    }

    @Command(name = "show", description = ["Show connection message"], mixinStandardHelpOptions = true)
    fun showMessage(
        @Option(names = ["-w", "--wallet"], description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean,

        @Parameters(description = ["A message alias"])
        alias: String
    ): Int {
        val ctxWallet = cliService.findContextWallet(walletAlias)
        val pcon = ctxWallet?.currentConnection
        checkNotNull(pcon) { "No connection for: $walletAlias" }
        val mex = MessageExchange.findByConnectionId(pcon.id)
        checkNotNull(mex) { "No message exchange for: ${pcon.shortString()}" }

        val msg = alias.toIntOrNull()?.let { idx -> mex.messages[idx] }
            ?: mex.messages.firstOrNull { m -> m.id.lowercase().startsWith(alias.lowercase()) }

        if (msg != null) {
            if (verbose)
                echo(msg.prettyPrint())
            else
                echo(msg.shortString())
        } else {
            echo("No message for: $alias")
        }
        return 0
    }
}
