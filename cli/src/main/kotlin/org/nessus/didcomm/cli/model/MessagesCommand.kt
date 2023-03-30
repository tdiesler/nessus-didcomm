package org.nessus.didcomm.cli.model

import id.walt.common.prettyPrint
import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.MessageExchange
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import kotlin.math.max

@Command(
    name = "message",
    description = ["Message related commands"])
class MessageCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List connection messages"])
    fun listMessages(
        @Option(names = ["--wallet"], description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["-n", "--tail"], description = ["Optional number of (tail) messages"], defaultValue = "12")
        msgCount: Int,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ): Int {
        val ctxWallet = cliService.findContextWallet(walletAlias)
        val pcon = ctxWallet?.currentConnection
        checkNotNull(pcon) { "No connection for: $walletAlias" }
        val mex = MessageExchange.findByVerkey(pcon.myVerkey)
        checkNotNull(mex) { "No message exchange for: ${pcon.myVerkey}" }

        val size = mex.messages.size
        val start = max(0, size - msgCount)
        val msgs = mex.messages.subList(start, size)
        if (verbose)
            echoList(msgs.map { it.prettyPrint() })
        else
            echoList(msgs.map { it.shortString() })
        return 0
    }

    @Command(name = "show", description = ["Show connection message"])
    fun showMessage(
        @Option(names = ["--wallet"], description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean,

        @Parameters(description = ["A message alias"])
        alias: String
    ): Int {
        val ctxWallet = cliService.findContextWallet(walletAlias)
        val pcon = ctxWallet?.currentConnection
        checkNotNull(pcon) { "No connection for: $walletAlias" }
        val mex = MessageExchange.findByVerkey(pcon.myVerkey)
        checkNotNull(mex) { "No message exchange for: ${pcon.myVerkey}" }

        mex.messages.firstOrNull {
            val candidates = listOf(it.id).map { c -> c.lowercase() }
            candidates.any { c -> c.startsWith(alias.lowercase()) }
        }?.let { msg ->
            if (verbose)
                echo(msg.prettyPrint())
            else
                echo(msg.shortString())
        }
        return 0
    }
}
