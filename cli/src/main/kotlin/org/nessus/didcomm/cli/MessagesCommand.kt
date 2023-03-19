package org.nessus.didcomm.cli

import id.walt.common.prettyPrint
import org.nessus.didcomm.protocol.MessageExchange
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import kotlin.math.max

@Command(
    name = "message",
    description = ["Message related commands"],
    subcommands = [
        MessageListCommand::class,
        MessageShowCommand::class,
    ])
class MessageCommands

open class AbstractMessageCommand: AbstractBaseCommand() {

    @Option(names = ["--pcon"], description = ["Optional connection alias"])
    var conAlias: String? = null

    @Option(names = ["--wallet"], description = ["Optional wallet alias"])
    var walletAlias: String? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false
}

@Command(
    name = "list",
    description = ["List connection messages"])
class MessageListCommand: AbstractMessageCommand() {

    @Option(names = ["-n", "--tail"], description = ["Optional number of (tail) messages"])
    var msgCount: Int = 12

    override fun call(): Int {
        val pcon = getContextConnection(walletAlias, conAlias)
        val mex = MessageExchange.findByVerkey(pcon.myVerkey)
        val size = mex.messages.size
        val start = max(0, size - msgCount)
        val msgs = mex.messages.subList(start, size)
        if (verbose)
            echoList(msgs.map { it.prettyPrint() })
        else
            echoList(msgs.map { it.shortString() })
        return 0
    }
}

@Command(
    name = "show",
    description = ["Show connection message"])
class MessageShowCommand: AbstractMessageCommand() {

    @Parameters(description = ["A message alias"])
    var alias: String? = null

    override fun call(): Int {
        val pcon = getContextConnection(walletAlias, conAlias)
        val mex = MessageExchange.findByVerkey(pcon.myVerkey)
        mex.messages.firstOrNull {
            val candidates = listOf(it.id).map { c -> c.lowercase() }
            candidates.any { c -> c.startsWith(alias!!.lowercase()) }
        }?.let { msg ->
            if (verbose)
                echo(msg.prettyPrint())
            else
                echo(msg.shortString())
        }
        return 0
    }
}