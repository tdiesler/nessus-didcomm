package org.nessus.didcomm.cli

import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "connection",
    description = ["Connection related commands"],
    subcommands = [
        ConnectionListCommand::class,
        ConnectionShowCommand::class,
    ])
class ConnectionCommands

/**
 * Common Connection Options
 */
open class AbstractConnectionCommand: AbstractBaseCommand() {

    @Option(names = ["--wallet"], scope = INHERIT, paramLabel = "wallet", description = ["Optional wallet alias"])
    var walletAlias: String? = null

    @Option(names = ["-v", "--verbose"], scope = INHERIT, description = ["Verbose terminal output"])
    var verbose: Boolean = false

    fun findConnections(wallet: Wallet, alias: String?): List<Connection> {
        return wallet.connections.filter {
            val candidates = listOf(it.id, it.alias).map { c -> c.lowercase() }
            candidates.any { c -> alias == null || c.startsWith(alias.lowercase()) }
        }
    }
}

@Command(name = "list", description = ["List available Connections"])
class ConnectionListCommand: AbstractConnectionCommand() {

    @Option(names = ["--alias"], description = ["Optional Connection alias"])
    var alias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val pcons = findConnections(ctxWallet, alias)
        if (verbose)
            echo(pcons.map { it.encodeJson(true) })
        else
            echo(pcons.map { it.shortString() })
        return 0
    }
}

@Command(name = "show", description = ["Show Connection details"])
class ConnectionShowCommand: AbstractConnectionCommand() {

    @Option(names = ["--alias"], description = ["Optional Connection alias"])
    var alias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        findConnections(ctxWallet, alias).firstOrNull()?.also {
            if (verbose)
                echo(it.encodeJson(true))
            else
                echo(it.shortString())

        }
        return 0
    }
}
