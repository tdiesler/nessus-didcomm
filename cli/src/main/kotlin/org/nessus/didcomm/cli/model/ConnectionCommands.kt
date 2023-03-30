package org.nessus.didcomm.cli.model

import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
    name = "connection",
    description = ["Connection related commands"],
    mixinStandardHelpOptions = true)
class ConnectionCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List available Connections"], mixinStandardHelpOptions = true)
    fun listConnections(
        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["--alias"], description = ["Optional Connection alias"])
        alias: String?,
        
        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean,
    ): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val pcons = findConnections(ctxWallet, alias)
        if (verbose)
            echoList(pcons.map { it.encodeJson(true) })
        else
            echoList(pcons.map { it.shortString() })
        return 0
    }

    @Command(name = "show", description = ["Show Connection details"], mixinStandardHelpOptions = true)
    fun showConnection(
        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["--alias"], description = ["Optional Connection alias"])
        alias: String?,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean,
    ): Int {
        val ctxWallet = getContextWallet(walletAlias)
        findConnections(ctxWallet, alias).firstOrNull()?.also {
            if (verbose)
                echo(it.encodeJson(true))
            else
                echo(it.shortString())

        }
        return 0
    }

    @Command(name = "switch", description = ["Switch the current Connection"], mixinStandardHelpOptions = true)
    fun switchConnection(
        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Parameters(description = ["The Connection alias (e.g. Acme-Alice)"])
        alias: String,
    ): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val pcon = ctxWallet.findConnection { c -> c.alias.lowercase().startsWith(alias.lowercase()) && c.state == ConnectionState.ACTIVE }
        if (pcon != null) {
            ctxWallet.currentConnection = pcon
            echo("Switched to: ${pcon.shortString()}")
        } else {
            echo("Cannot switch to: $alias")
        }
        return 0
    }

    private fun findConnections(wallet: Wallet, alias: String?): List<Connection> {
        return wallet.connections.filter {
            val candidates = listOf(it.id, it.alias).map { c -> c.lowercase() }
            candidates.any { c -> alias == null || c.startsWith(alias.lowercase()) }
        }
    }
}
