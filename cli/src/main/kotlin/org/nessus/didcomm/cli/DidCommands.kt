package org.nessus.didcomm.cli

import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "did",
    description = ["Did related commands"],
    subcommands = [
        DidCreateCommand::class,
        DidRemoveCommand::class,
        DidListCommand::class,
        DidShowCommand::class,
    ])
class DidCommands

/**
 * Common Did Options
 */
open class AbstractDidCommand: AbstractBaseCommand() {

    @Option(names = ["--wallet"], scope = INHERIT, paramLabel = "wallet", description = ["Optional wallet alias"])
    var walletAlias: String? = null

    @Option(names = ["-v", "--verbose"], scope = INHERIT, description = ["Verbose terminal output"])
    var verbose: Boolean = false

    fun findDids(wallet: Wallet, alias: String?): List<Did> {
        return wallet.dids.filter {
            val candidates = listOf(it.id, it.uri, it.verkey).map { c -> c.lowercase() }
            candidates.any { c -> alias == null || c.startsWith(alias.lowercase()) }
        }
    }

    fun echoDid(did: Did, showDoc: Boolean = false) {
        if (verbose) {
            echo(did.uri)
            echo(did.encodeJson(true))
            if (showDoc && did.method != DidMethod.SOV) {
                echo()
                val didDoc = didService.loadDidDocument(did.uri)
                echo("Did Document ...\n${didDoc.encodeJson(true)}")
            }
        } else {
            echo(did.uri)
        }
    }
}

@Command(name = "create", description = ["Create a Did for the given wallet"])
class DidCreateCommand: AbstractDidCommand() {

    @Option(names = ["-m", "--method"], description = ["The Did method"])
    var method = "key"

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val allowed = DidMethod.values().map { it.name.lowercase() }
        require(method in allowed) { "Invalid value for option '--method': expected one of $allowed" }
        val did = ctxWallet.createDid(DidMethod.fromValue(method))
        cliService.putContextDid(did)
        echoDid(did, true)
        return 0
    }
}

@Command(name = "remove", description = ["Remove a Did from the given wallet (tbd)"])
class DidRemoveCommand: AbstractDidCommand() {

    @Parameters(description = ["The Did alias"])
    var alias: String? = null

    override fun call(): Int {
        TODO("RemoveDidCommand")
    }
}

@Command(name = "list", description = ["List available Dids"])
class DidListCommand: AbstractDidCommand() {

    @Option(names = ["--alias"], description = ["Optional Did alias"])
    var alias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val dids = findDids(ctxWallet, alias)
        if (verbose)
            echo(dids.map { it.encodeJson(true) })
        else
            echo(dids.map { it.shortString() })
        return 0
    }
}

@Command(name = "show", description = ["Show Did details"])
class DidShowCommand: AbstractDidCommand() {

    @Option(names = ["--alias"], description = ["Optional Did alias"])
    var alias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        findDids(ctxWallet, alias).firstOrNull()?.let { did ->
            echoDid(did, true)
        }
        return 0
    }
}
