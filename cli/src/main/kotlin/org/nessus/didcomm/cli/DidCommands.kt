package org.nessus.didcomm.cli

import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.service.DidPeerOptions
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import picocli.CommandLine.ScopeType

@Command(
    name = "did",
    description = ["Did related commands"],
)
class DidCommands: AbstractBaseCommand() {

    @Option(names = ["--wallet"], scope = ScopeType.INHERIT, paramLabel = "wallet", description = ["Optional wallet alias"])
    var walletAlias: String? = null

    @Command(name = "list", description = ["List available Dids"])
    fun listDids(
        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ) {
        val ctxWallet = getContextWallet(walletAlias)
        ctxWallet.dids.forEachIndexed { idx, did ->
            if (verbose) echo("[$idx] " + did.encodeJson(true))
            else echo("[$idx] " + did.shortString())
        }
    }

    @Command(name = "show", description = ["Show Did details"])
    fun showDid(
        @Parameters(description = ["The did alias"])
        alias: String,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ) {
        findWalletAndDidFromAlias(walletAlias, alias).second?.also { did ->
            if (verbose) echoDidDoc(did)
            else echo(did.encodeJson(true))
        }
    }

    @Command(name = "create", description = ["Create a Did for the given wallet"])
    fun createDid(
        @Option(names = ["-m", "--method"], description = ["The Did method with url parameters (e.g. peer?algo=2)"], defaultValue = "key")
        method: String,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ) {

        fun parseMethodOptions(): Pair<String, Map<String, String>> {
            val toks = method.split('?')
            if (toks.size < 2) return Pair(toks[0], mapOf())
            val params = mutableMapOf<String, String>()
            toks[1].split('&').forEach { kv ->
                val (k, v) = kv.split('=')
                params[k] = v
            }
            return Pair(toks[0], params.toMap())
        }

        val ctxWallet = getContextWallet(walletAlias)
        val (methodName, didParams) = parseMethodOptions()
        val allowed = DidMethod.values().map { it.name.lowercase() }
        require(methodName in allowed) { "Invalid value for option '--method': expected one of $allowed" }

        val didMethod = DidMethod.fromValue(methodName)
        val didOptions = when (didMethod) {
            DidMethod.PEER -> {
                val numalgo = didParams["algo"]?.toInt() ?: 0
                val endpointUrl = didParams["url"] ?: ctxWallet.endpointUrl
                DidPeerOptions(numalgo, endpointUrl)
            }
            else -> null
        }

        val varKey = "${ctxWallet.name}.Did"
        val did = ctxWallet.createDid(didMethod, options = didOptions)
        cliService.putVar(varKey, did.uri)
        cliService.putContextDid(did)
        echo("$varKey=${did.uri}")
        if (verbose)
            echoDidDoc(did)
    }

    @Command(name = "remove", description = ["Remove a Did from the given wallet (tbd)"])
    fun removeDid(
//        @Parameters(description = ["The Did alias"])
//        alias: String?
    ) {
        TODO("RemoveDidCommand")
    }

    private fun echoDidDoc(did: Did) {
        echo(did.encodeJson(true))
        echo()
        val didDoc = didService.loadDidDocument(did.uri)
        echo("Did Document ...\n${didDoc.encodeJson(true)}")
    }
}
