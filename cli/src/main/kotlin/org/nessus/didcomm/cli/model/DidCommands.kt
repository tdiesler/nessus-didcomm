package org.nessus.didcomm.cli.model

import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.service.DidPeerOptions
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
    name = "did",
    description = ["Did related commands"],
    mixinStandardHelpOptions = true,
)
class DidCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List available Dids"], mixinStandardHelpOptions = true)
    fun listDids(
        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ) {
        val ctxWallet = getContextWallet(walletAlias)
        ctxWallet.dids.forEachIndexed { idx, did ->
            if (verbose) echo("[$idx] " + did.encodeJson(true))
            else echo("[$idx] " + did.shortString())
        }
    }

    @Command(name = "show", description = ["Show Did details"], mixinStandardHelpOptions = true)
    fun showDid(
        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Parameters(description = ["The did alias"])
        didAlias: String,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ) {
        findWalletAndDidFromAlias(walletAlias, didAlias).second?.also { did ->
            if (verbose) echoDidDoc(did)
            else echo(did.encodeJson(true))
        }
    }

    @Command(name = "create", description = ["Create a Did for the given wallet"], mixinStandardHelpOptions = true)
    fun createDid(
        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["-m", "--method"], description = ["The Did method with url parameters (e.g. peer?numalgo=2)"], defaultValue = "key")
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
                val numalgo = didParams["numalgo"]?.toInt() ?: 0
                val endpointUrl = didParams["url"] ?: ctxWallet.endpointUrl
                DidPeerOptions(numalgo, endpointUrl)
            }
            else -> null
        }

        val did = ctxWallet.createDid(didMethod, options = didOptions)
        cliService.putContextDid(ctxWallet.name, did)
        if (verbose)
            echoDidDoc(did)
    }

    @Command(name = "set-public", description = ["Set the public Did"], mixinStandardHelpOptions = true)
    fun setPublic(
        @Parameters(description = ["The did alias"])
        didAlias: String,
    ) {
        val (wallet, publicDid) = findWalletAndDidFromAlias(didAlias = didAlias)
        checkNotNull(publicDid) { "CAnnot find Did for: $didAlias" }
        checkNotNull(wallet) { "No target wallet" }
        wallet.publicDid = publicDid
    }

    @Command(name = "remove", description = ["Remove a Did from the given wallet (tbd)"], mixinStandardHelpOptions = true)
    fun removeDid(
//        @Parameters(description = ["The Did alias"])
//        alias: String?
    ) {
        TODO("RemoveDidCommand")
    }

    private fun echoDidDoc(did: Did) {
        echo(did.encodeJson(true))
        echo()
        val didDoc = didService.loadDidDoc(did.uri)
        echo("Did Document ...\n${didDoc.encodeJson(true)}")
    }
}
