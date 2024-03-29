package org.nessus.didcomm.cli.model

import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "invitation",
    description = ["Invitation related commands"],
    mixinStandardHelpOptions = true,
    subcommands = [
        InvitationListCommand::class,
        InvitationShowCommand::class,
    ])
class InvitationCommands

/**
 * Common Invitation Options
 */
open class AbstractInvitationCommand: AbstractBaseCommand() {

    @Option(names = ["-w", "--wallet"], scope = INHERIT, paramLabel = "wallet", description = ["Optional wallet alias"])
    var walletAlias: String? = null

    @Option(names = ["-v", "--verbose"], scope = INHERIT, description = ["Verbose terminal output"])
    var verbose: Boolean = false

    fun findInvitations(wallet: Wallet, alias: String?): List<Invitation> {
        return wallet.invitations.filter {
            val candidates = listOf(it.id, it.invitationKey()).map { c -> c.lowercase() }
            candidates.any { c -> alias == null || c.startsWith(alias.lowercase()) }
        }
    }
}

@Command(name = "list", description = ["List available Invitations"], mixinStandardHelpOptions = true)
class InvitationListCommand: AbstractInvitationCommand() {

    @Option(names = ["--alias"], description = ["Optional Invitation alias"])
    var alias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val invis = findInvitations(ctxWallet, alias)
        if (verbose)
            echoList(invis.map { it.encodeJson(true) })
        else
            echoList(invis.map { it.shortString() })
        return 0
    }
}

@Command(name = "show", description = ["Show Invitation details"], mixinStandardHelpOptions = true)
class InvitationShowCommand: AbstractInvitationCommand() {

    @Option(names = ["--alias"], description = ["Optional Invitation alias"])
    var alias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        if (alias == null) {
            cliService.findContextInvitation()?.also { alias = it.id }
        }
        findInvitations(ctxWallet, alias).firstOrNull()?.also {
            if (verbose)
                echo(it.encodeJson(true))
            else
                echo(it.shortString())

        }
        return 0
    }
}
