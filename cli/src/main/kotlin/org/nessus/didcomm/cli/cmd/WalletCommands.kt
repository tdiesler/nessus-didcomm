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
package org.nessus.didcomm.cli.cmd

import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.toWalletModel
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import kotlin.math.max

@Command(
    name = "wallet",
    description = ["Show available wallets and details"],
    subcommands = [
        WalletCreateCommand::class,
        WalletRemoveCommand::class,
        WalletConnectionCommand::class,
        WalletDidCommand::class,
        WalletInvitationCommand::class,
        WalletMessagesCommand::class,
        WalletUseCommand::class,
    ]
)
class WalletCommands: AbstractBaseCommand() {

    @Option(names = ["--alias"], description = ["Optional wallet alias"])
    var alias: String? = null

    @Option(names = ["--all"], description = ["Flag to show all wallets"])
    var all: Boolean = false

    /**
     * Show wallet details
     */
    override fun call(): Int {
        val ctxWallet = cliService.findContextWallet()
        val walletModels = when {
            all || ctxWallet == null -> modelService.wallets
            else -> listOf(getContextWallet(alias))
        }
        if (verbose)
            printResult("", walletModels)
        else
            printResult("", walletModels.map { it.shortString() })
        return 0
    }
}


@Command(name = "create", description = ["Create a wallet for a given agent"])
class WalletCreateCommand: AbstractBaseCommand() {

    @Option(names = ["-n", "--name"], required = true, description = ["The wallet name"])
    var name: String? = null

    @Option(names = ["-a", "--agent"], description = ["The agent type (default=Nessus)"], defaultValue = "Nessus")
    var agent: String? = null

    override fun call(): Int {
        val wallet = Wallet.Builder(name!!)
            .agentType(AgentType.fromValue(agent!!))
            .build()
        val walletModel = wallet.toWalletModel()
        cliService.putContextWallet(walletModel)
        val header = "Wallet created: "
        if (verbose)
            printResult(header, listOf(walletModel))
        else
            printResult(header, listOf(walletModel.shortString()))
        return 0
    }
}

@Command(name = "remove", description = ["Remove and delete a given wallet"])
class WalletRemoveCommand: AbstractBaseCommand() {

    @Option(names = ["--alias"], description = ["Optional wallet alias"])
    var alias: String? = null

    override fun call(): Int {
        val ctxWallet = cliService.findContextWallet()
        getContextWallet(alias).also { wm ->
            if (ctxWallet?.id == wm.id) {
                cliService.putAttachment(WALLET_ATTACHMENT_KEY, null)
            }
            walletService.removeWallet(wm.id) as Wallet
            val header = "Wallet removed: "
            if (verbose)
                printResult(header, listOf(wm))
            else
                printResult(header, listOf(wm.shortString()))
            return 0
        }
    }
}

@Command(name = "connection", description = ["Show available connections and their details"])
class WalletConnectionCommand: AbstractBaseCommand() {

    @Option(names = ["--alias"], description = ["Optional connection alias"])
    var alias: String? = null

    @Option(names = ["--wallet"], description = ["Optional wallet alias"])
    var walletAlias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val pcons: List<Connection> = if (alias != null) {
            val found = ctxWallet.findConnection {
                val candidates = listOf(it.id, it.alias).map { c -> c.lowercase() }
                candidates.any { c -> c.startsWith(alias!!.lowercase()) }
            }
            found?.run { listOf(this) } ?: listOf()
        } else {
            ctxWallet.connections
        }
        val header = "Wallet connections: "
        if (verbose)
            printResult(header, pcons)
        else
            printResult(header, pcons.map { it.shortString() })
        return 0
    }
}

@Command(name = "did", description = ["Show available Dids and their details"])
class WalletDidCommand: AbstractBaseCommand() {

    @Option(names = ["--alias"], description = ["Optional did alias"])
    var alias: String? = null

    @Option(names = ["--wallet"], description = ["Optional wallet alias"])
    var walletAlias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val dids: List<Did> = if (alias != null) {
            val found = ctxWallet.findDid {
                val candidates = listOf(it.id, it.qualified, it.verkey).map { c -> c.lowercase() }
                candidates.any { c -> c.startsWith(alias!!.lowercase()) }
            }
            found?.run { listOf(this) } ?: listOf()
        } else {
            ctxWallet.dids
        }
        val header = "Wallet dids: "
        if (verbose)
            printResult(header, dids)
        else
            printResult(header, dids.map { it.shortString() })
        return 0
    }
}

@Command(name = "invitation", description = ["Show available invitations and their details"])
class WalletInvitationCommand: AbstractBaseCommand() {

    @Option(names = ["--alias"], description = ["Optional invitation alias"])
    var alias: String? = null

    @Option(names = ["--wallet"], description = ["Optional wallet alias"])
    var walletAlias: String? = null

    override fun call(): Int {
        val ctxWallet = getContextWallet(walletAlias)
        val invis: List<Invitation> = if (alias != null) {
            val found = ctxWallet.findInvitation {
                val candidates = listOf(it.id, it.invitationKey()).map { c -> c.lowercase() }
                candidates.any { c -> c.startsWith(alias!!.lowercase()) }
            }
            found?.run { listOf(this) } ?: listOf()
        } else {
            ctxWallet.invitations
        }
        val header = "Wallet invitations: "
        if (verbose)
            printResult(header, invis)
        else
            printResult(header, invis.map { it.shortString() })
        return 0
    }
}


@Command(name = "messages", description = ["Show connection related messages"])
class WalletMessagesCommand: AbstractBaseCommand() {

    @Option(names = ["--pcon"], description = ["Optional connection alias"])
    var conAlias: String? = null

    @Option(names = ["--wallet"], description = ["Optional wallet alias"])
    var walletAlias: String? = null

    @Option(names = ["--msg"], description = ["Optional message alias"])
    var msgAlias: String? = null

    @Option(names = ["-n", "--tail"], description = ["Optional number of (tail) messages"])
    var msgCount: Int = 12

    override fun call(): Int {
        val pcon = getContextConnection(walletAlias, conAlias)
        val mex = MessageExchange.findByVerkey(pcon.myVerkey)
        val size = mex.messages.size
        val msgs = if (msgAlias != null) {
            mex.messages.find {
                val candidates = listOf(it.id).map { c -> c.lowercase() }
                candidates.any { c -> c.startsWith(msgAlias!!.lowercase()) }
            }?.run { listOf(this) } ?: listOf()
        } else {
            val start = max(0, size - msgCount)
            mex.messages.subList(start, size)
        }
        val header = "Messages:\n"
        if (verbose)
            printResult(header, msgs)
        else
            printResult(header, msgs.map { it.shortString() })
        return 0
    }
}

@Command(name = "use", description = ["Use the given wallet"])
class WalletUseCommand: AbstractBaseCommand() {

    @Parameters(description = ["The wallet alias"])
    var alias: String? = null

    override fun call(): Int {
        getContextWallet(alias as String).also {
            cliService.putContextWallet(it)
            return 0
        }
    }
}
