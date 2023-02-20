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
package org.nessus.didcomm.cli

import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
    name = "wallet",
    description = ["Multitenant wallet commands"],
    subcommands = [
        WalletCreateCommand::class,
        WalletListCommand::class,
        WalletShowCommand::class,
        WalletRemoveCommand::class,
        WalletSwitchCommand::class,
    ]
)
class WalletCommands

@Command(name = "list", description = ["List available wallets"])
class WalletListCommand: AbstractBaseCommand() {

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {
        val walletModels = modelService.wallets
        if (verbose)
            echo(walletModels.map { it.encodeJson(true) })
        else
            echo(walletModels.map { it.shortString() })
        return 0
    }
}

@Command(name = "show", description = ["Show wallet details"])
class WalletShowCommand: AbstractBaseCommand() {

    @Option(names = ["--alias"], description = ["Optional wallet alias"])
    var alias: String? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {
        val wallet = getContextWallet(alias)
        if (verbose)
            echo(wallet.encodeJson(true))
        else
            echo(wallet.shortString())
        return 0
    }
}

@Command(name = "create", description = ["Create a wallet for a given agent"])
class WalletCreateCommand: AbstractBaseCommand() {

    @Option(names = ["-n", "--name"], required = true, description = ["The wallet name"])
    var name: String? = null

    @Option(names = ["-a", "--agent"], description = ["The agent type (default=Nessus)"], defaultValue = "Nessus")
    var agent: String? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {
        val wallet = Wallet.Builder(name!!)
            .agentType(AgentType.fromValue(agent!!))
            .build()
        cliService.putContextWallet(wallet)
        if (verbose)
            echo("Wallet created\n${wallet.encodeJson(true)}")
        else
            echo("Wallet created: ${wallet.shortString()}")
        return 0
    }
}

@Command(name = "remove", description = ["Remove and delete a given wallet"])
class WalletRemoveCommand: AbstractBaseCommand() {

    @Parameters(description = ["The wallet alias"])
    var alias: String? = null

    override fun call(): Int {
        val walletAtt = cliService.getAttachment(WALLET_ATTACHMENT_KEY)
        getContextWallet(alias).also { wallet ->
            if (walletAtt?.id == wallet.id) {
                cliService.putAttachment(WALLET_ATTACHMENT_KEY, null)
            }
            walletService.removeWallet(wallet.id)
            echo("Wallet removed: ${wallet.shortString()}")
            return 0
        }
    }
}


@Command(name = "switch", description = ["Switch the current context wallet"])
class WalletSwitchCommand: AbstractBaseCommand() {

    @Parameters(description = ["The wallet alias"])
    var alias: String? = null

    override fun call(): Int {
        val wallet = getContextWallet(alias).also {
            cliService.putContextWallet(it)
        }
        wallet.connections.lastOrNull { it.state == ConnectionState.ACTIVE }?.also {
            cliService.putContextConnection(it)
        }
        return 0
    }
}
