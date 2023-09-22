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
package org.nessus.didcomm.cli.model

import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.model.MessageExchange.Companion.DID_ATTACHMENT_KEY
import org.nessus.didcomm.model.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.model.Wallet
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
    name = "wallet",
    description = ["Multitenant wallet commands"],
    mixinStandardHelpOptions = true,
)
class WalletCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List available wallets"], mixinStandardHelpOptions = true)
    fun listWallets(

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean = false
    ) {
        modelService.wallets.forEachIndexed { idx, w ->
            val wstr = if (verbose) w.encodeJson(true) else w.shortString()
            echo("[$idx] $wstr")
        }
    }

    @Command(name = "show", description = ["Show wallet details"], mixinStandardHelpOptions = true)
    fun showWallet(

        @Parameters(description = ["The wallet alias"], arity = "0..1")
        alias: String?,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean = false,
    ) {
        val w = getContextWallet(alias)
        if (verbose)
            echo(w.encodeJson(true))
        else
            echo(w.shortString())
    }

    @Command(name = "create", description = ["Create a wallet for a given agent"], mixinStandardHelpOptions = true)
    fun createWallet(
        @Option(names = ["-n", "--name"], required = true, description = ["The wallet name"])
        name: String,

        @Option(names = ["-a", "--agent"], description = ["The agent type (default=Nessus)"], defaultValue = "Nessus")
        agent: String?,

        @Option(names = ["-u", "--url"], description = ["The wallet's endpoint url"])
        endpointUrl: String?,

        @Option(names = ["-r", "--routing-key"], arity = "0..*", description = ["Optional routing key"])
        routingKeys: List<String>?,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean = false
    ) {

        // Validate the routing keys
        val effectiveRoutingKeys = routingKeys?.map {
            val (_, mediatorDid) = findWalletAndDidFromAlias(null, it)
            checkNotNull(mediatorDid?.uri) { "Cannot find mediator Did for: $it" }
        } ?: listOf()

        val wallet = Wallet.Builder(name)
            .agentType(AgentType.fromValue(agent!!))
            .routingKeys(effectiveRoutingKeys)
            .endpointUrl(endpointUrl)
            .build()
        cliService.putContextWallet(wallet)
        if (verbose)
            echo("Wallet created\n${wallet.encodeJson(true)}")
        else
            echo("Wallet created: ${wallet.shortString()}")
    }

    @Command(name = "remove", description = ["Remove and delete a given wallet"], mixinStandardHelpOptions = true)
    fun removeWallet(
        @Parameters(description = ["The wallet alias"])
        alias: String
    ) {
        getWalletFromAlias(alias).also { wallet ->
            val walletAtt = cliService.getAttachment(MessageExchange.WALLET_ATTACHMENT_KEY)
            if (wallet.id == walletAtt?.id) {
                cliService.removeAttachment(MessageExchange.WALLET_ATTACHMENT_KEY)
            }
            walletService.removeWallet(wallet.id)
            cliService.putAttachment(CONNECTION_ATTACHMENT_KEY, null)
            cliService.putAttachment(WALLET_ATTACHMENT_KEY, null)
            cliService.putAttachment(DID_ATTACHMENT_KEY, null)
            echo("Wallet removed: ${wallet.shortString()}")
        }
    }

    @Command(name = "switch", description = ["Switch the current context wallet"], mixinStandardHelpOptions = true)
    fun switchWallet(
        @Parameters(description = ["The wallet alias"])
        alias: String
    ) {
        val wallet = getWalletFromAlias(alias)
        cliService.putContextWallet(wallet)
        cliService.putContextDid(wallet.alias, wallet.dids.lastOrNull())
        cliService.putContextConnection(wallet.connections.lastOrNull { it.state == ConnectionState.ACTIVE })
    }
}
