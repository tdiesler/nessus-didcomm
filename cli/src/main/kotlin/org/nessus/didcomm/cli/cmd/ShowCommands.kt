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

import id.walt.common.prettyPrint
import org.nessus.didcomm.cli.cmd.ShowWalletCommand.Companion.reducedWalletMap
import org.nessus.didcomm.model.WalletModel
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.ScopeType.INHERIT
import java.util.concurrent.Callable

@Command(
    name = "show",
    description = ["Show state related commands"],
    subcommands = [
        ShowWalletsCommand::class,
        ShowWalletCommand::class,
    ]
)
class ShowCommands: AbstractBaseCommand() {
}

@Command(name = "wallets", description = ["Show a list of available wallets"])
class ShowWalletsCommand: AbstractBaseCommand() {

    // Show a single (reduced) wallet
    override fun call(): Int {
        val reducedWallets = modelService.wallets.map { reducedWalletMap(it) }
        val model = gson.toJson(reducedWallets)
        println("Wallets: ${model.prettyPrint()}")
        return 0
    }
}

@Command(name = "wallet")
class ShowWalletCommand: AbstractBaseCommand() {

    @Option(names = ["--alias" ], scope = INHERIT, description = ["A wallet id or name"])
    var alias: String? = null

    companion object {
        fun reducedWalletMap(wallet: WalletModel): MutableMap<String, Any?> {
            val unwantedKeys = listOf("dids", "connections", "invitations")
            val map = gson.toJson(wallet).decodeJson().toMutableMap()
            unwantedKeys.forEach { k -> map.remove(k) }
            return map
        }
    }

    // Show a single (reduced) wallet
    override fun call(): Int {
        getContextWallet(alias).also {
            val model = reducedWalletMap(it)
            println("Wallet: ${model.prettyPrint()}")
        }
        return 0
    }

    @Command(name = "dids", description = ["Show a given wallet's dids"])
    fun showDids(): Int {
        getContextWallet(alias).also {
            val model = gson.toJson(it.dids)
            println("Dids: ${model.prettyPrint()}")
        }
        return 0
    }

    @Command(name = "connections", description = ["Show a given wallet's connections"])
    fun showConnections(): Int {
        getContextWallet(alias).also {
            val model = gson.toJson(it.connections)
            println("Connections: ${model.prettyPrint()}")
        }
        return 0
    }

    @Command(name = "invitations", description = ["Show a given wallet's invitations"])
    fun showInvitations(): Int {
        getContextWallet(alias).also {
            val model = gson.toJson(it.invitations)
            println("Invitations: ${model.prettyPrint()}")
        }
        return 0
    }

    // Private ---------------------------------------------------------------------------------------------------------
}

