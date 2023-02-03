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

import org.nessus.didcomm.cli.CLIService
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.WalletModel
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.service.CamelEndpointService
import org.nessus.didcomm.service.DataModelService
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.toWalletModel
import picocli.CommandLine
import java.net.URL
import java.util.concurrent.Callable

abstract class AbstractBaseCommand: Callable<Int> {

    val cliService get() = CLIService.getService()
    val endpointService get() = CamelEndpointService.getService()
    val modelService get() = DataModelService.getService()
    val walletService get() = WalletService.getService()

    override fun call(): Int {
        CommandLine.usage(this, System.out)
        return 0
    }

    fun checkWalletEndpoint(vararg wallets: WalletModel) {
        wallets.forEach {
            when (it.agentType) {
                AgentType.ACAPY -> {
                    // Assume that AcaPy is running
                }
                AgentType.NESSUS -> {
                    val url = URL(it.endpointUrl)
                    val eps = EndpointSpec("", url.host, url.port)
                    check(cliService.attachmentKeys.any {
                        val result = runCatching { EndpointSpec.valueOf(it.name) }
                        val keyHost = result.getOrNull()?.host
                        val keyPort = result.getOrNull()?.port
                        // [TODO] verify endpoint type/host
                        result.isSuccess && eps.port == keyPort
                    }) { "No running endpoint for: ${it.endpointUrl}"}
                }
            }
        }
    }

    fun getContextConnection(): Connection {
        val pcon = cliService.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }
        return pcon
    }

    fun getContextInvitation(): Invitation {
        val invitation = cliService.getAttachment(INVITATION_ATTACHMENT_KEY)
        checkNotNull(invitation) { "No invitation" }
        return invitation
    }

    fun getContextWallet(alias: String? = null): WalletModel {
        val walletModel = findContextWallet(alias)
        checkNotNull(walletModel) { "Cannot find wallet: $alias" }
        return walletModel
    }

    fun findContextWallet(alias: String? = null): WalletModel? {
        return if (alias != null) {
            val test = { t: String -> t.lowercase().startsWith(alias) }
            modelService.findWallet { test(it.id) || test(it.name) }
        } else {
            cliService.getAttachment(WALLET_ATTACHMENT_KEY)?.toWalletModel()
        }
    }

    fun getWalletModel(alias: String): WalletModel {
        val walletModel = findWalletModel(alias)
        checkNotNull(walletModel) { "Cannot find wallet: $alias" }
        return walletModel
    }

    fun findWalletModel(alias: String): WalletModel? {
        val test = { t: String -> t.lowercase().startsWith(alias) }
        return modelService.findWallet { test(it.id) || test(it.name) }
    }
}
