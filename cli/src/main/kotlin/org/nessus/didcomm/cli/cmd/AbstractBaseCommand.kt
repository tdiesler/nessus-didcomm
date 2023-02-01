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
import org.nessus.didcomm.service.CamelEndpointService
import org.nessus.didcomm.service.DataModelService
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import java.net.URL

abstract class AbstractBaseCommand {

    val cliService get() = CLIService.getService()
    val endpointService get() = CamelEndpointService.getService()
    val modelService get() = DataModelService.getService()
    val walletService get() = WalletService.getService()


    fun checkWalletEndpoint(vararg wallets: Wallet) {
        wallets.forEach {
            when (it.agentType) {
                AgentType.ACAPY -> {
                    // Assume that AcaPy is running
                }
                AgentType.NESSUS -> {
                    val url = URL(it.endpointUrl)
                    val eps = AgentCommands.EndpointSpec("", url.host, url.port)
                    check(cliService.attachmentKeys.any {
                        val result = runCatching { AgentCommands.EndpointSpec.valueOf(it.name) }
                        val keyHost = result.getOrNull()?.host
                        val keyPort = result.getOrNull()?.port
                        // [TODO] verify endpoint type/host
                        result.isSuccess && eps.port == keyPort
                    }) { "No running endpoint for: ${it.endpointUrl}"}
                }
            }
        }
    }
}
