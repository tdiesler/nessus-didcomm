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

import mu.KotlinLogging
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.EndpointService
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.NessusDidService
import org.nessus.didcomm.service.VerificationPolicyService
import org.nessus.didcomm.service.WalletService
import picocli.CommandLine
import java.io.PrintStream
import java.net.URL
import java.util.concurrent.Callable

abstract class AbstractBaseCommand: Callable<Int> {
    val log = KotlinLogging.logger {  }

    companion object {
        // Can be set to redirect output
        var out: PrintStream = System.out
    }

    val cliService get() = CLIService.getService()
    val didService get() = NessusDidService.getService()
    val endpointService get() = EndpointService.getService()
    val modelService get() = ModelService.getService()
    val policyService get() = VerificationPolicyService.getService()
    val walletService get() = WalletService.getService()

    override fun call(): Int {
        CommandLine.usage(this, out)
        return 0
    }

    fun echo(msg: Any = "") {
        log.info { msg }
        out.println(msg)
    }

    fun echo(result: List<Any>) {
        result.forEach { echo(it) }
    }

    fun echo(message: String, result: List<Any>) {
        log.info { message }
        out.print(message)
        result.forEach { echo(it) }
    }

    fun checkWalletEndpoint(vararg wallets: Wallet) {
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

    fun getContextConnection(walletAlias: String? = null, conAlias: String? = null): Connection {
        val pcon = cliService.findContextConnection(walletAlias, conAlias)
        checkNotNull(pcon) { "No connection" }
        return pcon
    }

    fun getContextInvitation(walletAlias: String? = null, invAlias: String? = null): Invitation {
        val invitation = cliService.findContextInvitation(walletAlias, invAlias)
        checkNotNull(invitation) { "No invitation" }
        return invitation
    }

    fun getContextWallet(alias: String? = null): Wallet {
        val wallet = cliService.findContextWallet(alias)
        checkNotNull(wallet) { "Cannot find wallet: $alias" }
        return wallet
    }
}
