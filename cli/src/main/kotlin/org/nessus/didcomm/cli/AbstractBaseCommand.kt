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

import id.walt.auditor.Auditor
import id.walt.common.resolveContent
import id.walt.custodian.Custodian
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.EndpointService
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.NessusPolicyRegistryService
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.w3c.NessusSignatoryService
import org.nessus.didcomm.w3c.W3CVerifiableCredential
import picocli.CommandLine
import java.io.PrintStream
import java.net.URL
import java.util.concurrent.Callable

abstract class AbstractBaseCommand: Callable<Int> {
    private val log = KotlinLogging.logger {  }

    companion object {
        // Can be set to redirect output
        var out: PrintStream = System.out
    }

    val auditor get() = Auditor.getService()
    val cliService get() = CLIService.getService()
    val custodian get() = Custodian.getService()
    val didService get() = DidService.getService()
    val endpointService get() = EndpointService.getService()
    val modelService get() = ModelService.getService()
    val policyService get() = NessusPolicyRegistryService.getService()
    val signatory get() = NessusSignatoryService.getService()
    val walletService get() = WalletService.getService()

    override fun call(): Int {
        CommandLine.usage(this, out)
        return 0
    }

    fun echo(msg: Any = "") {
        log.info { msg }
        out.println(msg)
    }

    fun echoList(result: List<Any>) {
        result.forEach { echo(it) }
    }

    fun echoList(message: String, result: List<Any>) {
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
                        val keyPort = result.getOrNull()?.port
                        // val keyHost = result.getOrNull()?.host
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

    fun getContextDid(walletAlias: String? = null, didAlias: String? = null): Did {
        val did = cliService.findContextDid(walletAlias, didAlias)
        checkNotNull(did) { "No did" }
        return did
    }

    fun getContextInvitation(invAlias: String? = null): Invitation {
        val invitation = cliService.findContextInvitation(invAlias)
        checkNotNull(invitation) { "No invitation" }
        return invitation
    }

    fun getContextWallet(alias: String? = null): Wallet {
        val wallet = cliService.findContextWallet(alias)
        checkNotNull(wallet) { when (alias) {
            null -> "No context wallet"
            else -> "Cannot find wallet for: $alias"
        }}
        return wallet
    }

    fun getWalletFromAlias(alias: String?): Wallet {
        return alias?.toIntOrNull()
            ?.let { idx -> modelService.wallets[idx] }
            ?: getContextWallet(alias)
    }

    fun findWalletAndDidFromAlias(walletAlias: String?, alias: String?): Pair<Wallet?, Did?> {

        // Last Did of the context wallet
        if (alias == null) {
            return getContextWallet(walletAlias).let { w -> Pair(w, w.dids.lastOrNull()) }
        }

        // Did alias as a reference to a context variable
        cliService.getVar(alias)?.also {
            return findWalletAndDidFromAlias(walletAlias, it)
        }

        // Did alias as an index into the context wallet did list
        if (alias.toIntOrNull() != null) {
            val idx = alias.toInt()
            return getContextWallet(walletAlias).let { w -> Pair(w, w.dids[idx]) }
        }

        // Find did for the given wallet alias
        if (walletAlias != null) {
            return getContextWallet(walletAlias).let { w ->
                Pair(w, w.findDidsByAlias(alias).firstOrNull())
            }
        }

        // Did alias as fuzzy uri selector for all wallet dids
        modelService.wallets
            .map { w -> Pair(w, w.findDidsByAlias(alias).firstOrNull()) }
            .firstOrNull { p -> p.second != null }
            ?.also { return it }

        return Pair(null, null)
    }

    fun getVcpFromAlias(holder: Wallet, alias: String): W3CVerifiableCredential? {

        // Vc alias as a reference to a context variable
        cliService.getVar(alias)?.also {
            return holder.getVerifiableCredential(it)
        }

        // Vc alias as an index into the context wallet vc list
        if (alias.toIntOrNull() != null) {
            val idx = alias.toInt()
            return holder.verifiableCredentials[idx]
        }

        // Vc alias as fuzzy id selector
        holder.findVerifiableCredential { vc -> vc.id.toString().startsWith(alias) }
            ?.also { return it }

        // Vc alias as fileUrl or content
        return kotlin.runCatching { resolveContent(alias) }
            .getOrNull()?.let { W3CVerifiableCredential.fromJson(it) }
    }
}
