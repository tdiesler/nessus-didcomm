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
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.model.MessageExchange.Companion.DID_ATTACHMENT_KEY
import org.nessus.didcomm.model.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.model.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.util.AttachmentSupport
import picocli.CommandLine


object CLIService: AttachmentSupport() {
    private val log = KotlinLogging.logger {  }

    // Fetch the wallet state from external agents
    init {
        WalletService.getService()
    }

    fun getService() = apply {}

    private val modelService get() = ModelService.getService()
    private val variables = mutableMapOf<String, String>()

    fun execute(args: String, cmdln: CommandLine? = null): Result<Any> {
        return NessusCli().execute(args, cmdln)
    }

    fun nextCommand(lines: MutableList<String>): String? {
        if (lines.isEmpty()) return null
        val regex = Regex("\\s(.*)")
        val buffer = StringBuffer(lines.removeAt(0))
        while (lines.isNotEmpty() && regex.matches(lines[0])) {
            val part = lines.removeAt(0).trim()
            buffer.append(" $part")
        }
        return replaceVars(buffer.toString())
    }

    fun replaceVars(line: String): String {
        val regex = Regex("(.*)\\$\\{(.+)}(.*)")
        val tokens = line.split(Regex("\\s"))
        return tokens.joinToString(separator = " ") { tok ->
            regex.matchEntire(tok)?.groupValues?.let { groups ->
                val value = getVar(groups[2])
                "${groups[1]}$value${groups[3]}"
            } ?: tok
        }
    }

    fun putContextConnection(pcon: Connection?) {
        putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
        pcon?.also {
            checkNotNull(pcon.myLabel) { "No myLabel in: ${pcon.shortString()}" }
            checkNotNull(pcon.theirLabel) { "No theirLabel in: ${pcon.shortString()}" }
            putVar("${pcon.alias}.myDid", pcon.myDid.uri)
            putVar("${pcon.alias}.theirDid", pcon.theirDid.uri)
            putVar("${pcon.myLabel}.Did", pcon.myDid.uri)
            putVar("${pcon.theirLabel}.Did", pcon.theirDid.uri)
        }
    }

    fun findContextDid(walletAlias: String? = null, didAlias: String? = null): Did? {
        val ctxWallet = findContextWallet(walletAlias) ?: return null
        val effAlias = didAlias ?: getAttachment(DID_ATTACHMENT_KEY)?.id ?: return null
        return ctxWallet.findDid {
            val candidates = listOf(it.id, it.uri, it.verkey).map { c -> c.lowercase() }
            candidates.any { c -> c.startsWith(effAlias.lowercase()) }
        }
    }

    fun putContextDid(ownerAlias: String, did: Did?) {
        putAttachment(DID_ATTACHMENT_KEY, did)
        putVar("${ownerAlias}.Did", did?.uri)
    }

    fun findContextInvitation(invAlias: String? = null): Invitation? {
        val effAlias = invAlias ?: getAttachment(INVITATION_ATTACHMENT_KEY)?.id ?: return null
        val invitations = mutableListOf<Invitation>()
        modelService.wallets.forEach { w -> invitations.addAll(w.invitations.filter { iv ->
            val candidates = listOf(iv.id, iv.invitationKey()).map { c -> c.lowercase() }
            candidates.any { c -> c.startsWith(effAlias.lowercase()) }
        })}
        return invitations.firstOrNull()
    }

    fun putContextInvitation(invitation: Invitation?) {
        putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
    }

    fun findContextWallet(alias: String? = null): Wallet? {
        val effAlias = alias ?: getAttachment(WALLET_ATTACHMENT_KEY)?.id ?: return null
        return modelService.findWallet {
            val candidates = listOf(it.id, it.name).map { c -> c.lowercase() }
            candidates.any { c -> c.startsWith(effAlias.lowercase()) }
        }
    }

    fun putContextWallet(wallet: Wallet?) {
        log.debug { "Put context wallet: ${wallet?.shortString()}" }
        putAttachment(WALLET_ATTACHMENT_KEY, wallet)
    }

    fun getVar(key: String): String? {
        return variables.keys
            .firstOrNull { it.lowercase() == key.lowercase() }
            ?.let { variables[it] }
    }

    fun getVars(): Map<String, String> {
        return variables.toMap()
    }

    fun delVar(key: String): String? {
        return variables.keys
            .firstOrNull { it.lowercase() == key.lowercase() }
            ?.also {
                log.debug { "Delete variable: $it" }
                variables.remove(it)
            }
    }

    fun putVar(key: String, value: String?) {
        log.debug { "Put variable: $key=$value" }
        value?.also { variables[key] = it } ?: run { delVar(key) }
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
