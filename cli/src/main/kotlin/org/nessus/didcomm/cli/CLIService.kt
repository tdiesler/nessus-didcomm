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

import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.WalletModel
import org.nessus.didcomm.model.toWallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.service.AbstractAttachmentsService
import org.nessus.didcomm.service.DataModelService
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.toWalletModel
import picocli.CommandLine


class CLIService: AbstractAttachmentsService() {
    override val implementation get() = serviceImplementation<CLIService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = CLIService()
        override fun getService() = implementation
    }

    init {
        // Fetch the wallet state from external agents
        WalletService.getService()
    }

    private val modelService get() = DataModelService.getService()

    fun execute(args: String, cmdln: CommandLine? = null): Result<Any> {
        return NessusCli().execute(args, cmdln)
    }

    fun findContextConnection(): Connection? {
        return getAttachment(CONNECTION_ATTACHMENT_KEY)
    }

    fun putContextConnection(pcon: Connection): Connection? {
        return putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
    }

    fun findContextInvitation(): Invitation? {
        return getAttachment(INVITATION_ATTACHMENT_KEY)
    }

    fun putContextInvitation(invitation: Invitation): Invitation? {
        return putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
    }

    fun findContextWallet(alias: String? = null): WalletModel? {
        return if (alias != null) {
            val test = { t: String -> t.lowercase().startsWith(alias.lowercase()) }
            modelService.findWallet { test(it.id) || test(it.name) }
        } else {
            getAttachment(WALLET_ATTACHMENT_KEY)?.toWalletModel()
        }
    }

    fun putContextWallet(wallet: WalletModel): WalletModel? {
        return putAttachment(WALLET_ATTACHMENT_KEY, wallet.toWallet())?.toWalletModel()
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
