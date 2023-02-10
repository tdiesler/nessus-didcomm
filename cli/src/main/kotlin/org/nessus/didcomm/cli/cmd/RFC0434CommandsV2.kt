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

import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import picocli.CommandLine.Command
import picocli.CommandLine.Option

@Command(
    name = "rfc0434v2",
    description = ["RFC0434 Out-of-Band Invitation 2.0"],
    subcommands = [
        RFC0023CreateInvitationV2::class,
        RFC0023ReceiveInvitationV2::class,
    ]
)
class RFC0434CommandsV2

open class AbstractRFC0434CommandV2: DidCommV2Command() {

    protected fun printCreateInvitation(name: String, invitation: Invitation) {
        val header = "$name created an RFC0023 Invitation: "
        if (verbose) {
            printResult("${header}\n", listOf(invitation))
        } else {
            printResult(header, listOf(invitation.shortString()))
        }
    }

    protected fun printReceiveInvitation(name: String, invitation: Invitation) {
        val header = "$name received an RFC0434 Invitation: "
        if (verbose)
            printResult("${header}\n", listOf(invitation))
        else
            printResult(header, listOf(invitation.shortString()))
    }
}

@Command(name = "create-invitation", description = ["Create an RFC0023 Invitation"])
class RFC0023CreateInvitationV2: AbstractRFC0434CommandV2() {

    @Option(names = ["--inviter" ], description = ["Optional inviter alias"])
    var inviterAlias: String? = null

    override fun call(): Int {
        getContextWallet(inviterAlias).also {
            checkWalletEndpoint(it)
            val mex = MessageExchange()
                .withProtocol(RFC0434_OUT_OF_BAND_V2)
                .createOutOfBandInvitation(it)
                .getMessageExchange()
            val invitation = mex.getInvitation() as Invitation
            checkNotNull(it.getInvitation(invitation.id))
            cliService.putContextInvitation(invitation)
            printCreateInvitation(it.name, invitation)
        }
        return 0
    }
}

@Command(name = "receive-invitation", description = ["Receive an RFC0023 Invitation"])
class RFC0023ReceiveInvitationV2: AbstractRFC0434CommandV2() {

    @Option(names = ["--invitee" ], description = ["Optional invitee alias"])
    var inviteeAlias: String? = null

    @Option(names = ["--alias" ], description = ["Optional invitation alias"])
    var invitationAlias: String? = null

    override fun call(): Int {
        val ctxInvitation = cliService.getAttachment(INVITATION_ATTACHMENT_KEY)
        checkNotNull(ctxInvitation) { "No invitation" }
        if (invitationAlias != null) {
            val candidates = listOf(ctxInvitation.id, ctxInvitation.invitationKey()).map { c -> c.lowercase() }
            check(candidates.any { c -> c.startsWith(invitationAlias!!.lowercase()) }) { "Invitation does not match" }
        }
        getContextWallet(inviteeAlias).also {
            val invitee = it
            val mex = MessageExchange()
                .withAttachment(INVITATION_ATTACHMENT_KEY, ctxInvitation)
                .withProtocol(RFC0434_OUT_OF_BAND_V2)
                .receiveOutOfBandInvitation(invitee)
                .getMessageExchange()
            val connection = mex.getConnection()
            val invitation = mex.getInvitation() as Invitation
            checkNotNull(it.getConnection(connection.id))
            checkNotNull(it.getInvitation(invitation.id))
            cliService.putContextConnection(connection)
            cliService.putContextInvitation(invitation)
            printReceiveInvitation(it.name, invitation)
        }
        return 0
    }
}

