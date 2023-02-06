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
import org.nessus.didcomm.model.toWallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
    name = "rfc0434",
    description = ["RFC0434 Out-of-Band Invitation"],
    subcommands = [
        RFC0434CreateInvitation::class,
        RFC0434ReceiveInvitation::class,
        RFC0434InviteAndConnect::class,
    ]
)
class RFC0434Commands

open class AbstractInvitationCommand: AbstractBaseCommand() {

    protected fun printCreateInvitation(name: String, invitation: Invitation) {
        val header = "$name created an RFC0434 Invitation: "
        if (verbose)
            printResult("${header}\n", listOf(invitation))
        else
            printResult(header, listOf(invitation.shortString()))
    }

    protected fun printReceiveInvitation(name: String, invitation: Invitation) {
        val header = "$name received an RFC0434 Invitation: "
        if (verbose)
            printResult("${header}\n", listOf(invitation))
        else
            printResult(header, listOf(invitation.shortString()))
    }
}

@Command(name = "create-invitation", description = ["Create an RFC0434 Invitation"])
class RFC0434CreateInvitation: AbstractInvitationCommand() {

    @Option(names = ["--inviter" ], description = ["The inviter alias"])
    var inviterAlias: String? = null

    override fun call(): Int {
        getContextWallet(inviterAlias).also {
            checkWalletEndpoint(it)
            val invitation = MessageExchange().withProtocol(RFC0434_OUT_OF_BAND)
                .createOutOfBandInvitation(it.toWallet())
                .getMessageExchange().last.body as Invitation
            checkNotNull(it.getInvitation(invitation.id))
            cliService.putContextInvitation(invitation)
            printCreateInvitation(it.name, invitation)
        }
        return 0
    }
}

@Command(name = "receive-invitation", description = ["receive an RFC0434 Invitation"])
class RFC0434ReceiveInvitation: AbstractInvitationCommand() {

    @Option(names = ["--invitee" ], description = ["The invitee alias"])
    var inviteeAlias: String? = null

    override fun call(): Int {
        getContextWallet(inviteeAlias).also {
            val invitee = it.toWallet()
            val mex = MessageExchange()
                .withAttachment(INVITATION_ATTACHMENT_KEY, getContextInvitation())
                .withProtocol(RFC0434_OUT_OF_BAND)
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

@Command(name = "connect", description = ["Combine RFC0434 Invitation and RFC0023 Did Exchange"])
class RFC0434InviteAndConnect: AbstractInvitationCommand() {

    @Parameters(index = "0", description = ["The inviter alias"])
    var inviterAlias: String? = null

    @Parameters(index = "1", description = ["The invitee alias"])
    var inviteeAlias: String? = null

    override fun call(): Int {
        val inviter = getContextWallet(inviterAlias)
        val invitee = getContextWallet(inviteeAlias)
        checkWalletEndpoint(inviter, invitee)

        val pcon = MessageExchange()
            .withProtocol(RFC0434_OUT_OF_BAND)
            .createOutOfBandInvitation(inviter.toWallet())
            .also {
                val invitation = it.getMessageExchange().getInvitation()
                printCreateInvitation(inviter.name, invitation!!)
            }
            .receiveOutOfBandInvitation(invitee.toWallet())
            .also {
                val invitation = it.getMessageExchange().getInvitation()
                printReceiveInvitation(invitee.name, invitation!!)
            }
            .withProtocol(RFC0023_DIDEXCHANGE)
            .connect(invitee.toWallet())
            .getMessageExchange()
            .getConnection()

        cliService.putContextConnection(pcon)
        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, null)

        if (verbose)
            printResult("", listOf(pcon))
        else
            printResult("", listOf(pcon.shortString()))

        return 0
    }
}

