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

import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V2
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V1
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
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

open class AbstractRFC0434Command: DidCommV2Command() {

    protected fun printCreateInvitation(name: String, invitation: Invitation) {
        val header = "$name created an RFC0434 Invitation: "
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

@Command(name = "create-invitation", description = ["Create an RFC0434 Invitation"])
class RFC0434CreateInvitation: AbstractRFC0434Command() {

    @Option(names = ["--inviter" ], description = ["Optional inviter alias"])
    var inviterAlias: String? = null

    override fun call(): Int {
        getContextWallet(inviterAlias).also {
            checkWalletEndpoint(it)
            val mex = when {
                dcv2 -> {
                    MessageExchange()
                        .withProtocol(RFC0434_OUT_OF_BAND_V2)
                        .createOutOfBandInvitation(it)
                        .getMessageExchange()
                }
                else -> {
                    MessageExchange()
                        .withProtocol(RFC0434_OUT_OF_BAND_V1)
                        .createOutOfBandInvitation(it)
                        .getMessageExchange()
                }
            }
            val invitation = mex.getInvitation() as Invitation
            checkNotNull(it.getInvitation(invitation.id))
            cliService.putContextInvitation(invitation)
            printCreateInvitation(it.name, invitation)
        }
        return 0
    }
}

@Command(name = "receive-invitation", description = ["Receive an RFC0434 Invitation"])
class RFC0434ReceiveInvitation: AbstractRFC0434Command() {

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
            val mex = when {
                dcv2 -> {
                    MessageExchange()
                        .withAttachment(INVITATION_ATTACHMENT_KEY, ctxInvitation)
                        .withProtocol(RFC0434_OUT_OF_BAND_V2)
                        .receiveOutOfBandInvitation(invitee)
                        .getMessageExchange()
                }
                else -> {
                    MessageExchange()
                        .withAttachment(INVITATION_ATTACHMENT_KEY, ctxInvitation)
                        .withProtocol(RFC0434_OUT_OF_BAND_V1)
                        .receiveOutOfBandInvitation(invitee)
                        .getMessageExchange()
                }
            }
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
class RFC0434InviteAndConnect: AbstractRFC0434Command() {

    @Parameters(index = "0", description = ["The inviter alias"])
    var inviterAlias: String? = null

    @Parameters(index = "1", description = ["The invitee alias"])
    var inviteeAlias: String? = null

    override fun call(): Int {
        val inviter = getContextWallet(inviterAlias)
        val invitee = getContextWallet(inviteeAlias)
        checkWalletEndpoint(inviter, invitee)

        val mex = when {
            dcv2 -> {
                MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V2)
                    .createOutOfBandInvitation(inviter)
                    .also {
                        val invitation = it.getMessageExchange().getInvitation()
                        printCreateInvitation(inviter.name, invitation!!)
                    }
                    .receiveOutOfBandInvitation(invitee)
                    .also {
                        val invitation = it.getMessageExchange().getInvitation()
                        printReceiveInvitation(invitee.name, invitation!!)
                    }
                    .withProtocol(RFC0023_DIDEXCHANGE_V2)
                    .connect(invitee)
                    .getMessageExchange()
            }
            else -> {
                MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V1)
                    .createOutOfBandInvitation(inviter)
                    .also {
                        val invitation = it.getMessageExchange().getInvitation()
                        printCreateInvitation(inviter.name, invitation!!)
                    }
                    .receiveOutOfBandInvitation(invitee)
                    .also {
                        val invitation = it.getMessageExchange().getInvitation()
                        printReceiveInvitation(invitee.name, invitation!!)
                    }
                    .withProtocol(RFC0023_DIDEXCHANGE_V1)
                    .connect(invitee)
                    .getMessageExchange()
            }
        }

        val pcon = mex.getConnection()
        cliService.putContextConnection(pcon)
        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, null)

        if (verbose)
            printResult("", listOf(pcon))
        else
            printResult("", listOf(pcon.shortString()))
        return 0
    }
}

