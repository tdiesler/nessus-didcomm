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
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.wallet.toWalletModel
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import java.util.concurrent.Callable

@Command(
    name = "rfc0434",
    description = ["RFC0434 Out-of-Band Invitation"],
    subcommands = [
        RFC0434CreateInvitation::class,
        RFC0434ReceiveInvitation::class,
    ]
)
class RFC0434Commands: AbstractBaseCommand() {
}

@Command(name = "create-invitation")
class RFC0434CreateInvitation: AbstractBaseCommand(), Callable<Int> {

    @Parameters(index = "0", description = ["The inviter name"])
    var inviterName: String? = null

    override fun call(): Int {
        val inviter = walletService.findByName(inviterName!!)
        checkNotNull(inviter) { "No wallet for name: $inviterName" }
        checkWalletEndpoint(inviter)
        val invitation = MessageExchange().withProtocol(RFC0434_OUT_OF_BAND)
            .createOutOfBandInvitation(inviter)
            .getMessageExchange().last.body as Invitation
        checkNotNull(inviter.toWalletModel().getInvitation(invitation.id))
        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
        println("${inviter.name} created an RFC0434 Invitation")
        return 0
    }
}

@Command(name = "receive-invitation")
class RFC0434ReceiveInvitation: AbstractBaseCommand(), Callable<Int> {

    @Parameters(index = "0", description = ["The invitee name"])
    var inviteeName: String? = null

    override fun call(): Int {
        val invitee = walletService.findByName(inviteeName!!)
        checkNotNull(invitee) { "No wallet for name: $inviteeName" }
        val invitation = cliService.getAttachment(INVITATION_ATTACHMENT_KEY)
        checkNotNull(invitation) { "No invitation" }
        checkWalletEndpoint(invitee)
        val mex = MessageExchange()
            .withAttachment(INVITATION_ATTACHMENT_KEY, invitation)
            .withProtocol(RFC0434_OUT_OF_BAND)
            .receiveOutOfBandInvitation(invitee)
            .withProtocol(RFC0023_DIDEXCHANGE)
            .connect(invitee)
            .getMessageExchange()
        val pcon = mex.connection
        checkNotNull(invitee.toWalletModel().getInvitation(invitation.id))
        checkNotNull(invitee.toWalletModel().getConnection(pcon.id))
        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
        cliService.putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
        println("${invitee.name} received an RFC0434 Invitation")
        return 0
    }
}
