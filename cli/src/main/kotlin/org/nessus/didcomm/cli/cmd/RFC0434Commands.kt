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

import id.walt.common.prettyPrint
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.wallet.toWalletModel
import picocli.CommandLine.Command
import picocli.CommandLine.Option
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

    @Option(names = [ "--inviter" ], required = true, description = ["The inviter name"])
    var inviterName: String? = null

    override fun call(): Int {
        val inviter = walletService.findByName(inviterName!!)
        checkNotNull(inviter) { "No wallet for name: $inviterName" }
        val invitation = MessageExchange().withProtocol(RFC0434_OUT_OF_BAND)
            .createOutOfBandInvitation(inviter)
            .getMessageExchange().last.body as Invitation
        checkNotNull(inviter.toWalletModel().getInvitation(invitation.id))
        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
        println("${inviter.name} created RFC0434 Invitation: ${invitation.prettyPrint()}")
        return 0
    }
}

@Command(name = "receive-invitation")
class RFC0434ReceiveInvitation: AbstractBaseCommand(), Callable<Int> {

    @Option(names = [ "--invitee" ], required = true, description = ["The invitee name"])
    var inviteeName: String? = null

    override fun call(): Int {
        val invitee = walletService.findByName(inviteeName!!)
        checkNotNull(invitee) { "No wallet for name: $inviteeName" }
        val invitation = cliService.getAttachment(INVITATION_ATTACHMENT_KEY)
        checkNotNull(invitation) { "No invitation" }
        MessageExchange()
            .withAttachment(INVITATION_ATTACHMENT_KEY, invitation)
            .withProtocol(RFC0434_OUT_OF_BAND)
            .receiveOutOfBandInvitation(invitee)
        checkNotNull(invitee.toWalletModel().getInvitation(invitation.id))
        println("${invitee.name} received RFC0434 Invitation: ${invitation.prettyPrint()}")
        return 0
    }
}
