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
    name = "rfc0023",
    description = ["RFC0023 Did Exchange"],
    subcommands = [
        RFC0023ConnectCommand::class,
    ]
)
class RFC0023Commands

@Command(name = "connect")
class RFC0023ConnectCommand: AbstractBaseCommand(), Callable<Int> {

    @Parameters(index = "0", description = ["The requester wallet name"])
    var requesterName: String? = null

    @Parameters(index = "1", description = ["The responder wallet name"])
    var responderName: String? = null

    override fun call(): Int {
        val requester = walletService.findByName(requesterName!!)
        val responder = walletService.findByName(responderName!!)
        checkNotNull(requester) { "No wallet for name: $requesterName" }
        checkNotNull(responder) { "No wallet for name: $responderName" }
        checkWalletEndpoint(requester)
        val mex = MessageExchange()
            .withProtocol(RFC0434_OUT_OF_BAND)
            .createOutOfBandInvitation(responder)
            .receiveOutOfBandInvitation(requester)
            .withProtocol(RFC0023_DIDEXCHANGE)
            .connect(requester)
            .getMessageExchange()
        val invitation = mex.invitation as Invitation
        val pcon = mex.connection
        checkNotNull(requester.toWalletModel().getInvitation(invitation.id))
        checkNotNull(requester.toWalletModel().getConnection(pcon.id))
        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
        cliService.putAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
        println("${requester.name} now has a connection with ${responder.name} in state ${pcon.state}")
        return 0
    }
}
