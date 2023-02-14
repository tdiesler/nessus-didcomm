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

import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import picocli.CommandLine.Command
import picocli.CommandLine.Option

@Command(
    name = "rfc0023",
    description = ["RFC0023 Did Exchange"],
    subcommands = [
        RFC0023ConnectCommand::class,
    ]
)
class RFC0023Commands

@Command(name = "connect", description = ["Connect a requester with a responder"])
class RFC0023ConnectCommand: AbstractBaseCommand() {

    @Option(names = ["--requester" ], description = ["Optional requester alias"])
    var requesterAlias: String? = null

    override fun call(): Int {

        val requester = getContextWallet(requesterAlias)
        val invitation = getContextInvitation(requesterAlias)

        val inviKey = invitation.invitationKey()
        val responder = modelService.findWalletByVerkey(inviKey)
        checkNotNull(responder) { "No responder wallet" }

        val responderInvi = responder.findInvitation { it.invitationKey() == inviKey }
        val requesterInvi = responder.findInvitation { it.invitationKey() == inviKey }
        checkNotNull(responderInvi) { "Responder has no such invitation" }
        checkNotNull(requesterInvi) { "Requester has no such invitation" }

        val requesterConn = requester.findConnection { it.invitationKey == inviKey }
        checkNotNull(requesterConn) { "Requester has no such connection" }

        checkWalletEndpoint(requester, responder)

        val mex = MessageExchange.findByVerkey(requesterConn.myVerkey)
            .withAttachment(INVITATION_ATTACHMENT_KEY, invitation)
            .withProtocol(RFC0023_DIDEXCHANGE_V1)
            .connect(requester)
            .getMessageExchange()

        val pcon = mex.getConnection()
        if (verbose)
            printResult("", listOf(pcon))
        else
            printResult("", listOf(pcon.shortString()))
        return 0
    }
}
