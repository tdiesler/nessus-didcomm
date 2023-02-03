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

import org.nessus.didcomm.model.toWallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE
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

    @Option(names = ["--requester" ], description = ["The requester alias"])
    var requesterAlias: String? = null

    override fun call(): Int {

        val invitation = getContextInvitation()
        val connection = getContextConnection()
        val requester = getContextWallet(requesterAlias)

        val responder = modelService.findWalletByVerkey(invitation.invitationKey())
        checkNotNull(responder) { "No responder wallet" }

        checkWalletEndpoint(requester, responder)

        MessageExchange.findByVerkey(connection.myVerkey)
            .withAttachment(INVITATION_ATTACHMENT_KEY, invitation)
            .withProtocol(RFC0023_DIDEXCHANGE)
            .connect(requester.toWallet())
            .getMessageExchange()

        println("${requester.name} has a connection with ${responder.name} in state ${connection.state}")
        return 0
    }
}
