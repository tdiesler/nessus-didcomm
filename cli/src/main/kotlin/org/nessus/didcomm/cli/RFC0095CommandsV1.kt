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

import id.walt.common.prettyPrint
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocolV1.Companion.RFC0095_BASIC_MESSAGE_TYPE_V1
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE_V1
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "rfc0095",
    description = ["RFC0095 Basic Message"],
    subcommands = [
        RFC0095SendMessageCommand::class
    ],
)
class RFC0095BasicMessageCommand

@Command(name="send", description = ["Send a basic message"])
class RFC0095SendMessageCommand: AbstractBaseCommand() {

    @Parameters(index = "0", scope = INHERIT, description = ["The message"])
    var message: String? = null

    override fun call(): Int {
        val pcon = getContextConnection()
        val sender = modelService.findWalletByVerkey(pcon.myVerkey)
        checkNotNull(sender) { "No sender wallet for: ${pcon.myVerkey}" }
        val mex = MessageExchange()
            .withAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
            .withProtocol(RFC0095_BASIC_MESSAGE_V1)
            .sendMessage(message!!)
            .getMessageExchange()
        mex.checkLastMessageType(RFC0095_BASIC_MESSAGE_TYPE_V1)
        val header = "${sender.name} sent: $message"
        if (verbose)
            printResult("${header}\n", listOf(mex.last.prettyPrint()))
        else
            printResult("${header}\n", listOf())
        return 0
    }
}
