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

import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "rfc0095",
    description = ["RFC0095 Basic Message"],
)
class RFC0095BasicMessageCommand: AbstractBaseCommand() {

    @Parameters(index = "0", scope = INHERIT, description = ["The message"])
    var message: String? = null

    @Command(name="send", description = ["Send a basic message"])
    fun sendMessage(): Int {
        val pcon = getContextConnection()
        val sender = modelService.findWalletByVerkey(pcon.myVerkey)
        checkNotNull(sender) { "No sender wallet for: ${pcon.myVerkey}" }
        MessageExchange()
            .withAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
            .withProtocol(RFC0095_BASIC_MESSAGE)
            .sendMessage(message!!)
            .getMessageExchange()
        println("${sender.name} sent: $message")
        return 0
    }
}
