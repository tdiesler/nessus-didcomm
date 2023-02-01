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
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE
import org.nessus.didcomm.service.RFC0048_TRUST_PING
import picocli.CommandLine.Command

@Command(
    name = "rfc0048",
    description = ["RFC0048 Trust Ping"],
)
class RFC0048TrustPingCommand: AbstractBaseCommand() {

    @Command(name="send-ping")
    fun sendPing(): Int {
        val pcon = cliService.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }
        val sender = modelService.findWalletByVerkey(pcon.myVerkey)
        checkNotNull(sender) { "No sender wallet for: ${pcon.myVerkey}" }
        val mex = MessageExchange()
            .withAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
            .withProtocol(RFC0048_TRUST_PING)
            .sendTrustPing()
            .awaitTrustPingResponse()
            .getMessageExchange()
        mex.checkLastMessageType(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE)
        println("${sender.name} received a Trust Ping response")
        return 0
    }
}
