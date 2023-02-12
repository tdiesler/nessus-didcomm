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
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocolV1.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V1
import picocli.CommandLine.Command

@Command(
    name = "rfc0048",
    description = ["RFC0048 Trust Ping"],
    subcommands = [
        RFC0048SendPingCommand::class
    ],
)
class RFC0048TrustPingCommand

@Command(name="send-ping", description = ["Send a trust ping message"])
class RFC0048SendPingCommand: AbstractBaseCommand() {

    override fun call(): Int {
        val pcon = getContextConnection()
        val sender = modelService.findWalletByVerkey(pcon.myVerkey)
        checkNotNull(sender) { "No sender wallet for: ${pcon.myVerkey}" }
        val mex = MessageExchange()
            .withAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
            .withProtocol(RFC0048_TRUST_PING_V1)
            .sendTrustPing()
            .awaitTrustPingResponse()
            .getMessageExchange()
        mex.checkLastMessageType(RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V1)
        val header = "${sender.name} received a Trust Ping response"
        if (verbose)
            printResult("${header}\n", listOf(mex.last.prettyPrint()))
        else
            printResult("${header}\n", listOf())
        return 0
    }

}
