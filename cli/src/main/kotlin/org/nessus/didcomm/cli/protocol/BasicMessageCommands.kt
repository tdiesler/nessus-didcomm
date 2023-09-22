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
package org.nessus.didcomm.cli.protocol

import id.walt.common.prettyPrint
import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.service.BASIC_MESSAGE_PROTOCOL_V2
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "basic-message",
    description = ["Basic message commands"],
    mixinStandardHelpOptions = true)
class BasicMessageCommands: AbstractBaseCommand() {

    @Command(name="send", description = ["Send a basic message"], mixinStandardHelpOptions = true)
    fun sendMessage(
        @Option(names = ["--sign" ], description = ["Sign the DIDComm V2 messages"])
        sign: Boolean,

        @Option(names = ["--encrypt" ], description = ["Encrypt the DIDComm V2 messages"])
        encrypt: Boolean,

        @Parameters(index = "0", scope = INHERIT, description = ["The message"])
        message: String,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ): Int {
        val ctxWallet = cliService.findContextWallet()
        val pcon = ctxWallet?.currentConnection
        checkNotNull(pcon) { "No context wallet/connection" }
        val sender = modelService.findWalletByVerkey(pcon.myVerkey)
        checkNotNull(sender) { "No sender wallet for: ${pcon.myVerkey}" }

        val mex = when {
            encrypt -> {
                MessageExchange()
                    .withAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
                    .withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendEncryptedMessage(message)
                    .getMessageExchange()

            }

            sign -> {
                MessageExchange()
                    .withAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
                    .withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendSignedMessage(message)
                    .getMessageExchange()
            }

            else -> {
                MessageExchange()
                    .withAttachment(CONNECTION_ATTACHMENT_KEY, pcon)
                    .withProtocol(BASIC_MESSAGE_PROTOCOL_V2)
                    .sendPlaintextMessage(message)
                    .getMessageExchange()
            }
        }

        val header = "${sender.alias} sent: $message"
        if (verbose)
            echo("${header}\n${mex.last.prettyPrint()}")
        else
            echo(header)
        return 0
    }

}
