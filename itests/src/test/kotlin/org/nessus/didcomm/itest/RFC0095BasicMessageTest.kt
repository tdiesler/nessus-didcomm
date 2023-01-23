/*-
 * #%L
 * Nessus DIDComm :: ITests
 * %%
 * Copyright (C) 2022 Nessus
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
package org.nessus.didcomm.itest

import org.hyperledger.acy_py.generated.model.SendMessage
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocol.Companion.RFC0095_BASIC_MESSAGE_TYPE
import org.nessus.didcomm.service.RFC0095_BASIC_MESSAGE
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * Aries RFC 0095: Basic Message Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
 */
class RFC0095BasicMessageTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_AliceAcapy() {

        /**
         * Create the Wallets
         */

        val faber = getWalletByAlias(Faber.name) ?: fail("No Inviter")

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .build()

        val basicMessageFuture = CompletableFuture<EndpointMessage>()
        val listener: MessageListener = { epm ->
            val mex = dispatchService.invoke(epm) as MessageExchange
            if (mex.last.messageType == RFC0095_BASIC_MESSAGE_TYPE) {
                basicMessageFuture.complete(mex.last)
            }
            mex
        }

        try {
            endpointService.startEndpoint(alice, listener).use {

                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .acceptConnectionFrom(alice)

                val pcon = mex.getConnection()
                assertEquals(ConnectionState.ACTIVE, pcon?.state)

                mex.withProtocol(RFC0095_BASIC_MESSAGE)
                    .sendMessage("Ich habe Sauerkraut in meinen Lederhosen")

                val myDid = pcon?.myDid
                log.info { "My Did: $myDid" }

                val faberClient = faber.walletClient() as AriesClient
                val faberConId = faberClient.connections().get()
                    .filter { it.state.toString() == "ACTIVE" }
                    .firstOrNull { it.theirDid == myDid?.id }?.connectionId
                checkNotNull(faberConId) { "No Faber connection" }

                val msg = "I have an Elk under my Fedora"
                faberClient.connectionsSendMessage(faberConId, SendMessage.builder().content(msg).build())

                val epm = basicMessageFuture.get(5, TimeUnit.SECONDS)
                assertEquals(msg, epm.bodyAsJson.selectJson("content"))
            }
        } finally {
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }
}
