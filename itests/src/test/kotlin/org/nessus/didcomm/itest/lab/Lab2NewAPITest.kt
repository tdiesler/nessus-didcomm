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
package org.nessus.didcomm.itest.lab

import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.itest.AbstractIntegrationTest
import org.nessus.didcomm.itest.Alice
import org.nessus.didcomm.itest.Faber
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.MESSAGE_EXCHANGE_INVITEE_CONNECTION_ID_KEY
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol.Companion.PROTOCOL_METHOD_RECEIVE_INVITATION
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0023_DID_EXCHANGE
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.StorageType
import org.nessus.didcomm.wallet.Wallet
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.fail


/**
 * Aries RFC 0434: Out-of-Band Protocol 1.1
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
 *
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 *
 * DIDComm - Out Of Band Messages
 * https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
 */
class Lab2NewAPITest : AbstractIntegrationTest() {

    @Test
    fun test_AliceNessus_invites_FaberAcapy() {

        val alice = Wallet.Builder(Alice.name)
            .agentType(AgentType.NESSUS)
            .storageType(StorageType.IN_MEMORY)
            .build()

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        try {

            endpointService.startEndpoint().use {

                /**
                 * Inviter (Alice) creates an Out-of-Band Invitation
                 */

                val mex = MessageExchange()
                    .withProtocol(PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1)
                    .createOutOfBandInvitation(alice)
                    .dispatchToWallet(faber, mapOf(
                        MESSAGE_PROTOCOL_METHOD to PROTOCOL_METHOD_RECEIVE_INVITATION))
                    .withProtocol(PROTOCOL_URI_RFC0023_DID_EXCHANGE)
                    .awaitReceiveDidExchangeRequest(5, TimeUnit.SECONDS)
                    .peekMessageExchange()

                // Verify that the Faber connection is in state 'request'
                val faberClient = faber.walletClient() as AriesClient
                val faberConnectionId = mex.getAttachment(MESSAGE_EXCHANGE_INVITEE_CONNECTION_ID_KEY) as String
                val connectionRecord = faberClient.connectionsGetById(faberConnectionId).get()
                assertEquals("inviter", connectionRecord.theirRole.name.lowercase())
                assertEquals("request", connectionRecord.state.name.lowercase())

                // StorageNotFoundError: Record not found
                //val acceptRequestFilter = DidExchangeAcceptRequestFilter.builder().build()
                //faberClient.didExchangeAcceptRequest(faberConnectionId, acceptRequestFilter)

                // Returns the did doc that we already got as response to /receive-invitation
                //val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
                //faberClient.didExchangeAcceptInvitation(faberConnectionId, acceptInvitationFilter)
            }

        } finally {
            faber.removeConnections()
            removeWallet(alice)
        }
    }
}
