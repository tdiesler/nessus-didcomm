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

import org.junit.jupiter.api.Test
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_AUTO_ACCEPT
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.MESSAGE_EXCHANGE_PEER_CONNECTION_KEY
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol.Companion.OOB_METHOD_RECEIVE_INVITATION
import org.nessus.didcomm.service.ConnectionState
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertEquals
import kotlin.test.assertNotNull


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
class RFC0434OutOfBandTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_invites_AliceAcapy() {

        /**
         * Create the Wallets
         */

        val inviter = Wallet.Builder(Faber.name)
            .walletAgent(WalletAgent.ACAPY)
            .walletType(WalletType.INDY)
            .mayExist(true)
            .build()

        val invitee = Wallet.Builder(Alice.name)
            .walletAgent(WalletAgent.ACAPY)
            .walletType(WalletType.IN_MEMORY)
            .build()

        val inviterAutoAccept = true
        val inviteeAutoAccept = true

        try {

            /**
             * Inviter (Faber) creates an Out-of-Band Invitation
             */

            val rfc0434 = inviter.getProtocol(PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1)
            val mex: MessageExchange = rfc0434.createOutOfBandInvitation(inviter, mapOf(
                "goalCode" to "Faber invites Alice",
                "autoAccept" to inviterAutoAccept,
                "usePublicDid" to false,
            ))

            /**
             * Invitee (Alice) receives the Invitation
             *
             * Note, we could equally call `rfc0434.receiveOutOfBandInvitation`
             * here we test the fluent API and the route through the MessageDispatcher
             */

            mex.dispatchTo(invitee, mapOf(
                MESSAGE_PROTOCOL_METHOD to OOB_METHOD_RECEIVE_INVITATION,
                MESSAGE_AUTO_ACCEPT to inviteeAutoAccept,
            ))

            /**
             * Invitee (Alice) accepts the Invitation
             */
            if (!inviteeAutoAccept) {
                rfc0434.acceptDidExchange(invitee, mex)
            }

            /**
             * Verify that we have an active connection
             */
            val peerConnection = mex.getAttachment(MESSAGE_EXCHANGE_PEER_CONNECTION_KEY)
            assertNotNull(peerConnection) {"${invitee.alias} has no peer connection"}
            assertEquals(ConnectionState.ACTIVE, peerConnection.state)

        } finally {
            removeWallet(invitee)
        }
    }
}
