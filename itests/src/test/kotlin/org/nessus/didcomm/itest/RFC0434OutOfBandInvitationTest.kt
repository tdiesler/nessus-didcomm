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
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
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
class RFC0434OutOfBandInvitationTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_invites_AliceAcapy() {

        /**
         * Create the Wallets
         */

        val faber = getWalletByAlias(Faber.name) ?: fail("No Inviter")

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .build()

        try {

            /**
             * Inviter (Faber) creates an Out-of-Band Invitation
             */

            val rfc0434 = MessageExchange().withProtocol(RFC0434_OUT_OF_BAND)
                .createOutOfBandInvitation(faber, mapOf(
                    "goalCode" to "Faber invites Alice",
                    "usePublicDid" to false,
                    "autoAccept" to true,
                ))

            /**
             * Invitee (Alice) receives the Invitation
             */

            rfc0434.receiveOutOfBandInvitation(alice)

        } finally {
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }
}
