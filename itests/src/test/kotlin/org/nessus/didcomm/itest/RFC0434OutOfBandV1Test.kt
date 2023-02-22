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

import io.kotest.core.annotation.EnabledIf
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.InvitationState
import org.nessus.didcomm.model.InvitationV1
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V1

/**
 * Aries RFC 0434: Out-of-Band Protocol 1.1
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
 *
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
@EnabledIf(AcaPyOnlyCondition::class)
class RFC0434OutOfBandV1Test : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_invites_AliceNessus() {

        /**
         * Create the Wallets
         */

        val faber = Wallet.Builder(Faber.name)
            .options(ACAPY_OPTIONS_01)
            .agentType(AgentType.ACAPY)
            .build()

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .build()

        try {

            /**
             * Inviter (Faber) creates an Out-of-Band Invitation
             * Invitee (Alice) receives the Invitation
             */

            val mex = MessageExchange()
                .withProtocol(RFC0434_OUT_OF_BAND_V1)
                .createOutOfBandInvitation(faber, "Faber invites Alice")
                .receiveOutOfBandInvitation(alice)
                .getMessageExchange()

            mex.messages.size shouldBe 1

            val invitation = mex.last.body as? InvitationV1
            invitation?.state shouldBe InvitationState.DONE

        } finally {
            removeWallet(Alice.name)
            removeWallet(Faber.name)
        }
    }

    @Test
    fun test_AliceNessus_invites_FaberAcapy() {

        /**
         * Create the Wallets
         */

        val faber = Wallet.Builder(Faber.name)
            .options(ACAPY_OPTIONS_01)
            .agentType(AgentType.ACAPY)
            .build()

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .build()

        try {

            /**
             * Inviter (Alice) creates an Out-of-Band Invitation
             * Invitee (Faber) receives the Invitation
             */

            val mex = MessageExchange()
                .withProtocol(RFC0434_OUT_OF_BAND_V1)
                .createOutOfBandInvitation(alice, "Alice invites Faber")
                .receiveOutOfBandInvitation(faber)
                .getMessageExchange()

            mex.messages.size shouldBe 1

            val invitation = mex.last.body as? InvitationV1
            invitation?.state shouldBe InvitationState.DONE

        } finally {
            removeWallet(Alice.name)
            removeWallet(Faber.name)
        }
    }
}
