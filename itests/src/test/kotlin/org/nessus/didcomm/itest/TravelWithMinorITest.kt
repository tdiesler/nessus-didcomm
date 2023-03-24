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
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.util.NessusIsLiveCondition
import java.net.URL

/**
 * Nessus DIDComm RFC0434: Out-of-Band Invitation 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0434-oob-invitation
 */
@EnabledIf(NessusIsLiveCondition::class)
class TravelWithMinorITest<T: AutoCloseable> : AbstractIntegrationTest() {

    private var malathi: Wallet? = null

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint(NESSUS_OPTIONS)
        malathi = Wallet.Builder("Malathi")
            .build()
    }

    @AfterAll
    fun stopAgent() {
        removeWallet(malathi!!)
        stopNessusEndpoint<T>()
    }

    @Test
    fun issuePassport_DidKey() {

        /**
         * Invitee (Malathi) receives the Invitation from the Government
         */

        val invitationUrl = "http://localhost:9100/dashboard/invitation?inviter=Government&method=key"
        val invitationV2 = InvitationV2.fromUrl(URL(invitationUrl))

        val mex = MessageExchange()
            .withAttachment(MessageExchange.INVITATION_ATTACHMENT_KEY, Invitation(invitationV2))
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .receiveOutOfBandInvitation(malathi!!)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()
            .getMessageExchange()

        val pcon = mex.getConnection()
        pcon.state shouldBe ConnectionState.ACTIVE
    }

    @Test
    fun issuePassport_DidPeer() {

        /**
         * Invitee (Malathi) receives the Invitation from the Government
         */

        val invitationUrl = "http://localhost:9100/dashboard/invitation?inviter=Government&method=peer"
        val invitationV2 = InvitationV2.fromUrl(URL(invitationUrl))

        val mex = MessageExchange()
            .withAttachment(MessageExchange.INVITATION_ATTACHMENT_KEY, Invitation(invitationV2))
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .receiveOutOfBandInvitation(malathi!!)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()
            .getMessageExchange()

        val pcon = mex.getConnection()
        pcon.state shouldBe ConnectionState.ACTIVE
    }
}
