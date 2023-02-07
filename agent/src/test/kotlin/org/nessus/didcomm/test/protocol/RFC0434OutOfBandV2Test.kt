/*-
 * #%L
 * Nessus DIDComm :: Core
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
package org.nessus.didcomm.test.protocol

import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocolV2.Companion.RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Acme
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RFC0434OutOfBandV2Test: AbstractDidCommTest() {

    @Test
    fun createOutOfBandInvitationV2() {

        val acme = Wallet.Builder(Acme.name)
            .build()

        try {
            val invitation = MessageExchange()
                .withProtocol(RFC0434_OUT_OF_BAND_V2)
                .createOutOfBandInvitation(acme, mapOf(
                    "goal_code" to "issue-vc",
                    "goal" to "Employment credential with Acme"))
                .getMessageExchange()
                .getInvitation()

            assertTrue(invitation is Invitation)
            assertEquals(RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2, invitation.type)
            assertEquals("issue-vc", invitation.actV2.goalCode)
            assertEquals("Employment credential with Acme", invitation.actV2.goal)

        } finally {
            removeWallet(Acme.name)
        }
    }
}
