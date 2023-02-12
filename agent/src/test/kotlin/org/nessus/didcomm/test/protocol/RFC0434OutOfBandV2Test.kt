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

import org.didcommx.didcomm.message.Message
import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocolV2.Companion.RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Acme
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.decodeMessage
import org.nessus.didcomm.util.trimJson
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Nessus DIDComm RFC0434: Out-of-Band Invitation 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0434-oob-invitation
 */
class RFC0434OutOfBandV2Test: AbstractDidCommTest() {

    @Test
    fun testRFC0434OutOfBandV2() {

        val acme = Wallet.Builder(Acme.name)
            .build()

        val alice = Wallet.Builder(Alice.name)
            .build()

        try {
            val mex = MessageExchange()
                .withProtocol(RFC0434_OUT_OF_BAND_V2)
                .createOutOfBandInvitation(acme, mapOf(
                    "goal_code" to "issue-vc",
                    "goal" to "Employment credential with Acme"))
                .receiveOutOfBandInvitation(alice)
                .getMessageExchange()

            val invitation = mex.getInvitation()
            assertTrue(invitation is Invitation)
            assertEquals(RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2, invitation.type)
            assertEquals("issue-vc", invitation.actV2.goalCode)
            assertEquals("Employment credential with Acme", invitation.actV2.goal)

            assertNotNull(acme.findInvitation { it.id == invitation.id }, "Acme invitation")
            assertNotNull(alice.findInvitation { it.id == invitation.id }, "Alice invitation")

            val aliceAcme = mex.getConnection()
            assertEquals(ConnectionState.INVITATION, aliceAcme.state)
            assertEquals("Invitee Alice on NESSUS", aliceAcme.myLabel)

            assertNotNull(acme.findConnection { it.invitationKey == invitation.invitationKey() }, "Acme connection")
            assertNotNull(alice.findConnection { it.invitationKey == invitation.invitationKey() }, "Alice connection")

        } finally {
            removeWallet(Alice.name)
            removeWallet(Acme.name)
        }
    }

    @Test
    fun testInvitationV2() {

        val exp = """
        {
          "type": "https://didcomm.org/out-of-band/2.0/invitation",
          "id": "1234567890",
          "from": "did:example:faber",
          "body": {
            "goal_code": "issue-vc",
            "goal": "To issue a Faber College Graduate credential",
            "accept": [
              "didcomm/v2",
              "didcomm/aip2;env=rfc587"
            ]
          },
          "attachments": [
            {
                "id": "request-0",
                "media_type": "application/json",
                "data": {
                    "json": {"protocol message": "content"}
                }
            }
          ]
        }                
        """.trimJson()

        val expMsg: Message = exp.decodeMessage()
        val inviV2: InvitationV2 = InvitationV2.fromMessage(expMsg)

        val wasMsg: Message = inviV2.toMessage()
        assertEquals(expMsg.toJSONObject(), wasMsg.toJSONObject())
    }
}
