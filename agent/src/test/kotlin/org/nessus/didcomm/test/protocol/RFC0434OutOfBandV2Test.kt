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

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocolV2.Companion.RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Acme
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.decodeMessage
import org.nessus.didcomm.util.trimJson

/**
 * Nessus DIDComm RFC0434: Out-of-Band Invitation 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0434-oob-invitation
 */
class RFC0434OutOfBandV2Test: AbstractAgentTest() {

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

            val invitation = mex.getInvitation() as Invitation
            invitation.type shouldBe RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2
            invitation.actV2.goalCode shouldBe "issue-vc"
            invitation.actV2.goal shouldBe "Employment credential with Acme"

            acme.findInvitation { it.id == invitation.id } shouldNotBe null
            alice.findInvitation { it.id == invitation.id } shouldNotBe null

            val aliceAcme = mex.getConnection()
            aliceAcme.state shouldBe ConnectionState.INVITATION
            aliceAcme.myLabel shouldBe "Invitee Alice on NESSUS"

            acme.findConnection { it.invitationKey == invitation.invitationKey() } shouldNotBe null
            alice.findConnection { it.invitationKey == invitation.invitationKey() } shouldNotBe null

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
        wasMsg.toJSONObject() shouldBe expMsg.toJSONObject()
    }
}
