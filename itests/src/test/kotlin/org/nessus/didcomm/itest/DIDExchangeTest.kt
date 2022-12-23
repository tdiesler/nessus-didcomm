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

import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.aries.AriesAgentService
import org.nessus.didcomm.agent.aries.AriesWalletService
import org.nessus.didcomm.model.MessageReader
import org.nessus.didcomm.model.MessageType.Companion.OUT_OF_BAND_INVITATION
import org.nessus.didcomm.model.MessageWriter
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.agentService
import kotlin.test.assertEquals

/**
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
class DIDExchangeTest : AbstractAriesTest() {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.addService(AriesAgentService())
            ServiceRegistry.addService(AriesWalletService())
        }
    }

    @Test
    fun testFaberInvitesAlice() {

        val faber = getWalletByName(FABER)!!
        val alice = getWalletByName(ALICE)

        // Create the OOB Invitation through the Agent
        val body = MessageWriter.toMutableMap("""
            {
                "goal_code": "did-exchange",
                "goal": "Faber College invites you for a DID exchange",
                "accept": [ "didcomm/v2" ]
            }
        """.trimIndent())
        val msg: Message = agentService().createMessage(faber, OUT_OF_BAND_INVITATION, body)

        // Verify the DCV2 message
        val att0: Attachment = msg.attachments?.get(0)!!
        val invJson = MessageWriter.toJson(att0.data.toJSONObject()["json"]!!)
        val invRec: InvitationRecord = MessageReader.fromJson(invJson, InvitationRecord::class.java)
        assertEquals(att0.id, invRec.inviMsgId)
    }
}
