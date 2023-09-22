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
package org.nessus.didcomm.test.json

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.nessus.didcomm.json.model.InvitationData
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.WalletRole

class InvitationRpcTest: AbstractJsonRpcTest() {

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
    }

    @Test
    fun createInvitation() {
        val faber = createWallet("Faber", WalletRole.ENDORSER)
        try {
            val dataA = InvitationData(faber.id)
            val invitationA = createInvitation(dataA)
            assertTrue(invitationA.diddoc.id.startsWith("did:key"))

            val didPeer = faber.createDid(DidMethod.PEER)
            val dataB = InvitationData(faber.id, didUri = didPeer.uri)
            val invitationB = createInvitation(dataB)
            assertTrue(invitationB.diddoc.id.startsWith("did:peer"))

            val dataC = InvitationData(faber.id, options = mapOf(
                "goal" to "some_goal",
                "goal_code" to "some_goal_code"))
            val invitationC = createInvitation(dataC)
            assertEquals(invitationC.goal, "some_goal")
            assertEquals(invitationC.goalCode, "some_goal_code")
        } finally {
            removeWallets()
        }
    }

    @Test
    fun receiveInvitation() {
        val faber = createWallet("Faber", WalletRole.ENDORSER)
        val alice = createWallet("Alice")
        try {
            val invitation = createInvitation(InvitationData(faber.id))
            val encoded = invitation.encodeBase64()

            val pcon = receiveInvitation(InvitationData(inviteeId = alice.id, inviterAlias = faber.alias, urlEncoded = encoded))
            assertEquals(ConnectionState.ACTIVE, pcon.state)
        } finally {
            removeWallets(alice, faber)
        }
    }
}
