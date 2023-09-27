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
package org.nessus.didcomm.json

import kotlinx.serialization.json.Json
import org.nessus.didcomm.json.model.InvitationData
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2

object InvitationApiHandler: AbstractApiHandler() {

    @JvmStatic
    fun createInvitation(payload: String): Invitation {
        val data = Json.decodeFromString<InvitationData>(payload)
        checkNotNull(data.inviterId) { "No inviterId" }
        val inviterDid = data.didUri?.let { Did.fromUri(it) }
        val inviter = assertWallet(data.inviterId)
        val mex = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(inviter, inviterDid, data.didMethod, data.options)
            .getMessageExchange()
        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }
        return invitation
    }

    @JvmStatic
    fun receiveInvitation(payload: String): Connection {
        val data = Json.decodeFromString<InvitationData>(payload)
        checkNotNull(data.inviteeId) { "No inviteeId" }
        checkNotNull(data.urlEncoded) { "No invitation" }
        val invitee = assertWallet(data.inviteeId)
        val inviteeDid = data.didUri?.let { Did.fromUri(it) }
        val inviterAlias = data.inviterAlias
        val invitation = Invitation.fromBase64(data.urlEncoded)
        val mex = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .receiveOutOfBandInvitation(invitee, inviteeDid, inviterAlias, invitation)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()
        return mex.getConnection()
    }
}
