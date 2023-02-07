/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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
package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV2Builder
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import java.util.*

/**
 * RFC 0434: Out-of-Band Invitation 2.0
 * https://identity.foundation/didcomm-messaging/spec/#invitation
 */
class RFC0434OutOfBandProtocolV2(mex: MessageExchange): Protocol<RFC0434OutOfBandProtocolV2>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0434_OUT_OF_BAND_V2.uri

    companion object {
        val RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2 = "${RFC0434_OUT_OF_BAND_V2.uri}/invitation"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    /**
     * Creates an out-of-band invitation message
     *
     * Supported options
     * -----------------
     * goal_code: String
     * goal: String
     */
    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocolV2 {
        checkAgentType(inviter.agentType)


        val id = "${UUID.randomUUID()}"
        val type = RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2
        val inviterDid = inviter.createDid(DidMethod.KEY)
        val from = inviterDid.qualified

        val service = Invitation.Service(
            id = "#inline",
            type = "did-communication",
            recipientKeys = listOf(inviterDid.qualified),
            serviceEndpoint = inviter.endpointUrl
        )

        val dataJson = Attachment.Data.Json.parse(mapOf(
            "json" to gson.toJson(service).decodeJson()
        ))
        val attachment = Attachment.Builder("${UUID.randomUUID()}", dataJson)
            .build()

        val invitationV2 = InvitationV2Builder(id, type, from)
            .goalCode(options["goal_code"] as? String)
            .goal(options["goal"] as? String)
            .accept(listOf("didcomm/v2", "didcomm/aip2;env=rfc587"))
            .attachments(listOf(attachment))
            .build()

        val message = invitationV2.toMessage()
        log.info { "Inviter (${inviter.name}) created Invitation: ${message.prettyPrint()}" }

        val epm = EndpointMessage(message)
        mex.addMessage(epm)

        mex.putAttachment(WALLET_ATTACHMENT_KEY, inviter)
        inviter.addInvitation(Invitation(invitationV2))

        return this
    }

    fun receiveOutOfBandInvitation(invitee: Wallet): RFC0434OutOfBandProtocolV2 {
        checkAgentType(invitee.agentType)

        val invitation = mex.getInvitation() as Invitation
        log.info { "Invitee (${invitee.name}) received Invitation: ${invitation.prettyPrint()}"}

        // [TODO] invitation state for v2
        // check(invitation.state == InvitationState.INITIAL) { "Unexpected invitation state: $invitation" }

        val rfc0434 = receiveOutOfBandInvitationNessus(invitee, invitation)

        // Associate this invitation with the invitee wallet
        // invitationV2.state = InvitationState.RECEIVED
        // invitationV2.state = InvitationState.DONE
        invitee.addInvitation(invitation)

        // Returns an instance of this protocol associated with another MessageExchange
        return rfc0434
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun receiveOutOfBandInvitationNessus(invitee: Wallet, invitation: Invitation): RFC0434OutOfBandProtocolV2 {

        // Start a new MessageExchange
        val inviteeMex = MessageExchange()
        inviteeMex.putAttachment(WALLET_ATTACHMENT_KEY, invitee)

        val invitationV2 = invitation.actV2
        val epm = EndpointMessage(invitationV2.toMessage())
        inviteeMex.addMessage(epm)

        val myDid = invitee.createDid(DidMethod.KEY)
        val myLabel = "Invitee ${invitee.name} on ${invitee.agentType}"
        val myEndpointUrl = invitee.endpointUrl
        val invitationKey = invitation.invitationKey()

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = invitee.agentType,
            invitationKey = invitationKey,
            myDid = myDid,
            myRole = ConnectionRole.INVITEE,
            myLabel = myLabel,
            myEndpointUrl = myEndpointUrl,
            theirDid = null,
            theirRole = ConnectionRole.INVITER,
            theirLabel = null,
            theirEndpointUrl = null,
            state = ConnectionState.INVITATION
        )

        inviteeMex.setConnection(pcon)
        invitee.addConnection(pcon)

        return inviteeMex.withProtocol(RFC0434_OUT_OF_BAND_V2)
    }

}
