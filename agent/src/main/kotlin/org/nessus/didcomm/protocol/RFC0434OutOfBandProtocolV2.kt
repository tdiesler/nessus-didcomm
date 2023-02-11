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
import org.didcommx.didcomm.protocols.routing.PROFILE_DIDCOMM_V2
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import java.util.UUID

/**
 * Nessus DIDComm RFC0434: Out-of-Band Invitation 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0434-oob-invitation
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
     * label: String
     */
    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocolV2 {
        checkAgentType(inviter.agentType)

        val id = "${UUID.randomUUID()}"
        val type = RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2
        val invitationDid = inviter.createDid(DidMethod.KEY)
        val inviterEndpointUrl = inviter.endpointUrl

        // Create and register the Did Document for this Invitation
        diddocV2Service.createDidDocument(invitationDid, inviterEndpointUrl)

        val service = Invitation.Service(
            id = "#inline",
            type = "did-communication",
            recipientKeys = listOf(invitationDid.qualified),
            serviceEndpoint = inviterEndpointUrl
        )

        val dataJson = Attachment.Data.Json.parse(mapOf(
            "json" to gson.toJson(service).decodeJson()
        ))
        val attachment = Attachment.Builder("${UUID.randomUUID()}", dataJson)
            .build()

        val invitationV2 = InvitationV2.Builder(id, type, invitationDid.qualified)
            .goalCode(options["goal_code"] as? String)
            .goal(options["goal"] as? String)
            .accept(listOf(PROFILE_DIDCOMM_V2))
            .attachments(listOf(attachment))
            .build()

        val message = invitationV2.toMessage()
        log.info { "Inviter (${inviter.name}) created Invitation: ${message.prettyPrint()}" }

        val epm = EndpointMessage(message)
        mex.addMessage(epm)

        mex.putAttachment(WALLET_ATTACHMENT_KEY, inviter)
        inviter.addInvitation(Invitation(invitationV2))

        val invitationKey = invitationV2.invitationKey()
        val myLabel = options["label"] as? String ?: "Invitation from ${inviter.name}"

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = inviter.agentType,
            invitationKey = invitationKey,
            myDid = invitationDid,
            myRole = ConnectionRole.INVITER,
            myLabel = myLabel,
            myEndpointUrl = inviter.endpointUrl,
            theirDid = null,
            theirRole = ConnectionRole.INVITEE,
            theirLabel = null,
            theirEndpointUrl = null,
            state = ConnectionState.INVITATION
        )

        mex.setConnection(pcon)
        inviter.addConnection(pcon)

        return this
    }

    fun receiveOutOfBandInvitation(invitee: Wallet): RFC0434OutOfBandProtocolV2 {
        checkAgentType(invitee.agentType)

        val invitation = mex.getInvitation() as Invitation
        log.info { "Invitee (${invitee.name}) received Invitation: ${invitation.prettyPrint()}"}

        // [TODO] invitation state for v2
        // check(invitation.state == InvitationState.INITIAL) { "Unexpected invitation state: $invitation" }

        // Start a new MessageExchange
        val inviteeMex = MessageExchange()
        inviteeMex.putAttachment(WALLET_ATTACHMENT_KEY, invitee)

        val invitationV2 = invitation.actV2
        val epm = EndpointMessage(invitationV2.toMessage())
        inviteeMex.addMessage(epm)

        // Create and attach the Connection

        val inviteeDid = invitee.createDid(DidMethod.KEY)
        val inviteeLabel = "Invitee ${invitee.name} on ${invitee.agentType}"
        val inviteeEndpointUrl = invitee.endpointUrl
        val invitationKey = invitation.invitationKey()

        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = invitee.agentType,
            invitationKey = invitationKey,
            myDid = inviteeDid,
            myRole = ConnectionRole.INVITEE,
            myLabel = inviteeLabel,
            myEndpointUrl = inviteeEndpointUrl,
            theirDid = null,
            theirRole = ConnectionRole.INVITER,
            theirLabel = null,
            theirEndpointUrl = null,
            state = ConnectionState.INVITATION
        )

        inviteeMex.setConnection(pcon)
        invitee.addConnection(pcon)

        // Associate this invitation with the invitee wallet
        // invitationV2.state = InvitationState.RECEIVED
        // invitationV2.state = InvitationState.DONE
        invitee.addInvitation(invitation)

        // Returns an instance of this protocol associated with another MessageExchange
        return inviteeMex.withProtocol(RFC0434_OUT_OF_BAND_V2)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
