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
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.DidPeer
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.DidPeerOptions
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import java.util.UUID

/**
 * Nessus DIDComm: Out-of-Band Invitation 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0434-oob-invitation
 */
class OutOfBandV2Protocol(mex: MessageExchange): Protocol<OutOfBandV2Protocol>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = OUT_OF_BAND_PROTOCOL_V2.uri

    companion object {
        val OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2 = "${OUT_OF_BAND_PROTOCOL_V2.uri}/invitation"
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
    fun createOutOfBandInvitation(inviter: Wallet, did: Did? = null, options: Map<String, Any> = mapOf()): OutOfBandV2Protocol {
        checkAgentType(inviter.agentType)

        val id = "${UUID.randomUUID()}"
        val type = OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2

        // Create and register the Did Document for this Invitation
        val invitationDid = did ?: inviter.createDid()

        val invitationBuilder = InvitationV2.Builder(id, type, invitationDid.uri)
            .goalCode(options["goal_code"] as? String)
            .goal(options["goal"] as? String)
            .accept(InvitationV2.DEFAULT_ACCEPT)

        // Add the DidDoc attachment when we don't have a did:peer:2
        val maybeDidPeer = DidPeer.fromUri(invitationDid.uri)
        if (maybeDidPeer?.numalgo != 2) {
            val invitationDidDoc = didService.loadDidDoc(invitationDid.uri)
            val invitationDidDocAttachment = invitationDidDoc.toAttachment()
            invitationBuilder.attachments(listOf(invitationDidDocAttachment))
        }
        val invitationV2 = invitationBuilder.build()

        val message = invitationV2.toMessage()
        log.info { "Inviter (${inviter.name}) created Invitation: ${message.prettyPrint()}" }

        val epm = EndpointMessage(message)
        mex.addMessage(epm)

        mex.putAttachment(WALLET_ATTACHMENT_KEY, inviter)
        inviter.addInvitation(Invitation(invitationV2))

        val invitationKey = invitationV2.invitationKey()

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            invitationKey = invitationKey,
            myDid = invitationDid,
            myAgent = inviter.agentType.value,
            myRole = ConnectionRole.INVITER,
            myLabel = inviter.name,
            myEndpointUrl = inviter.endpointUrl,
            theirDid = null,
            theirAgent = null,
            theirRole = ConnectionRole.INVITEE,
            theirLabel = null,
            theirEndpointUrl = null,
            state = ConnectionState.INVITATION
        )

        mex.setConnection(pcon)
        inviter.addConnection(pcon)

        return this
    }

    fun receiveOutOfBandInvitation(
        invitee: Wallet,
        did: Did? = null,
        inviterAlias: String? = null,
        inviterAgent: String? = null
    ): OutOfBandV2Protocol {
        checkAgentType(invitee.agentType)

        val invitation = mex.getInvitation()
        checkNotNull(invitation) { "No invitation" }
        check(invitation.isV2) { "Invalid invitation" }
        log.info { "Invitee (${invitee.name}) received Invitation: ${invitation.prettyPrint()}"}

        // [TODO] invitation state for v2
        // check(invitation.state == InvitationState.INITIAL) { "Unexpected invitation state: $invitation" }

        // Extract Inviter Did + Document
        val invitationV2 = invitation.actV2
        val inviterDidDoc = invitationV2.diddoc
        didService.importDidDoc(inviterDidDoc)

        val inviterDid = Did.fromUri(inviterDidDoc.id)
        val inviterEndpointUrl = inviterDidDoc.serviceEndpoint
        checkNotNull(inviterEndpointUrl) { "No inviter endpointUrl" }

        // Create Invitee Did + Document
        val inviteeEndpointUrl = invitee.endpointUrl
        val inviteeDid = did ?: when(inviterDid.method) {
            DidMethod.PEER -> invitee.createDid(inviterDid.method, options = DidPeerOptions(2, inviteeEndpointUrl))
            else -> invitee.createDid(inviterDid.method)
        }

        // Start a new MessageExchange
        val inviteeMex = MessageExchange()
        inviteeMex.putAttachment(WALLET_ATTACHMENT_KEY, invitee)

        val epm = EndpointMessage(invitationV2.toMessage())
        inviteeMex.addMessage(epm)

        // Create and attach the Connection

        val invitationKey = invitation.invitationKey()

        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            invitationKey = invitationKey,
            myDid = inviteeDid,
            myAgent = invitee.agentType.value,
            myRole = ConnectionRole.INVITEE,
            myLabel = invitee.name,
            myEndpointUrl = inviteeEndpointUrl,
            theirDid = inviterDid,
            theirAgent = inviterAgent,
            theirRole = ConnectionRole.INVITER,
            theirLabel = inviterAlias,
            theirEndpointUrl = inviterEndpointUrl,
            state = ConnectionState.INVITATION
        )

        inviteeMex.setConnection(pcon)
        invitee.addConnection(pcon)

        // Associate this invitation with the invitee wallet
        // invitationV2.state = InvitationState.RECEIVED
        // invitationV2.state = InvitationState.DONE
        invitee.addInvitation(invitation)

        // Returns an instance of this protocol associated with another MessageExchange
        return inviteeMex.withProtocol(OUT_OF_BAND_PROTOCOL_V2)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
