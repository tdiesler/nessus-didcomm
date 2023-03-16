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
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidDoc
import org.nessus.didcomm.did.DidDocV2
import org.nessus.didcomm.did.DidPeer
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITEE_DID_DOCUMENT_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITER_DID_DOCUMENT_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
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
    fun createOutOfBandInvitation(inviter: Wallet, did: Did? = null, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocolV2 {
        checkAgentType(inviter.agentType)

        val id = "${UUID.randomUUID()}"
        val type = RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V2

        // Create and register the Did Document for this Invitation
        val invitationDid = did ?: inviter.createDid()

        val invitationBuilder = InvitationV2.Builder(id, type, invitationDid.uri)
            .goalCode(options["goal_code"] as? String)
            .goal(options["goal"] as? String)
            .accept(DidDocV2.DEFAULT_ACCEPT)

        // Add the DidDoc attachment when we don't have a did:peer:2
        val maybeDidPeer = DidPeer.fromUri(invitationDid.uri)
        if (maybeDidPeer?.numalgo != 2) {
            val invitationDidDoc = diddocV2Service.resolveDidDocument(invitationDid.uri)
            val invitationDidDocAttachment = diddocV2Service.createDidDocAttachment(invitationDidDoc)
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
        val inviterLabel = options["label"] as? String ?: "Invitation from ${inviter.name}"

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = inviter.agentType,
            invitationKey = invitationKey,
            myDid = invitationDid,
            myRole = ConnectionRole.INVITER,
            myLabel = inviterLabel,
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

    fun receiveOutOfBandInvitation(invitee: Wallet, did: Did? = null): RFC0434OutOfBandProtocolV2 {
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
        mex.putAttachment(INVITER_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(inviterDidDoc))

        val inviterDid = Did.fromUri(inviterDidDoc.id)
        val inviterEndpointUrl = inviterDidDoc.serviceEndpoint()

        // Create Invitee Did + Document
        val inviteeEndpointUrl = invitee.endpointUrl
        val inviteeDid = did ?: invitee.createDid(inviterDid.method)
        val inviteeDidDoc = diddocV2Service.resolveDidDocument(inviteeDid.uri)
        mex.putAttachment(INVITEE_DID_DOCUMENT_ATTACHMENT_KEY, DidDoc(inviteeDidDoc))

        // Start a new MessageExchange
        val inviteeMex = MessageExchange()
        inviteeMex.putAttachment(WALLET_ATTACHMENT_KEY, invitee)

        val epm = EndpointMessage(invitationV2.toMessage())
        inviteeMex.addMessage(epm)

        // Create and attach the Connection

        val inviteeLabel = "Invitee ${invitee.name} on ${invitee.agentType}"
        val invitationKey = invitation.invitationKey()

        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = invitee.agentType,
            invitationKey = invitationKey,
            myDid = inviteeDid,
            myRole = ConnectionRole.INVITEE,
            myLabel = inviteeLabel,
            myEndpointUrl = inviteeEndpointUrl,
            theirDid = inviterDid,
            theirRole = ConnectionRole.INVITER,
            theirLabel = null,
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
        return inviteeMex.withProtocol(RFC0434_OUT_OF_BAND_V2)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
