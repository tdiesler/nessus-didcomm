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
import org.didcommx.didcomm.protocols.routing.PROFILE_DIDCOMM_V2
import org.hyperledger.aries.api.connection.ConnectionFilter
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.InvitationMessage.InvitationMessageService
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationState
import org.nessus.didcomm.model.InvitationV1
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_THID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_TYPE
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocolV1.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V1
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.gsonPretty
import org.nessus.didcomm.wallet.AcapyWallet
import org.nessus.didcomm.wallet.NessusWallet
import java.util.UUID

/**
 * Aries RFC 0434: Out-of-Band Protocol 1.1
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
 *
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 *
 * DIDComm - Out Of Band Messages
 * https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
 */
class RFC0434OutOfBandProtocolV1(mex: MessageExchange): Protocol<RFC0434OutOfBandProtocolV1>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0434_OUT_OF_BAND_V1.uri

    companion object {
        val RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V1 = "${RFC0434_OUT_OF_BAND_V1.uri}/invitation"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.ACAPY, AgentType.NESSUS)

    fun createOutOfBandInvitation(inviter: Wallet, label: String): RFC0434OutOfBandProtocolV1 {
        return createOutOfBandInvitation(inviter, mapOf("label" to label))
    }

    /**
     * Creates an out-of-band invitation message
     *
     * Supported options
     * -----------------
     * label: String
     * usePublicDid: Boolean (false)
     * autoAccept: Boolean (true)
     */
    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocolV1 {

        val label = options["label"] as? String ?: "Invitation from ${inviter.name}"

        val invitationV1 = if (inviter.agentType == AgentType.ACAPY) {
            createOutOfBandInvitationAcapy(inviter as AcapyWallet, label, options)
        } else {
            createOutOfBandInvitationNessus(inviter as NessusWallet, label)
        }.validate()
        log.info { "Inviter (${inviter.name}) created Invitation: ${gsonPretty.toJson(invitationV1)}" }

        mex.addMessage(EndpointMessage(
            invitationV1, mapOf(
                MESSAGE_HEADER_PROTOCOL_URI to protocolUri,
                MESSAGE_HEADER_ID to invitationV1.id,
                MESSAGE_HEADER_THID to invitationV1.id,
                MESSAGE_HEADER_TYPE to invitationV1.type,
            )
        ))

        mex.putAttachment(WALLET_ATTACHMENT_KEY, inviter)
        inviter.addInvitation(Invitation(invitationV1))

        return this
    }

    fun receiveOutOfBandInvitation(invitee: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocolV1 {

        val invitation = mex.getInvitation() as Invitation
        val invitationV1 = invitation.actV1
        log.info { "Invitee (${invitee.name}) received Invitation: ${invitation.prettyPrint()}"}
        check(invitationV1.state == InvitationState.INITIAL) { "Unexpected invitation state: $invitation" }

        val rfc0434 = when(invitee.agentType) {
            AgentType.ACAPY -> receiveOutOfBandInvitationAcapy(invitee as AcapyWallet, invitationV1, options)
            AgentType.NESSUS -> receiveOutOfBandInvitationNessus(invitee as NessusWallet, invitationV1)
        }

        // Associate this invitation with the invitee wallet
        invitationV1.state = InvitationState.RECEIVED
        invitationV1.state = InvitationState.DONE
        invitee.addInvitation(invitation)

        // Returns an instance of this protocol associated with another MessageExchange
        return rfc0434
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createOutOfBandInvitationAcapy(inviter: AcapyWallet, label: String, options: Map<String, Any>): InvitationV1 {

        val usePublicDid = options["usePublicDid"] as? Boolean ?: false
        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val createInvRequest = InvitationCreateRequest.builder()
            .accept(listOf(PROFILE_DIDCOMM_V2))
            .alias(inviter.name)
            .myLabel(label)
            .handshakeProtocols(listOf(RFC0023_DIDEXCHANGE_V1.uri))
            .usePublicDid(usePublicDid)
            .build()
        val createInvFilter = CreateInvitationFilter.builder()
            .autoAccept(autoAccept)
            .build()

        val inviterClient = inviter.walletClient() as AriesClient
        val invitationRecord = inviterClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
        val invitationJson = gson.toJson(invitationRecord.invitation)
        val invitationV1 = InvitationV1.fromJson(invitationJson)
        val invitationDid = invitationV1.recipientDid()
        val invitationKey = invitationV1.invitationKey()

        // Register the Invitation did:key with the KeyStore
        didService.importDid(invitationDid)
        inviter.addDid(invitationDid)

        // Fetch the AcaPy ConnectionRecord
        val filter = ConnectionFilter.builder().invitationKey(invitationKey).build()
        val conRecord = inviterClient.connections(filter).get().firstOrNull()
        checkNotNull(conRecord) { "No connection record" }

        val myEndpointUrl = inviter.endpointUrl

        // Create and attach the Connection
        val pcon = Connection(
            id = conRecord.connectionId,
            agent = inviter.agentType,
            invitationKey = invitationKey,
            myDid = invitationDid,
            myRole = ConnectionRole.INVITER,
            myLabel = label,
            myEndpointUrl = myEndpointUrl,
            theirDid = null,
            theirRole = ConnectionRole.INVITEE,
            theirLabel = null,
            theirEndpointUrl = null,
            state = ConnectionState.INVITATION
        )

        mex.setConnection(pcon)
        inviter.addConnection(pcon)

        return invitationV1
    }

    private fun createOutOfBandInvitationNessus(inviter: NessusWallet, label: String): InvitationV1 {

        val invitationDid = inviter.createDid(DidMethod.KEY)

        val invitationV1 = InvitationV1(
            id = "${UUID.randomUUID()}",
            type = RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION_V1,
            label = label,
            accept = listOf(PROFILE_DIDCOMM_V2),
            handshakeProtocols = listOf(RFC0023_DIDEXCHANGE_V1.uri),
            services = listOf(
                Invitation.Service(
                    id = "#inline",
                    type = "did-communication",
                    recipientKeys = listOf(invitationDid.qualified),
                    serviceEndpoint = inviter.endpointUrl
                )
            )
        )

        val invitationKey = invitationV1.invitationKey()

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
            agent = inviter.agentType,
            invitationKey = invitationKey,
            myDid = invitationDid,
            myRole = ConnectionRole.INVITER,
            myLabel = label,
            myEndpointUrl = inviter.endpointUrl,
            theirDid = null,
            theirRole = ConnectionRole.INVITEE,
            theirLabel = null,
            theirEndpointUrl = null,
            state = ConnectionState.INVITATION
        )

        mex.setConnection(pcon)
        inviter.addConnection(pcon)

        return invitationV1
    }

    private fun receiveOutOfBandInvitationAcapy(invitee: AcapyWallet, invitation: InvitationV1, options: Map<String, Any>): RFC0434OutOfBandProtocolV1 {

        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val invitationMessage = InvitationMessage.builder<InvitationMessageService>()
            .atId(invitation.id)
            .atType(invitation.type)
            .goalCode(invitation.label)
            .accept(invitation.accept)
            .handshakeProtocols(invitation.handshakeProtocols)
            .services(invitation.services.map {
                gson.fromJson(gson.toJson(it), InvitationMessageService::class.java)
            }).build()
        val receiveInvFilter = ReceiveInvitationFilter.builder()
            .useExistingConnection(false)
            .autoAccept(autoAccept)
            .build()

        // Start a new MessageExchange
        val inviteeMex = MessageExchange()
        inviteeMex.putAttachment(WALLET_ATTACHMENT_KEY, invitee)

        // Do this before the admin command call to avoid a race with the incoming didex request message
        inviteeMex.addMessage(EndpointMessage(
            invitation, mapOf(
                MESSAGE_HEADER_PROTOCOL_URI to protocolUri,
                MESSAGE_HEADER_ID to invitation.id,
                MESSAGE_HEADER_THID to invitation.id,
                MESSAGE_HEADER_TYPE to invitation.type,
            )
        ))

        /*
         * AcaPy sends the DidEx Request automatically on receipt
         * of the Invitation. This is regardless of the auto-accept flag.
         *
         * We place the future before the receive-invitation admin command
         */
        mex.placeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1)

        val inviteeClient = invitee.walletClient() as AriesClient
        inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()

        // We stay with the inviter protocol/mex
        return this
    }

    private fun receiveOutOfBandInvitationNessus(invitee: NessusWallet, invitation: InvitationV1): RFC0434OutOfBandProtocolV1 {

        // Start a new MessageExchange
        val inviteeMex = MessageExchange()
        inviteeMex.putAttachment(WALLET_ATTACHMENT_KEY, invitee)

        inviteeMex.addMessage(EndpointMessage(invitation, mapOf(
            MESSAGE_HEADER_PROTOCOL_URI to protocolUri,
            MESSAGE_HEADER_ID to invitation.id,
            MESSAGE_HEADER_THID to invitation.id,
            MESSAGE_HEADER_TYPE to invitation.type,
        )))

        // Needs to be did:sov, otherwise
        // ValidationError: {'did': ['Value did:key:z6... is not an indy decentralized identifier (DID)']}
        val myDid = invitee.createDid(DidMethod.SOV)
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

        return inviteeMex.withProtocol(RFC0434_OUT_OF_BAND_V1)
    }
}
