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
import org.hyperledger.aries.api.connection.ConnectionFilter
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_THID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_TYPE
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.AcapyWallet
import org.nessus.didcomm.wallet.NessusWallet
import java.util.*

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
class RFC0434OutOfBandProtocol(mex: MessageExchange): Protocol<RFC0434OutOfBandProtocol>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0434_OUT_OF_BAND.uri

    companion object {
        val RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION = "${RFC0434_OUT_OF_BAND.uri}/invitation"
    }

    fun createOutOfBandInvitation(inviter: Wallet, label: String): RFC0434OutOfBandProtocol {
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
    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocol {

        val label = options["label"] as? String ?: "Invitation from ${inviter.name}"

        val invitation = if (inviter.agentType == AgentType.ACAPY) {
            createOutOfBandInvitationAcapy(inviter as AcapyWallet, label, options)
        } else {
            createOutOfBandInvitationNessus(inviter as NessusWallet, label)
        }.validate()
        log.info { "Inviter (${inviter.name}) created Invitation: ${prettyGson.toJson(invitation)}" }

        // Associate this invitation & recipient Did with the inviter wallet
        val walletModel = inviter
        walletModel.addInvitation(invitation)

        mex.putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
        mex.putAttachment(WALLET_ATTACHMENT_KEY, inviter)

        mex.addMessage(EndpointMessage(
            invitation, mapOf(
                MESSAGE_HEADER_PROTOCOL_URI to protocolUri,
                MESSAGE_HEADER_ID to invitation.id,
                MESSAGE_HEADER_THID to invitation.id,
                MESSAGE_HEADER_TYPE to invitation.type,
            )
        ))
        return this
    }

    fun receiveOutOfBandInvitation(invitee: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocol {

        val invitation = mex.getAttachment(INVITATION_ATTACHMENT_KEY) as Invitation
        log.info { "Invitee (${invitee.name}) received Invitation: ${invitation.prettyPrint()}"}
        check(invitation.state == InvitationState.INITIAL) { "Unexpected invitation state: $invitation" }

        val rfc0434 = when(invitee.agentType) {
            AgentType.ACAPY -> receiveOutOfBandInvitationAcapy(invitee as AcapyWallet, invitation, options)
            AgentType.NESSUS -> receiveOutOfBandInvitationNessus(invitee as NessusWallet, invitation)
        }

        // Associate this invitation with the invitee wallet
        invitation.state = InvitationState.RECEIVED
        invitation.state = InvitationState.DONE
        invitee.addInvitation(invitation)

        // Returns an instance of this protocol associated with another MessageExchange
        return rfc0434
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createOutOfBandInvitationAcapy(inviter: AcapyWallet, label: String, options: Map<String, Any>): Invitation {

        val usePublicDid = options["usePublicDid"] as? Boolean ?: false
        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val createInvRequest = InvitationCreateRequest.builder()
            .accept(listOf("didcomm/v2"))
            .alias(inviter.name)
            .myLabel(label)
            .handshakeProtocols(listOf(RFC0023_DIDEXCHANGE.uri))
            .usePublicDid(usePublicDid)
            .build()
        val createInvFilter = CreateInvitationFilter.builder()
            .autoAccept(autoAccept)
            .build()

        val inviterClient = inviter.walletClient() as AriesClient
        val invitationRecord = inviterClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
        val invitationJson = gson.toJson(invitationRecord.invitation)
        val invitation = Invitation.fromJson(invitationJson)
        val invitationDid = invitation.recipientDidKey()
        val invitationKey = invitation.invitationKey()

        // Register the Invitation did:key with the KeyStore
        val walletModel = inviter
        didService.registerWithKeyStore(invitationDid)
        walletModel.addDid(invitationDid)

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

        return invitation
    }

    private fun createOutOfBandInvitationNessus(inviter: NessusWallet, label: String): Invitation {

        val invitationDid = inviter.createDid(DidMethod.KEY)

        val invitation = Invitation(
            id = "${UUID.randomUUID()}",
            type = RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION,
            label = label,
            accept = listOf("didcomm/v2"),
            handshakeProtocols = listOf(RFC0023_DIDEXCHANGE.uri),
            services = listOf(
                Invitation.Service(
                    id = "#inline",
                    type = "did-communication",
                    recipientKeys = listOf(invitationDid.qualified),
                    serviceEndpoint = inviter.endpointUrl
                )
            )
        )

        val myEndpointUrl = inviter.endpointUrl
        val invitationKey = invitation.invitationKey()

        // Create and attach the Connection
        val pcon = Connection(
            id = "${UUID.randomUUID()}",
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

        return invitation
    }

    private fun receiveOutOfBandInvitationAcapy(invitee: AcapyWallet, invitation: Invitation, options: Map<String, Any>): RFC0434OutOfBandProtocol {

        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val invitationMessage = InvitationMessage.builder<InvitationMessage.InvitationMessageService>()
            .atId(invitation.id)
            .atType(invitation.type)
            .goalCode(invitation.label)
            .accept(invitation.accept)
            .handshakeProtocols(invitation.handshakeProtocols)
            .services(invitation.services.map {
                gson.fromJson(gson.toJson(it), InvitationMessage.InvitationMessageService::class.java)
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
        mex.placeEndpointMessageFuture(RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST)

        val inviteeClient = invitee.walletClient() as AriesClient
        inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()

        // We stay with the inviter protocol/mex
        return this
    }

    private fun receiveOutOfBandInvitationNessus(invitee: NessusWallet, invitation: Invitation): RFC0434OutOfBandProtocol {

        // Start a new MessageExchange
        val inviteeMex = MessageExchange()
        inviteeMex.putAttachment(WALLET_ATTACHMENT_KEY, invitee)

        inviteeMex.addMessage(EndpointMessage(invitation, mapOf(
            MESSAGE_HEADER_PROTOCOL_URI to protocolUri,
            MESSAGE_HEADER_ID to invitation.id,
            MESSAGE_HEADER_THID to invitation.id,
            MESSAGE_HEADER_TYPE to invitation.type,
        )))

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
            theirLabel = invitation.label,
            theirEndpointUrl = null,
            state = ConnectionState.INVITATION
        )

        inviteeMex.setConnection(pcon)
        invitee.addConnection(pcon)

        return inviteeMex.withProtocol(RFC0434_OUT_OF_BAND)
    }
}
