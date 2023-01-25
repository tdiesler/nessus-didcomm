package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationState
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_TYPE
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITEE_WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.MessageExchange.Companion.INVITER_WALLET_ATTACHMENT_KEY
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE
import org.nessus.didcomm.service.RFC0048_TRUST_PING
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.toWalletModel
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

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

    override val protocolUri = RFC0434_OUT_OF_BAND.uri
    override val log = KotlinLogging.logger {}

    companion object {
        val RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION = "${RFC0434_OUT_OF_BAND.uri}/invitation"
    }

    fun createOutOfBandInvitation(inviter: Wallet, goalCode: String): RFC0434OutOfBandProtocol {
        return createOutOfBandInvitation(inviter, mapOf("goalCode" to goalCode))
    }

    /**
     * Creates an out-of-band invitation message
     *
     * Supported options
     * -----------------
     * goalCode: String
     * usePublicDid: Boolean (false)
     * autoAccept: Boolean (true)
     */
    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocol {

        val goalCode = options["goal_code"] as? String ?: "Invitation from ${inviter.name}"

        val invitation = if (inviter.agentType == AgentType.ACAPY) {
            createOutOfBandInvitationAcapy(inviter, goalCode, options)
        } else {
            createOutOfBandInvitationNessus(inviter, goalCode, options)
        }.validate()
        log.info { "Created Invitation: ${prettyGson.toJson(invitation)}" }

        // Attach the Inviter wallet
        mex.putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
        mex.putAttachment(INVITER_WALLET_ATTACHMENT_KEY, inviter)


        // Associate this invitation & recipient Did with the inviter wallet
        val walletModel = inviter.toWalletModel()
        walletModel.addInvitation(invitation)

        val invitationDid = invitation.recipientDidKey()
        if (!walletModel.hasDid(invitationDid.verkey))
            walletModel.addDid(invitationDid)

        mex.addMessage(EndpointMessage(
            invitation, mapOf(
                MESSAGE_PROTOCOL_URI to protocolUri,
                MESSAGE_ID to invitation.id,
                MESSAGE_THID to invitation.id,
                MESSAGE_TYPE to invitation.type,
            )
        ))
        return this
    }

    fun receiveOutOfBandInvitation(invitee: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocol {

        val invitation = mex.last.body as Invitation
        check(invitation.state == InvitationState.INITIAL) { "Unexpected invitation state: $invitation" }

        // Attach the Invitee wallet
        mex.putAttachment(INVITATION_ATTACHMENT_KEY, invitation)
        mex.putAttachment(INVITEE_WALLET_ATTACHMENT_KEY, invitee)

        when(invitee.agentType) {
            AgentType.ACAPY -> receiveOutOfBandInvitationAcapy(invitee, invitation, options)
            AgentType.NESSUS -> receiveOutOfBandInvitationNessus(invitee, invitation, options)
        }

        // Associate this invitation with the invitee wallet
        invitation.state = InvitationState.RECEIVED
        invitation.state = InvitationState.DONE
        invitee.toWalletModel().addInvitation(invitation)

        return this
    }

    fun acceptConnectionFrom(invitee: Wallet): MessageExchange {

        mex.withProtocol(RFC0434_OUT_OF_BAND)
            .receiveOutOfBandInvitation(invitee)
            .withProtocol(RFC0023_DIDEXCHANGE)
            .sendDidExchangeRequest()
            .awaitDidExchangeResponse(5, TimeUnit.SECONDS)
            .sendDidExchangeComplete()
            .withProtocol(RFC0048_TRUST_PING)
            .sendTrustPing()
            .awaitTrustPingResponse(5, TimeUnit.SECONDS)

        return mex
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createOutOfBandInvitationAcapy(inviter: Wallet, goalCode: String, options: Map<String, Any>): Invitation {

        val usePublicDid = options["usePublicDid"] as? Boolean ?: false
        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val createInvRequest = InvitationCreateRequest.builder()
            .accept(listOf("didcomm/v2"))
            .alias(inviter.name)
            .myLabel(goalCode)
            .handshakeProtocols(listOf(RFC0023_DIDEXCHANGE.uri))
            .protocolVersion("1.1")
            .usePublicDid(usePublicDid)
            .build()
        val createInvFilter = CreateInvitationFilter.builder()
            .autoAccept(autoAccept)
            .build()

        val inviterClient = inviter.walletClient() as AriesClient
        val inviRecord: InvitationRecord = inviterClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
        val invitationJson = gson.toJson(inviRecord.invitation)
        val invitation = Invitation.fromJson(invitationJson)

        val inviterDid = invitation.recipientDidKey()
        didService.registerWithKeyStore(inviterDid)

        return invitation
    }

    private fun createOutOfBandInvitationNessus(inviter: Wallet, goalCode: String, options: Map<String, Any>): Invitation {

        val inviterDid = inviter.createDid(DidMethod.KEY)

        return Invitation(
            id = "${UUID.randomUUID()}",
            type = RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION,
            accept = listOf("didcomm/v2"),
            handshakeProtocols = listOf(RFC0023_DIDEXCHANGE.uri),
            goalCode = goalCode,
            services = listOf(
                Invitation.Service(
                    id = "#inline",
                    type = "did-communication",
                    recipientKeys = listOf(inviterDid.qualified),
                    serviceEndpoint = inviter.endpointUrl
                )
            )
        )
    }

    private fun receiveOutOfBandInvitationAcapy(invitee: Wallet, invitation: Invitation, options: Map<String, Any>) {

        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val invitationMessage = InvitationMessage.builder<InvitationMessage.InvitationMessageService>()
            .atId(invitation.id)
            .atType(invitation.type)
            .goalCode(invitation.goalCode)
            .goal("Issue a Faber College Graduate credential")
            .accept(invitation.accept)
            .handshakeProtocols(invitation.handshakeProtocols)
            .services(invitation.services.map {
                gson.fromJson(gson.toJson(it), InvitationMessage.InvitationMessageService::class.java)
            }).build()
        val receiveInvFilter = ReceiveInvitationFilter.builder()
            .useExistingConnection(false)
            .autoAccept(autoAccept)
            .build()

        // Do this before the admin command call to avoid a race with the incoming didex request message
        mex.addMessage(EndpointMessage(
            invitation, mapOf(
                MESSAGE_PROTOCOL_URI to protocolUri,
                MESSAGE_ID to invitation.id,
                MESSAGE_THID to invitation.id,
                MESSAGE_TYPE to invitation.type,
            )
        ))

        val futureId = "${RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST}?invId=${invitation.id}"
        val futureKey = AttachmentKey(futureId, CompletableFuture::class.java)
        mex.putAttachment(futureKey, CompletableFuture<EndpointMessage>())
        log.info("Placed future: ${futureKey.name}")

        val inviteeClient = invitee.walletClient() as AriesClient
        inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()
    }

    private fun receiveOutOfBandInvitationNessus(invitee: Wallet, invitation: Invitation, options: Map<String, Any>) {
        mex.addMessage(EndpointMessage(
            invitation, mapOf(
                MESSAGE_PROTOCOL_URI to protocolUri,
                MESSAGE_ID to invitation.id,
                MESSAGE_THID to invitation.id,
                MESSAGE_TYPE to invitation.type,
            )
        ))
    }
}
