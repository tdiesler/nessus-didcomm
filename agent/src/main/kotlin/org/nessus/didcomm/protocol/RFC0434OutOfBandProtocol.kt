package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.nessus.didcomm.agent.AgentConfiguration
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.InvitationState
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_TYPE
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

    companion object {
        val INVITER_WALLET_ATTACHMENT = AttachmentKey("InviterWallet", Wallet::class.java)
        val INVITEE_WALLET_ATTACHMENT = AttachmentKey("InviteeWallet", Wallet::class.java)

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

        // Attach the Inviter wallet
        mex.putAttachment(INVITER_WALLET_ATTACHMENT, inviter)

        val invitation = if (inviter.agentType == AgentType.ACAPY) {
            createOutOfBandInvitationAcapy(inviter, goalCode, options)
        } else {
            createOutOfBandInvitationNessus(inviter, goalCode, options)
        }

        val service = (invitation.services).firstOrNull { it.type == "did-communication" }
        checkNotNull(service) { "Cannot find service of type 'did-communication' in: ${invitation.services}"}
        check(service.recipientKeys.size == 1) { "Unexpected number of recipientKeys: ${service.recipientKeys}" }

        val recipientDid = Did.fromSpec(service.recipientKeys[0])
        didService.registerWithKeyStore(recipientDid)

        log.info { "Created Invitation: ${prettyGson.toJson(invitation)}" }

        // Associate this invitation & recipient Did with the inviter wallet
        val walletModel = inviter.toWalletModel()
        walletModel.addInvitation(invitation)
        walletModel.addDid(recipientDid)

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
        mex.putAttachment(INVITEE_WALLET_ATTACHMENT, invitee)

        if (invitee.agentType == AgentType.ACAPY) {
            receiveOutOfBandInvitationAcapy(invitee, invitation, options)
        } else {
            receiveOutOfBandInvitationNessus(invitee, invitation, options)
        }

        // Associate this invitation with the invitee wallet
        invitation.state = InvitationState.RECEIVED
        invitation.state = InvitationState.DONE
        invitee.toWalletModel().addInvitation(invitation)

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

    @Suppress("UNCHECKED_CAST")
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
        val acapyInvitation = inviRecord.invitation

        val service = (acapyInvitation.services as List<Map<String, Any>>).firstOrNull { it["type"] == "did-communication" }
        checkNotNull(service) { "Cannot find service of type 'did-communication' in: ${acapyInvitation.services}"}
        val recipientKeys = service["recipientKeys"] as List<String>
        check(recipientKeys.size == 1) { "Unexpected number of recipientKeys: $recipientKeys" }

        val inviterDid = Did.fromSpec(recipientKeys[0])
        val endpointUrl = inviter.endpointUrl ?: AgentConfiguration.defaultConfiguration.userUrl

        return Invitation(
            id = acapyInvitation.atId,
            type = acapyInvitation.atType,
            handshakeProtocols = acapyInvitation.handshakeProtocols,
            accept = acapyInvitation.accept,
            goalCode = acapyInvitation.label,
            services = listOf(
                Invitation.Service(
                    id = service["id"] as String,
                    type = "did-communication",
                    recipientKeys = listOf(inviterDid.qualified),
                    serviceEndpoint = endpointUrl as String
                )
            ),
            state = InvitationState.INITIAL
        )
    }

    private fun createOutOfBandInvitationNessus(inviter: Wallet, goalCode: String, options: Map<String, Any>): Invitation {
        val inviterDid = inviter.createDid(DidMethod.KEY)
        checkNotNull(inviter.endpointUrl) { "No endpoint for: $inviter" }
        return Invitation(
            id = "${UUID.randomUUID()}",
            type = RFC0434_OUT_OF_BAND_MESSAGE_TYPE_INVITATION,
            handshakeProtocols = listOf(RFC0023_DIDEXCHANGE.uri),
            accept = listOf("didcomm/v2"),
            goalCode = goalCode,
            services = listOf(
                Invitation.Service(
                    id = "#inline",
                    type = "did-communication",
                    recipientKeys = listOf(inviterDid.qualified),
                    serviceEndpoint = inviter.endpointUrl
                )
            ),
            state = InvitationState.INITIAL
        )
    }

    private fun receiveOutOfBandInvitationAcapy(invitee: Wallet, invitation: Invitation, options: Map<String, Any>) {

        // [TODO] Add support for goal/goal_code

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

        val inviteeClient = invitee.walletClient() as AriesClient
        var conRecord = inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()
        val conId = conRecord.connectionId

        conRecord = inviteeClient.connectionsGetById(conId).get()
        log.info { gson.toJson(conRecord).prettyPrint() }
    }

    private fun receiveOutOfBandInvitationNessus(invitee: Wallet, invitation: Invitation, options: Map<String, Any>) {
        // Do nothing
    }
}
