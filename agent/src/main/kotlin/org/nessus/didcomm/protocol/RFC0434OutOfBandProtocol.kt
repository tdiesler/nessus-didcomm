package org.nessus.didcomm.protocol

import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.nessus.didcomm.agent.AgentConfiguration
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_CONTENT_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ALIAS
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol.Companion.PROTOCOL_METHOD_CREATE_INVITATION
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.service.InvitationService
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.Wallet
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
class RFC0434OutOfBandProtocol: Protocol() {
    override val protocolUri = RFC0434_OUT_OF_BAND.uri

    companion object {
        const val PROTOCOL_METHOD_CREATE_INVITATION = "/out-of-band/create-invitation"
        const val PROTOCOL_METHOD_RECEIVE_INVITATION = "/out-of-band/receive-invitation"
    }

    override fun invokeMethod(to: Wallet, method: String, mex: MessageExchange): Boolean {
        when(method) {
            PROTOCOL_METHOD_RECEIVE_INVITATION -> receiveOutOfBandInvitation(to, mex.last.body as Invitation)
            else -> throw IllegalStateException("Unsupported protocol method: $method")
        }
        return true
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
    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): Invitation {

        val invitationService = InvitationService.getService()

        val goalCode = options["goal_code"] as? String ?: "Invitation from ${inviter.name}"

        // Create the legacy Acapy invitation
        val invitation = if (inviter.agentType == AgentType.ACAPY) {
            createOutOfBandInvitationAcapy(inviter, goalCode, options)

        } else {

            val inviterDid = inviter.createDid(DidMethod.KEY)
            checkNotNull(inviter.endpointUrl) { "No endpoint for: $inviter" }

            Invitation(
                atId = "${UUID.randomUUID()}",
                atType = "https://didcomm.org/out-of-band/1.1/invitation",
                handshakeProtocols = listOf("https://didcomm.org/didexchange/1.0"),
                accept = listOf("didcomm/v2"),
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

        val service = (invitation.services).firstOrNull { it.type == "did-communication" }
        checkNotNull(service) { "Cannot find service of type 'did-communication' in: ${invitation.services}"}
        check(service.recipientKeys.size == 1) { "Unexpected number of recipientKeys: ${service.recipientKeys}" }
        val inviterDid = Did.fromSpec(service.recipientKeys[0])

        log.info { "Created Invitation: ${prettyGson.toJson(invitation)}" }

        // Associate this invitation with the inviter wallet
        invitationService.addInvitation(inviter.id, invitation)

        return invitation
    }

    fun receiveOutOfBandInvitation(invitee: Wallet, invitation: Invitation, options: Map<String, Any> = mapOf()) {

        if (invitee.agentType == AgentType.ACAPY) {
            receiveOutOfBandInvitationAcapy(invitee, invitation, options)
        }
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
            .handshakeProtocols(listOf("https://didcomm.org/didexchange/1.0"))
            .protocolVersion("1.1")
            .usePublicDid(usePublicDid)
            .build()
        val createInvFilter = CreateInvitationFilter.builder()
            .autoAccept(autoAccept)
            .build()

        val inviterClient = inviter.walletClient() as AriesClient
        val invitationRecord: InvitationRecord = inviterClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
        val ariesInvitation = invitationRecord.invitation

        val service = (ariesInvitation.services as List<Map<String, Any>>).firstOrNull { it["type"] == "did-communication" }
        checkNotNull(service) { "Cannot find service of type 'did-communication' in: ${ariesInvitation.services}"}
        val recipientKeys = service["recipientKeys"] as List<String>
        check(recipientKeys.size == 1) { "Unexpected number of recipientKeys: $recipientKeys" }

        val inviterDid = Did.fromSpec(recipientKeys[0])
        val endpointUrl = inviter.endpointUrl ?: AgentConfiguration.defaultConfiguration.userUrl

        return Invitation(
            atId = ariesInvitation.atId,
            atType = ariesInvitation.atType,
            handshakeProtocols = ariesInvitation.handshakeProtocols,
            accept = ariesInvitation.accept,
            goalCode = ariesInvitation.label,
            services = listOf(
                Invitation.Service(
                    id = service["id"] as String,
                    type = "did-communication",
                    recipientKeys = listOf(inviterDid.qualified),
                    serviceEndpoint = endpointUrl as String
                )
            )
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun receiveOutOfBandInvitationAcapy(invitee: Wallet, invitation: Invitation, options: Map<String, Any>) {

        // [TODO] Add support for goal/goal_code

        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val invitationMessageBuilder = InvitationMessage.builder<InvitationMessage.InvitationMessageService>()
            .atId(invitation.atId)
            .atType(invitation.atType)
            .goalCode(invitation.goalCode)
            .goal("Issue a Faber College Graduate credential")
            .accept(invitation.accept)
            .handshakeProtocols(invitation.handshakeProtocols)
            .services(invitation.services.map {
                gson.fromJson(gson.toJson(it), InvitationMessage.InvitationMessageService::class.java)
            })
        val invitationMessage = invitationMessageBuilder.build()

        val receiveInvFilter = ReceiveInvitationFilter.builder()
            .useExistingConnection(false)
            .autoAccept(autoAccept)
            .build()

        val inviteeClient = invitee.walletClient() as AriesClient
        val inviteeConnection = inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()

        //messageExchange.putAttachment(MESSAGE_EXCHANGE_INVITEE_CONNECTION_ID_KEY, inviteeConnection.connectionId)
    }
}

class RFC0434OutOfBandProtocolWrapper(mex: MessageExchange):
    ProtocolWrapper<RFC0434OutOfBandProtocolWrapper, RFC0434OutOfBandProtocol>(RFC0434OutOfBandProtocol(), mex) {

    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocolWrapper {
        val invitation = protocol.createOutOfBandInvitation(inviter, options)
        mex.addMessage(EndpointMessage(
            invitation, mapOf(
                MESSAGE_THREAD_ID to invitation.atId,
                MESSAGE_PROTOCOL_METHOD to PROTOCOL_METHOD_CREATE_INVITATION,
                MESSAGE_PROTOCOL_URI to protocol.protocolUri,
                MESSAGE_FROM_ID to inviter.id,
                MESSAGE_FROM_ALIAS to inviter.name,
                MESSAGE_CONTENT_URI to invitation.atType,
            )
        ))
        return this
    }

    fun receiveOutOfBandInvitation(invitee: Wallet, options: Map<String, Any> = mapOf()): RFC0434OutOfBandProtocolWrapper {
        val invitation = mex.last.body as Invitation
        protocol.receiveOutOfBandInvitation(invitee, invitation, options)
        return this
    }
}
