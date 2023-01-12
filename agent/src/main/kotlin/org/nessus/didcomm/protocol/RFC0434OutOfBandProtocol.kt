package org.nessus.didcomm.protocol

import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_CONTENT_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_DIRECTION
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ALIAS
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_DID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_FROM_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.protocol.MessageExchange.Companion.MESSAGE_EXCHANGE_PEER_CONNECTION_KEY
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1
import org.nessus.didcomm.service.PeerConnection
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent

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
    override val protocolUri = PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1.name

    companion object {
        const val PROTOCOL_METHOD_CREATE_INVITATION = "/out-of-band/create-invitation"
        const val PROTOCOL_METHOD_RECEIVE_INVITATION = "/out-of-band/receive-invitation"
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
    fun createOutOfBandInvitation(inviter: Wallet, options: Map<String, Any> = mapOf()): MessageExchange {

        // Create the legacy Acapy invitation
        if (inviter.walletAgent == WalletAgent.ACAPY)
            return createOutOfBandInvitationAcapy(inviter, options)

        TODO("createOutOfBandInvitation")

//        val wallets = WalletService.getService()
//        val goalCode = options["goal_code"] ?: "Unknown"
//        checkNotNull(inviter) { "No wallet for did: ${inviterDid.qualified}" }
//        checkNotNull(inviter.endpointUrl) { "No endpoint for: $inviter" }
//
//        val message = """
//        {
//          "@id": "${UUID.randomUUID()}",
//          "@type": "https://didcomm.org/out-of-band/1.1/invitation",
//          "handshake_protocols": [ "https://didcomm.org/didexchange/1.0" ],
//          "accept": [ "didcomm/v2" ],
//          "goal_code": "$goalCode",
//          "services": [
//            {
//              "id": "#inline",
//              "type": "did-communication",
//              "recipientKeys": [ "${inviterDid.qualified}" ],
//              "serviceEndpoint": "${inviter.endpointUrl}"
//            }
//          ]
//        }
//        """.trimIndent()
    }

    fun receiveOutOfBandInvitation(invitee: Wallet, mex: MessageExchange) {
        checkProtocol(mex)

        if (invitee.walletAgent == WalletAgent.ACAPY)
            return receiveOutOfBandInvitationAcapy(invitee, mex)

        TODO("receiveOutOfBandInvitation")
    }

    fun acceptDidExchange(invitee: Wallet, mex: MessageExchange) {
        TODO("acceptOutOfBandInvitation")
    }

    fun sendTo(to: Wallet, mex: MessageExchange): Boolean {
        checkProtocol(mex)
        when(val protocolMethod = mex.last.protocolMethod) {

            // We can also send the output of OOB_METHOD_CREATE_INVITATION
            // directly to the OOB_METHOD_RECEIVE_INVITATION target method
            PROTOCOL_METHOD_CREATE_INVITATION -> receiveOutOfBandInvitation(to, mex)
            PROTOCOL_METHOD_RECEIVE_INVITATION -> receiveOutOfBandInvitation(to, mex)
            
            else -> throw IllegalStateException("Unsupported protocol method: $protocolMethod")
        }
        return true
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createOutOfBandInvitationAcapy(inviter: Wallet, options: Map<String, Any> = mapOf()): MessageExchange {

        val goalCode = options["goalCode"] as? String
        val usePublicDid = options["usePublicDid"] as? Boolean ?: false
        val autoAccept = options["autoAccept"] as? Boolean ?: true

        val createInvRequest = InvitationCreateRequest.builder()
            .accept(listOf("didcomm/v2"))
            .alias("${inviter.alias}")
            .myLabel(goalCode)
            .handshakeProtocols(listOf("https://didcomm.org/didexchange/1.0"))
            .protocolVersion("1.1")
            .usePublicDid(usePublicDid)
            .build()
        val createInvFilter = CreateInvitationFilter.builder()
            .autoAccept(autoAccept)
            .build()

        val inviterClient = AriesAgent.walletClient(inviter)
        val invitationRecord: InvitationRecord = inviterClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
        val invitationMessageId = invitationRecord.inviMsgId
        val invitation = invitationRecord.invitation
        val invitationType = invitation.atType

        val service = (invitation.services as List<Map<String, Any>>).firstOrNull { it["type"] == "did-communication" }
        checkNotNull(service) { "Cannot find service of type 'did-communication' in: ${invitation.services}"}
        val recipientKeys = service["recipientKeys"] as List<String>
        check(recipientKeys.size == 1) { "Unexpected number of recipientKeys: $recipientKeys" }
        val myDid = Did.fromSpec(recipientKeys[0])
        log.info { "Inviter Did: $myDid" }

        val epm = EndpointMessage(invitationRecord, mapOf(
            MESSAGE_PROTOCOL_METHOD to PROTOCOL_METHOD_CREATE_INVITATION,
            MESSAGE_PROTOCOL_URI to protocolUri,
            MESSAGE_THREAD_ID to invitationMessageId,
            MESSAGE_FROM_ID to inviter.id,
            MESSAGE_FROM_DID to myDid.qualified,
            MESSAGE_FROM_ALIAS to inviter.alias,
            MESSAGE_CONTENT_URI to invitationType,
        ))
        return MessageExchange(epm, invitationMessageId)
    }

    private fun receiveOutOfBandInvitationAcapy(invitee: Wallet, mex: MessageExchange) {
        val invitationMessageId = mex.threadId
        val invitationRecord = mex.last.body as InvitationRecord
        val invitation = invitationRecord.invitation
        val autoAccept = mex.last.autoAccept

        val invitationMessageBuilder = InvitationMessage.builder<InvitationMessage.InvitationMessageService>()
            .services(invitation.services.map {
                val srvJson: String = gson.toJson(it)
                gson.fromJson(srvJson, InvitationMessage.InvitationMessageService::class.java)
            })

        val invitationMessage = invitationMessageBuilder.atId(invitation.atId)
            .atType(invitation.atType)
            .goalCode("issue-vc")
            .goalCode("Issue a Faber College Graduate credential")
            .accept(invitation.accept)
            .build()

        val receiveInvFilter = ReceiveInvitationFilter.builder()
            .useExistingConnection(false)
            .autoAccept(autoAccept)
            .build()

        val inviteeClient = AriesAgent.walletClient(invitee)
        var inviteeConnection = inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()

        // Expect invitee connection in state 'active'
        if (autoAccept) {
            val connection = AriesAgent.awaitConnectionRecord(invitee) {
                it.invitationMsgId == invitationMessageId && it.stateIsActive()
            }
            checkNotNull(connection) {"${invitee.alias} has no connection record in state 'active'"}
            log.info {"${invitee.alias} connection: ${connection?.state}"}
            log.info("${invitee.alias}: {}", prettyGson.toJson(connection))
            inviteeConnection = connection
        }

        mex.addMessage(EndpointMessage(invitationRecord, mapOf(
            MESSAGE_DIRECTION to MessageDirection.INBOUND,
            MESSAGE_PROTOCOL_URI to protocolUri,
            MESSAGE_THREAD_ID to invitationMessageId,
            MESSAGE_FROM_ID to invitee.id,
            MESSAGE_FROM_ALIAS to invitee.alias,
            MESSAGE_CONTENT_URI to inviteeConnection.connectionProtocol,
        )))

        val peerConnection = PeerConnection.fromAcapyRecord(inviteeConnection)
        mex.putAttachment(MESSAGE_EXCHANGE_PEER_CONNECTION_KEY, peerConnection)
        invitee.addPeerConnection(peerConnection)
    }
}