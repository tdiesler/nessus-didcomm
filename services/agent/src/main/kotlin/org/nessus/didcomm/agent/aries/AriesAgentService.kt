package org.nessus.didcomm.agent.aries

import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.didcommx.didcomm.utils.idGeneratorDefault
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.api.connection.ConnectionRecord
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.nessus.didcomm.model.MessageType.Companion.OUT_OF_BAND_INVITATION
import org.nessus.didcomm.model.MessageWriter
import org.nessus.didcomm.service.AgentService
import org.nessus.didcomm.wallet.NessusWallet
import org.slf4j.event.Level

class UnsupportedMessageType(msg: String) : Exception(msg)

class AriesAgentService : AgentService {

    private val log = KotlinLogging.logger {}

    companion object {
        private val interceptorLogLevel = Level.DEBUG
        fun adminClient(): AriesClient {
            return AriesClientFactory.adminClient(level=interceptorLogLevel)
        }
        fun walletClient(wallet: NessusWallet): AriesClient {
            return AriesClientFactory.walletClient(wallet=wallet, level=interceptorLogLevel)
        }
    }

    override fun createMessage(wallet: NessusWallet, type: String, body: Map<String, Any>) : Message {
        val message = when(type) {
            OUT_OF_BAND_INVITATION -> createOutOfBandInvitation(wallet, body)
            else -> throw UnsupportedMessageType(type)
        }
        if (log.isDebugEnabled) {
            log.debug("{}", MessageWriter.toJson(message, true))
        }
        return message
    }

//    fun sendMessage(msg: Message) {
//
//    }

    private fun createId(): String {
        return idGeneratorDefault()
    }

    private fun createOutOfBandInvitation(wallet: NessusWallet, body: Map<String, Any>): Message {

        // Make the call to AcaPy
        val reqObj = InvitationCreateRequest.builder()
            .handshakeProtocols(listOf(ConnectionRecord.ConnectionProtocol.DID_EXCHANGE_V1.value))
            .build()
        val filterObj = CreateInvitationFilter.builder().build()
        val invRecord: InvitationRecord = walletClient(wallet).outOfBandCreateInvitation(reqObj, filterObj).get()
        val invRecordMap = MessageWriter.toMutableMap(invRecord)

        // Get the msgId and remove the encoded URL that points to AcaPy
        val msgId = invRecordMap["invi_msg_id"] as String
        invRecordMap.remove("invitation_url")

        // Prepare the attachment
        val datMap = mapOf("json" to invRecordMap)
        val att0 = Attachment.builder(msgId, Attachment.Data.parse(datMap)).build()

        // Create the DIDcomm message
        return MessageBuilder(createId(), body, OUT_OF_BAND_INVITATION)
            .attachments(listOf(att0)).build()
    }

}
