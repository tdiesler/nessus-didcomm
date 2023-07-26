package org.nessus.didcomm.service

import id.walt.common.prettyPrint
import okhttp3.MediaType.Companion.toMediaType
import org.didcommx.didcomm.common.Typ
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.model.UnpackResult
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_FROM
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_PROTOCOL_URI
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_RECIPIENT_DID
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_SENDER_DID
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_TO
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_TYPE
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.ForwardMessageV2
import org.nessus.didcomm.protocol.RoutingProtocolV2.Companion.ROUTING_MESSAGE_TYPE_FORWARD_V2
import org.nessus.didcomm.protocol.TrustPingProtocolV2
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.jsonData
import org.nessus.didcomm.util.matches
import java.util.concurrent.Executors

typealias MessageReceiver = (msg: EndpointMessage) -> Message

/**
 * The MessageReceiverService is the entry point for all incoming messages
 */
object MessageReceiverService: ObjectService<MessageReceiverService>(), MessageReceiver {

    override fun getService() = apply { }

    private val didService get() = DidService.getService()
    private val dispatchService get() = MessageDispatchService.getService()
    private val modelService get() = ModelService.getService()
    private val protocolService get() = ProtocolService.getService()

    private val executor = Executors.newCachedThreadPool()

    /**
     * Entry point for all external messages sent to the agent
     * @return The unpacked message
     */
    override fun invoke(epm: EndpointMessage): Message {
        val contentType = epm.headers["Content-Type"] as? String
        checkNotNull(contentType) { "No 'Content-Type' header"}
        return processDidCommV2Envelope(epm, contentType)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun processDidCommV2Envelope(epm: EndpointMessage, contentType: String): Message {
        check(setOf(Typ.Plaintext, Typ.Signed, Typ.Encrypted).any { it.typ.toMediaType().matches(contentType) }) { "Unknown content type: $contentType" }
        val unpackResult = DidCommService.unpack(
            UnpackParams.Builder(epm.bodyAsJson).build()
        )
        processUnpackedMessage(unpackResult)
        return unpackResult.message
    }

    private fun processUnpackedMessage(unpackResult: UnpackResult) {

        val msg = unpackResult.message
        log.info { "Unpacked Message\n${msg.encodeJson(true)}" }

        /**
         * Find protocol key from message type
         */
        val protocolKey = ProtocolService.getProtocolKey(msg.type)
        checkNotNull(protocolKey) { "Unknown message type: ${msg.type}" }

        fun kidToDid(kid: String): Did {
            val didDoc = didService.loadOrResolveDidDoc(kid)
            checkNotNull(didDoc) { "Cannot load/resolve DidDoc for: $kid" }
            val vm = didDoc.verificationMethods.first { it.id == kid }
            return didService.loadDid(vm.controller)
        }

        val msgTo = unpackResult.metadata.encryptedTo?.map { kidToDid(it).uri }
        val msgFrom = unpackResult.metadata.signFrom?.let { kidToDid(it).uri }

        val epm = EndpointMessage.Builder(msg, mapOf(
            MESSAGE_HEADER_PROTOCOL_URI to protocolKey.name,
            MESSAGE_HEADER_FROM to (msgFrom ?: msg.from),
            MESSAGE_HEADER_TO to (msgTo ?: msg.to),
        )).inbound().build()

        when(msg.type) {
            ROUTING_MESSAGE_TYPE_FORWARD_V2 -> processForwardMessage(epm)
            else -> processTargetWalletMessage(protocolKey, epm)
        }
    }

    private fun processForwardMessage(epm: EndpointMessage): Boolean {
        epm.checkMessageType(ROUTING_MESSAGE_TYPE_FORWARD_V2)

        val msg = epm.body as Message
        val forwardV2 = ForwardMessageV2.fromMessage(msg)
        val attachments = forwardV2.attachments

        val nextDid = didService.loadOrResolveDid(forwardV2.next)
        checkNotNull(nextDid) { "Cannot resolve recipient Did from: ${forwardV2.next}" }
        check(attachments.size == 1) { "Unsupported number of attachments: ${attachments.size}" }

        val candidateWallets = modelService.wallets.filter { w -> w.connections.any { c -> c.theirDid == nextDid }}
        check(candidateWallets.size == 1) { "Unexpected number of candidate wallets: ${candidateWallets.map { it.shortString() }}" }

        val pcon = candidateWallets.first().findConnection { c -> c.theirDid == nextDid }
        checkNotNull(pcon) { "Cannot find connection for: ${nextDid.uri}" }

        val attachmentData = attachments.first().data
        val wrappedMsg = attachmentData.jsonData()?.encodeJson()
        checkNotNull(wrappedMsg) { "Unsupported attachment data format : ${attachmentData.prettyPrint()}" }

        val wrapperEpm = EndpointMessage.Builder(wrappedMsg, mapOf(MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound()
            .build()

        val endpointUrl = pcon.theirEndpointUrl
        checkNotNull(endpointUrl)
        dispatchService.dispatchToRemoteEndpoint(endpointUrl, wrapperEpm)

        return true
    }

    private fun processTargetWalletMessage(protocolKey: ProtocolKey<*>, epm: EndpointMessage): Boolean {

        /**
         * Find the recipient Wallet and MessageExchange
         */

        val msg = epm.body as Message
        val recipientDids = epm.to?.mapNotNull { uri -> didService.resolveDid(uri) }
        check(!recipientDids.isNullOrEmpty()) { "Cannot resolve recipient Did from: ${epm.to}" }
        check(recipientDids.size < 2) { "Multiple recipients not supported" }
        val recipientDid = recipientDids.first()

        val recipientWallet = ModelService.findWalletByDid(recipientDid.uri)
        checkNotNull(recipientWallet) { "No recipient wallet for: ${recipientDid.uri}" }

        // We may not have the sender wallet
        val senderDid = epm.from?.let { Did.fromUri(it) }
        checkNotNull(senderDid) { "Cannot derive sender Did from: ${epm.from}" }

        // Find the Connection between sender => recipient

        var pcon = recipientWallet.findConnection { c -> c.myDid == recipientDid && c.theirDid == senderDid }
        if (pcon == null && msg.type == TrustPingProtocolV2.TRUST_PING_MESSAGE_TYPE_PING_V2) {
            pcon = recipientWallet.findConnection { c -> c.myDid == recipientDid && c.state == ConnectionState.INVITATION }
        }
        if (pcon == null && msg.type == TrustPingProtocolV2.TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2) {
            pcon = recipientWallet.findConnection { c -> c.myDid == recipientDid  && c.state == ConnectionState.COMPLETED }
        }
        checkNotNull(pcon) { "No connection between: ${recipientDid.uri} => ${senderDid.uri}" }

        // Find the message exchange associated with the Connection

        val mex = MessageExchange.findByConnectionId(pcon.id)
        checkNotNull(mex) { "No message exchange for: ${pcon.shortString()}" }

        /**
         * Now, we dispatch (async) to the MessageExchange associated with the Connection
         */

        executor.execute {

            mex.addMessage(EndpointMessage.Builder(msg, mapOf(
                    MESSAGE_HEADER_PROTOCOL_URI to protocolKey.name,
                    MESSAGE_HEADER_SENDER_DID to senderDid.uri,
                    MESSAGE_HEADER_RECIPIENT_DID to recipientDid.uri,
                )).inbound().build())

            dispatchToWallet(recipientWallet, mex)
        }

        return true
    }

    /**
     * Routes the message to a given target wallet through it's associated protocol.
     */
    private fun dispatchToWallet(target: Wallet, mex: MessageExchange): Boolean {

        val protocolUri = mex.last.protocolUri
        val messageType = mex.last.type
        checkNotNull(protocolUri) { "No protocol uri" }
        checkNotNull(messageType) { "No message type" }

        val key = protocolService.findProtocolKey(protocolUri)
        val protocol = ProtocolService.getProtocol(key, mex)
        return protocol.invokeMethod(target, messageType)
    }
}