/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
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
package org.nessus.didcomm.service

import id.walt.common.prettyPrint
import mu.KotlinLogging
import okhttp3.MediaType.Companion.toMediaType
import org.didcommx.didcomm.common.Typ.Encrypted
import org.didcommx.didcomm.common.Typ.Plaintext
import org.didcommx.didcomm.common.Typ.Signed
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.UnpackParams
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_RECIPIENT_DID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_SENDER_DID
import org.nessus.didcomm.protocol.TrustPingProtocolV2.Companion.TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2
import org.nessus.didcomm.protocol.TrustPingProtocolV2.Companion.TRUST_PING_MESSAGE_TYPE_PING_V2
import org.nessus.didcomm.util.NessusRuntimeException
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.matches

typealias MessageDispatcher = (msg: EndpointMessage) -> MessageExchange?

/**
 * The MessageDispatchService is the entry point for all messages
 */
object MessageDispatchService: ObjectService<MessageDispatchService>(), MessageDispatcher {
    private val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    private val didService get() = DidService.getService()
    private val httpService get() = HttpService.getService()
    private val modelService get() = ModelService.getService()
    private val protocolService get() = ProtocolService.getService()

    /**
     * Entry point for all external messages sent to the agent
     */
    override fun invoke(epm: EndpointMessage): MessageExchange? {
        val contentType = epm.headers["Content-Type"] as? String
        checkNotNull(contentType) { "No 'Content-Type' header"}
        return dispatchDidCommV2Envelope(epm, contentType)
    }

    fun dispatchToEndpoint(url: String, epm: EndpointMessage): Boolean {
        val httpClient = httpService.httpClient()
        val res = httpClient.post(url, epm.body, headers = epm.headers.mapValues { (_, v) -> v.toString() })
        if (!res.isSuccessful) {
            val error = res.body?.string()
            log.error { error?.prettyPrint() }
            when {
                !error.isNullOrEmpty() -> throw NessusRuntimeException(error)
                else -> throw IllegalStateException("Call failed with ${res.code} ${res.message}")
            }
        }
        return true
    }

    // Private ---------------------------------------------------------------------------------------------------------

    /**
     * Routes the message to a given target wallet through it's associated protocol.
     */
    private fun dispatchToWallet(target: Wallet, mex: MessageExchange): Boolean {

        val protocolUri = mex.last.protocolUri
        val messageType = mex.last.type
        checkNotNull(protocolUri) { "No protocol uri" }
        checkNotNull(messageType) { "No message type" }

        val protocolService = ProtocolService.getService()
        val key = protocolService.findProtocolKey(protocolUri)
        val protocol = protocolService.getProtocol(key, mex)
        return protocol.invokeMethod(target, messageType)
    }

    private fun dispatchDidCommV2Envelope(epm: EndpointMessage, contentType: String): MessageExchange? {
        check(setOf(Plaintext, Signed, Encrypted).any { it.typ.toMediaType().matches(contentType) }) { "Unknown content type: $contentType" }
        val unpackResult = DidCommService.getService().unpack(
            UnpackParams.Builder(epm.bodyAsJson).build()
        )
        return dispatchUnpackedMessage(unpackResult.message)
    }

    private fun dispatchUnpackedMessage(msg: Message): MessageExchange {

        log.info { "Unpacked Message\n${msg.encodeJson(true)}" }
        checkNotNull(msg.to) { "No target did" }

        /**
         * Find protocol key from message type
         */
        val protocolKey = protocolService.getProtocolKey(msg.type)
        checkNotNull(protocolKey) { "Unknown message type: ${msg.type}" }

        /**
         * Find the recipient Wallet and MessageExchange
         */

        val recipientDids = msg.to!!.mapNotNull { didService.resolveDid(it) }
        check(recipientDids.size < 2) { "Multiple recipients not supported" }
        check(recipientDids.isNotEmpty()) { "No recipient Did" }
        val recipientDid = recipientDids.first()

        val recipientWallet = modelService.findWalletByDid(recipientDid.uri)
        checkNotNull(recipientWallet) { "No recipient wallet" }

        // We may not have the sender wallet
        val senderDid = msg.from?.let { Did.fromUri(it) }
        checkNotNull(senderDid) { "No sender Did" }

        // Find the Connection between sender => recipient

        var pcon = recipientWallet.findConnection { c -> c.myDid == recipientDid && c.theirDid == senderDid }
        if (pcon == null && msg.type == TRUST_PING_MESSAGE_TYPE_PING_V2) {
            pcon = recipientWallet.findConnection { c -> c.myDid == recipientDid && c.state == ConnectionState.INVITATION }
        }
        if (pcon == null && msg.type == TRUST_PING_MESSAGE_TYPE_PING_RESPONSE_V2) {
            pcon = recipientWallet.findConnection { c -> c.myDid == recipientDid  && c.state == ConnectionState.COMPLETED }
        }
        checkNotNull(pcon) { "No connection between: ${recipientDid.uri} => ${senderDid.uri}" }

        // Find the message exchange associated with the Connection

        val mex = MessageExchange.findByConnectionId(pcon.id)
        checkNotNull(mex) { "No message exchange for: ${pcon.shortString()}" }

        /**
         * Now, we dispatch to the MessageExchange associated with the recipientVerkey
         */

        mex.addMessage(EndpointMessage.Builder(msg)
            .header(MESSAGE_HEADER_PROTOCOL_URI, protocolKey.name)
            .header(MESSAGE_HEADER_SENDER_DID, senderDid.uri)
            .header(MESSAGE_HEADER_RECIPIENT_DID, recipientDid.uri)
            .inbound()
            .build())

        dispatchToWallet(recipientWallet, mex)
        return mex
    }
}
