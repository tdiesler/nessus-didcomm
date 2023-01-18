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
import id.walt.servicematrix.ServiceProvider
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PARENT_THREAD_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_METHOD
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_THREAD_ID
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.findByThreadId
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.PROTOCOL_METHOD_RECEIVE_REQUEST
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJsonPretty
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.toDeeplySortedMap
import org.nessus.didcomm.wallet.Wallet

/**
 * The MessageDispatchService is the entry point for all messages
 */
class MessageDispatchService: NessusBaseService(), MessageListener {
    override val implementation get() = serviceImplementation<MessageDispatchService>()

    companion object: ServiceProvider {
        private val implementation = MessageDispatchService()
        override fun getService() = implementation
    }

    private val protocolService get() = ProtocolService.getService()

    /**
     * Entry point for all external messages sent to a wallet endpoint
     */
    fun dispatchInbound(msg: EndpointMessage): Boolean {
        val contentType = msg.headers["Content-Type"] as? String
        checkNotNull(contentType) { "No Content-Type" }
        check(msg.body is String) { "No msg body" }
        log.info { "Message Content-Type: $contentType" }
        log.info { "Message Body: ${msg.body.prettyPrint()}" }
        when(contentType) {
            "application/didcomm-envelope-enc" -> didcommEncryptedEnvelopeHandler(msg)
            else -> throw IllegalStateException("Unsupported content type: $contentType")
        }
        return true
    }

    /**
     * Routes the message to a given target wallet through it's associated protocol.
     */
    fun dispatchToWallet(target: Wallet, mex: MessageExchange): Boolean {

        val protocolUri = mex.last.protocolUri as? String
        val protocolMethod = mex.last.protocolMethod as? String
        checkNotNull(protocolUri) { "No protocol uri" }
        checkNotNull(protocolMethod) { "No protocol method" }

        val key = ProtocolService.findProtocolKey(protocolUri)
        val protocol = protocolService.getProtocol(key, mex, target.agentType)
        return protocol.invokeMethod(target, protocolMethod)
    }

    /**
     * MessageListener invocation
     */
    override fun invoke(msg: EndpointMessage): Boolean {
        return dispatchInbound(msg)
    }

    private fun didcommEncryptedEnvelopeHandler(msg: EndpointMessage): Boolean {
        val unpacked = MessageExchange()
            .withProtocol(PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE)
            .unpackRFC0019Envelope(msg.body as String)
        checkNotNull(unpacked) { "Could not unpack encrypted envelope" }

        val (body, recipientKid) = unpacked
        val envelope = body.decodeJson().toDeeplySortedMap()
        log.info { "Unpacked Envelope: ${envelope.encodeJsonPretty(sorted = true)}" }

        /**
         * Ok, we successfully unpacked the encrypted message.
         *
         * We now need tho find the target wallet and the MessageExchange
         * that this message can be attached to
         */

        val thread = envelope["~thread"] as? String
        val thid = envelope.selectJson("~thread.thid") as? String ?: envelope["@id"] as String
        val pthid = envelope.selectJson("~thread.pthid") as? String

        var mex = thid.run { findByThreadId(thid) }
        if (mex == null && pthid != null) {
            mex = findByThreadId(pthid)
        }
        checkNotNull(mex) { "Cannot find message exchange for: $thread" }

        val walletService = WalletService.getService()
        val recipientWallet = walletService.findByVerkey(recipientKid)
        checkNotNull(recipientWallet) { "Cannot fine recipient wallet for: $recipientKid" }

        /**
         * Now, we dispatch mex associated with the thread to the wallet
         * identified by the recipient key(s)
         */

        val atType = envelope["@type"] as String
        val (protocolUri, protocolMethod) = when(atType) {
            "https://didcomm.org/didexchange/1.0/request" -> Pair(PROTOCOL_URI_RFC0023_DID_EXCHANGE.uri, PROTOCOL_METHOD_RECEIVE_REQUEST)
            else -> throw IllegalStateException("Unsupported message type: $atType")
        }
        mex.addMessage(EndpointMessage(body, mapOf(
            MESSAGE_THREAD_ID to thid,
            MESSAGE_PARENT_THREAD_ID to pthid,
            MESSAGE_PROTOCOL_URI to protocolUri,
            MESSAGE_PROTOCOL_METHOD to protocolMethod
        )))
        return dispatchToWallet(recipientWallet, mex)
    }
}
