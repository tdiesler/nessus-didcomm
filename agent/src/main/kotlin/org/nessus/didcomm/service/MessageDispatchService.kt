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

import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_RECIPIENT_VERKEY
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_SENDER_VERKEY
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageExchange.Companion.findMessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocol.Companion.RFC0095_BASIC_MESSAGE_TYPE
import org.nessus.didcomm.util.matches
import org.nessus.didcomm.wallet.Wallet

/**
 * The MessageDispatchService is the entry point for all messages
 */
class MessageDispatchService: NessusBaseService(), MessageListener {
    override val implementation get() = serviceImplementation<MessageDispatchService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = MessageDispatchService()
        override fun getService() = implementation
    }

    private val httpService get() = HttpService.getService()

    /**
     * Entry point for all external messages sent to a wallet endpoint
     */
    fun dispatchInbound(epm: EndpointMessage): MessageExchange? {
        val contentType = epm.headers["Content-Type"] as? String
        checkNotNull(contentType) { "No 'Content-Type' header"}
        return when {
            RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE.matches(contentType) -> dispatchEncryptedEnvelope(epm)
            else -> throw IllegalStateException("Unknown content type: $contentType")
        }
    }

    fun dispatchToDid(did: Did, epm: EndpointMessage): Boolean {
        TODO("dispatchToDid")
    }

    fun dispatchToEndpoint(url: String, epm: EndpointMessage): Boolean {
        val httpClient = httpService.httpClient()
        val res = httpClient.post(url, epm.body, headers = epm.headers.mapValues { (_, v) -> v.toString() })
        check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
        return res.isSuccessful
    }

    /**
     * Routes the message to a given target wallet through it's associated protocol.
     */
    fun dispatchToWallet(target: Wallet, mex: MessageExchange): Boolean {

        val protocolUri = mex.last.protocolUri as? String
        val messageType = mex.last.messageType as? String
        checkNotNull(protocolUri) { "No protocol uri" }
        checkNotNull(messageType) { "No message type" }

        val protocolService = ProtocolService.getService()
        val key = protocolService.findProtocolKey(protocolUri)
        val protocolWrapper = protocolService.getProtocol(key, mex)
        return protocolWrapper.invokeMethod(target, messageType)
    }

    /**
     * MessageListener invocation
     */
    override fun invoke(msg: EndpointMessage): MessageExchange? {
        return dispatchInbound(msg)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun dispatchEncryptedEnvelope(msg: EndpointMessage): MessageExchange {
        val rfc0019 = RFC0019EncryptionEnvelope()
        val unpacked = rfc0019.unpackEncryptedEnvelope(msg.body as String)
        checkNotNull(unpacked) { "Unknown recipients" }

        val message = unpacked.message
        val recipientVerkey = unpacked.recipientVerkey

        /**
         * Ok, we successfully unpacked the encrypted message.
         *
         * We now need tho find the target wallet and the MessageExchange
         * that this message can be attached to
         */

        val aux = EndpointMessage(message, mapOf(
            MESSAGE_SENDER_VERKEY to unpacked.senderVerkey,
            MESSAGE_RECIPIENT_VERKEY to unpacked.recipientVerkey
        ))

        val walletService = WalletService.getService()
        val recipientWallet = walletService.findByVerkey(recipientVerkey)
        checkNotNull(recipientWallet) { "Cannot find recipient wallet for: $recipientVerkey" }

        /**
         * Now, we dispatch mex associated with the thread to the wallet
         * identified by the recipient key(s)
         */

        fun prepareMessageExchange(protocolUri: String, defaultExchange: MessageExchange?): MessageExchange {
            val mex = findMessageExchange(aux) ?: defaultExchange
            checkNotNull(mex) { "No message exchange for: $aux"}
            return mex.addMessage(EndpointMessage.Builder(aux.body, aux.headers)
                .header(MESSAGE_PROTOCOL_URI, protocolUri)
                .build())
        }

        val mex = when (aux.messageType) {

            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST,
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE,
            RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE ->
                prepareMessageExchange(RFC0023_DIDEXCHANGE.uri, null)

            RFC0048_TRUST_PING_MESSAGE_TYPE_PING ->
                prepareMessageExchange(RFC0048_TRUST_PING.uri, MessageExchange())

            RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE ->
                prepareMessageExchange(RFC0048_TRUST_PING.uri, null)

            RFC0095_BASIC_MESSAGE_TYPE ->
                prepareMessageExchange(RFC0095_BASIC_MESSAGE.uri, MessageExchange())

            else -> throw IllegalStateException("Unknown message type: ${aux.messageType}")
        }

        dispatchToWallet(recipientWallet, mex)
        return mex
    }
}
