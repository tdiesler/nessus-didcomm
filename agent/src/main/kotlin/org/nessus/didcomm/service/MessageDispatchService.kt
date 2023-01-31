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
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_PROTOCOL_URI
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.util.matches
import org.nessus.didcomm.wallet.Wallet

typealias MessageDispatcher = (msg: EndpointMessage) -> MessageExchange?

/**
 * The MessageDispatchService is the entry point for all messages
 */
class MessageDispatchService: NessusBaseService(), MessageDispatcher {
    override val implementation get() = serviceImplementation<MessageDispatchService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = MessageDispatchService()
        override fun getService() = implementation
    }

    private val httpService get() = HttpService.getService()
    private val protocolService get() = ProtocolService.getService()
    private val walletService get() = WalletService.getService()

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

        val protocolUri = mex.last.protocolUri
        val messageType = mex.last.type
        checkNotNull(protocolUri) { "No protocol uri" }
        checkNotNull(messageType) { "No message type" }

        val protocolService = ProtocolService.getService()
        val key = protocolService.findProtocolKey(protocolUri)
        val protocolWrapper = protocolService.getProtocol(key, mex)
        return protocolWrapper.invokeMethod(target, messageType)
    }

    /**
     * MessageDispatcher invocation
     */
    override fun invoke(msg: EndpointMessage): MessageExchange? {
        return dispatchInbound(msg)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun dispatchEncryptedEnvelope(encrypted: EndpointMessage): MessageExchange? {

        val rfc0019 = RFC0019EncryptionEnvelope()
        val (message, _, recipientVerkey) = rfc0019.unpackEncryptedEnvelope(encrypted.body as String) ?: run {
                // This service may receive encrypted envelopes with key ids in `recipients.header.kid` that we have never seen.
                // Here, we silently ignore these messages and rely on the unpack function to provide appropriate logging.
                return null
            }

        /**
         * Ok, we successfully unpacked the encrypted message.
         *
         * We now need to find the target Wallet and MessageExchange
         */

        val aux = EndpointMessage(message)

        val recipientWallet = walletService.findByVerkey(recipientVerkey)
        checkNotNull(recipientWallet) { "Cannot find recipient wallet for: $recipientVerkey" }

        /**
         * Now, we dispatch to the MessageExchange associated with the recipientVerkey
         */

        val protocolKey = protocolService.getProtocolKey(aux.type as String)
        checkNotNull(protocolKey) { "Unknown message type: ${aux.type}" }

        val mex = MessageExchange.findByVerkey(recipientVerkey)
        mex.addMessage(EndpointMessage.Builder(aux.body, aux.headers)
            .header(MESSAGE_PROTOCOL_URI, protocolKey.name)
            .build())

        dispatchToWallet(recipientWallet, mex)
        return mex
    }
}
