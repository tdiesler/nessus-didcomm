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
import okhttp3.MediaType.Companion.toMediaType
import org.didcommx.didcomm.common.Typ.Encrypted
import org.didcommx.didcomm.common.Typ.Plaintext
import org.didcommx.didcomm.common.Typ.Signed
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.UnpackParams
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_PROTOCOL_URI
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_RECIPIENT_VERKEY
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_SENDER_VERKEY
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocolV1.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.matches

typealias MessageDispatcher = (msg: EndpointMessage) -> MessageExchange?

/**
 * The MessageDispatchService is the entry point for all messages
 */
class MessageDispatchService: AbstractBaseService(), MessageDispatcher {
    override val implementation get() = serviceImplementation<MessageDispatchService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = MessageDispatchService()
        override fun getService() = implementation
    }

    private val httpService get() = HttpService.getService()
    private val modelService get() = ModelService.getService()
    private val protocolService get() = ProtocolService.getService()

    /**
     * Entry point for all external messages sent to a wallet endpoint
     */
    fun dispatchInbound(epm: EndpointMessage): MessageExchange? {
        val contentType = epm.headers["Content-Type"] as? String
        checkNotNull(contentType) { "No 'Content-Type' header"}
        return when {
            RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE.matches(contentType) -> dispatchEncryptionEnvelopeV1(epm)
            Plaintext.typ.toMediaType().matches(contentType) -> dispatchPlaintextEnvelope(epm)
            Signed.typ.toMediaType().matches(contentType) -> dispatchSignedEnvelope(epm)
            Encrypted.typ.toMediaType().matches(contentType) -> dispatchEncryptedEnvelopeV2(epm)
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
        val protocol = protocolService.getProtocol(key, mex)
        return protocol.invokeMethod(target, messageType)
    }

    /**
     * MessageDispatcher invocation
     */
    override fun invoke(msg: EndpointMessage): MessageExchange? {
        return dispatchInbound(msg)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun dispatchEncryptionEnvelopeV1(encrypted: EndpointMessage): MessageExchange? {

        val rfc0019 = RFC0019EncryptionEnvelope()
        val (message, senderVerkey, recipientVerkey) = rfc0019.unpackEncryptedEnvelope(encrypted.body as String) ?: run {
                // This service may receive encrypted envelopes with key ids in `recipients.header.kid` that we have never seen.
                // Here, we silently ignore these messages and rely on the unpack function to provide appropriate logging.
                return null
            }

        /**
         * Ok, we successfully unpacked the encrypted message.
         *
         * We now need to find the target Wallet and MessageExchange
         */

        val aux = EndpointMessage(message, mapOf(
            MESSAGE_HEADER_SENDER_VERKEY to senderVerkey,
            MESSAGE_HEADER_RECIPIENT_VERKEY to recipientVerkey))

        // The other agent may send ping messages to a wallet that we have already deleted
        // We warn about these, all other undeliverable messages cause an error
        val recipientWallet = modelService.findWalletByVerkey(recipientVerkey) ?: run {
            val logmsg = "Cannot find recipient wallet verkey=$recipientVerkey"
            when (aux.type) {
                RFC0048_TRUST_PING_MESSAGE_TYPE_PING_V1 -> log.warn { "$logmsg for trust ping" }
                else -> log.error { "$logmsg for message type: ${aux.type}" }
            }
            return null
        }

        /**
         * Now, we dispatch to the MessageExchange associated with the recipientVerkey
         */

        val protocolKey = protocolService.getProtocolKey(aux.type as String)
        checkNotNull(protocolKey) { "Unknown message type: ${aux.type}" }

        val mex = MessageExchange.findByVerkey(recipientVerkey)
        mex.addMessage(EndpointMessage.Builder(aux.body, aux.headers)
            .header(MESSAGE_HEADER_PROTOCOL_URI, protocolKey.name)
            .build())

        dispatchToWallet(recipientWallet, mex)
        return mex
    }

    private fun dispatchPlaintextEnvelope(plaintext: EndpointMessage): MessageExchange? {
        val unpackResult = DidCommService.getService().unpack(
            UnpackParams.Builder(plaintext.bodyAsJson).build()
        )
        return dispatchUnpackedMessage(unpackResult.message)
    }

    private fun dispatchSignedEnvelope(signed: EndpointMessage): MessageExchange? {
        val unpackResult = DidCommService.getService().unpack(
            UnpackParams.Builder(signed.bodyAsJson).build()
        )
        return dispatchUnpackedMessage(unpackResult.message)
    }

    private fun dispatchEncryptedEnvelopeV2(encrypted: EndpointMessage): MessageExchange? {
        val unpackResult = DidCommService.getService().unpack(
            UnpackParams.Builder(encrypted.bodyAsJson).build()
        )
        return dispatchUnpackedMessage(unpackResult.message)
    }

    private fun dispatchUnpackedMessage(msg: Message): MessageExchange? {

        log.info { "Unpacked Message\n${msg.encodeJson(true)}" }
        checkNotNull(msg.to) { "No target did" }

        /**
         * Find the target Wallet and MessageExchange
         */

        val recipientDids = msg.to!!.map { Did.fromSpec(it) }
            .filter { modelService.findWalletByVerkey(it.verkey) != null }
        check(recipientDids.size < 2) { "Multiple recipients not supported" }
        check(recipientDids.isNotEmpty()) { "No recipient wallet" }

        /**
         * Now, we dispatch to the MessageExchange associated with the recipientVerkey
         */

        val protocolKey = protocolService.getProtocolKey(msg.type)
        checkNotNull(protocolKey) { "Unknown message type: ${msg.type}" }

        val recipientVerkey = recipientDids.first().verkey
        val recipientWallet = modelService.findWalletByVerkey(recipientVerkey) as Wallet

        val senderVerkey =
            if (msg.from?.startsWith("did:key") == true)
                Did.fromSpec(msg.from!!).verkey
            else null

        val mex = MessageExchange.findByVerkey(recipientVerkey)
        mex.addMessage(EndpointMessage.Builder(msg)
            .header(MESSAGE_HEADER_PROTOCOL_URI, protocolKey.name)
            .header(MESSAGE_HEADER_SENDER_VERKEY, senderVerkey)
            .header(MESSAGE_HEADER_RECIPIENT_VERKEY, recipientVerkey)
            .build())

        dispatchToWallet(recipientWallet, mex)
        return mex
    }
}
