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
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.prettyGson
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

    private val protocols get() = ProtocolService.getService()

    /**
     * Entry point for all unqualified messages, for example coming
     * in through an Http endpoint
     */
    override fun invoke(msg: EndpointMessage): Boolean {
        val contentType = msg.headers["Content-Type"] as? String
        checkNotNull(contentType) { "No Content-Type" }
        check(msg.body is String) { "No msg body" }
        return messageHandler(contentType, msg.body)
    }

    /**
     * Routes the message to a given target wallet through it's associated protocol.
     *
     * Note, the target protocol must support also support `sendTo`
     */
    fun sendTo(to: Wallet, mex: MessageExchange): Boolean {
        val pid = when(val protocolUri = mex.message.protocolUri) {
            PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1.name -> PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1
            else -> throw IllegalStateException("Unknown protocol: $protocolUri")
        }
        val protocol = protocols.getProtocol(pid, to.walletAgent)
        return protocol.sendTo(to, mex)
    }

    private fun messageHandler(contentType: String, envelope: String): Boolean {
        log.info { "Content-Type: $contentType" }
        log.info { envelope.prettyPrint() }
        return when(contentType) {
            "application/didcomm-envelope-enc" -> didcommEncryptedEnvelopeHandler(contentType, envelope)
            else -> throw IllegalStateException("Unsupported content type: $contentType")
        }
    }

    private fun didcommEncryptedEnvelopeHandler(contentType: String, envelope: String): Boolean {
        require("application/didcomm-envelope-enc" == contentType)
        val protocols = ProtocolService.getService()
        val rfc0019 = protocols.getProtocol(PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE)
        val unpacked = rfc0019.unpackRFC0019Envelope(envelope)
        if (unpacked != null) {
            val unpackedMap = unpacked.decodeJson()
            log.info { "Unpacked Envelope: ${prettyGson.toJson(unpackedMap)}" }
        }
        return unpacked != null
    }
}
