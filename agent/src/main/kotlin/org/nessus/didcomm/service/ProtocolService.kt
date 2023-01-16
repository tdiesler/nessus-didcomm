/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
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
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.Protocol
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocol
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.wallet.WalletAgent

val PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE = ProtocolKey("https://rfc0019/application/didcomm-enc-env", RFC0019EncryptionEnvelope::class.java)
val PROTOCOL_URI_RFC0023_DID_EXCHANGE = ProtocolKey("https://didcomm.org/didexchange/1.0", RFC0023DidExchangeProtocol::class.java)
val PROTOCOL_URI_RFC0048_TRUST_PING = ProtocolKey("https://didcomm.org/trust_ping/1.0", RFC0048TrustPingProtocol::class.java)
val PROTOCOL_URI_RFC0095_BASIC_MESSAGE = ProtocolKey("https://didcomm.org/basicmessage/1.0", RFC0095BasicMessageProtocol::class.java)
val PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1 = ProtocolKey("https://didcomm.org/out-of-band/1.1", RFC0434OutOfBandProtocol::class.java)

class ProtocolKey<T: Protocol<T>>(uri: String, type: Class<T>): AttachmentKey<T>(uri, type) {
    val uri get() = this.name
}

class ProtocolService : NessusBaseService() {
    override val implementation get() = serviceImplementation<ProtocolService>()

    companion object: ServiceProvider {
        private val implementation = ProtocolService()
        override fun getService() = implementation

        val supportedProtocols: List<ProtocolKey<*>> get() = listOf(
                PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE,
                PROTOCOL_URI_RFC0023_DID_EXCHANGE,
                PROTOCOL_URI_RFC0048_TRUST_PING,
                PROTOCOL_URI_RFC0095_BASIC_MESSAGE,
                PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1,
            )

        val protocolsByAgent: Map<WalletAgent, List<ProtocolKey<*>>> get() = mapOf(
            WalletAgent.ACAPY to listOf(
                PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE,
                PROTOCOL_URI_RFC0023_DID_EXCHANGE,
                PROTOCOL_URI_RFC0048_TRUST_PING,
                PROTOCOL_URI_RFC0095_BASIC_MESSAGE,
                PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1,
            ),
            WalletAgent.NESSUS to listOf(
                PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE,
                PROTOCOL_URI_RFC0023_DID_EXCHANGE,
                PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1,
            ),
        )

        fun findProtocolKey(uri: String): ProtocolKey<*> {
            val key = supportedProtocols.find { it.uri == uri }
            checkNotNull(key) { "Unknown protocol uri: $uri" }
            return key
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T: Protocol<T>> getProtocol(key: ProtocolKey<T>, mex: MessageExchange, agent: WalletAgent? = null): T {
        if (agent != null) check(protocolsByAgent[agent]!!.contains(key))
        return when(key) {
            PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE -> RFC0019EncryptionEnvelope(mex)
            PROTOCOL_URI_RFC0023_DID_EXCHANGE -> RFC0023DidExchangeProtocol(mex)
            PROTOCOL_URI_RFC0048_TRUST_PING -> RFC0048TrustPingProtocol(mex)
            PROTOCOL_URI_RFC0095_BASIC_MESSAGE -> RFC0095BasicMessageProtocol(mex)
            PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1 -> RFC0434OutOfBandProtocol(mex)
            else -> throw IllegalStateException("Unknown protocol: $key")
        } as T
    }
}
