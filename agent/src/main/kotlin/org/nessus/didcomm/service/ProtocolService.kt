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
import org.nessus.didcomm.protocol.Protocol
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocol
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.toUnionMap
import org.nessus.didcomm.wallet.WalletAgent

val PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE = ProtocolId("https://rfc0019/application/didcomm-enc-env", RFC0019EncryptionEnvelope::class.java)
val PROTOCOL_URI_RFC0023_DID_EXCHANGE = ProtocolId("https://didcomm.org/didexchange/1.0", RFC0023DidExchangeProtocol::class.java)
val PROTOCOL_URI_RFC0048_TRUST_PING = ProtocolId("https://didcomm.org/trust_ping/1.0", RFC0048TrustPingProtocol::class.java)
val PROTOCOL_URI_RFC0095_BASIC_MESSAGE = ProtocolId("https://didcomm.org/basicmessage/1.0", RFC0095BasicMessageProtocol::class.java)
val PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1 = ProtocolId("https://didcomm.org/out-of-band/1.1", RFC0434OutOfBandProtocol::class.java)

class ProtocolId<T: Protocol>(uri: String, type: Class<T>): AttachmentKey<T>(uri, type) {
    val uri get() = this.name
}

class ProtocolService : NessusBaseService() {
    override val implementation get() = serviceImplementation<ProtocolService>()

    companion object: ServiceProvider {
        private val implementation = ProtocolService()
        override fun getService() = implementation

        @Suppress("UNCHECKED_CAST")
        val supportedProtocols: Map<ProtocolId<*>, Protocol> get() = run {
            val acapyProtocols = supportedProtocolsByAgent[WalletAgent.ACAPY]!!
            val nessusProtocols = supportedProtocolsByAgent[WalletAgent.NESSUS]!!
            acapyProtocols.toUnionMap(nessusProtocols) as Map<ProtocolId<*>, Protocol>
        }

        val supportedProtocolsByAgent: Map<WalletAgent, Map<ProtocolId<*>, Protocol>> get() = mapOf(
            WalletAgent.ACAPY to mapOf(
                PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE to RFC0019EncryptionEnvelope(),
                PROTOCOL_URI_RFC0023_DID_EXCHANGE to RFC0023DidExchangeProtocol(),
                PROTOCOL_URI_RFC0048_TRUST_PING to RFC0048TrustPingProtocol(),
                PROTOCOL_URI_RFC0095_BASIC_MESSAGE to RFC0095BasicMessageProtocol(),
                PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1 to RFC0434OutOfBandProtocol(),
            ),
            WalletAgent.NESSUS to mapOf(
                PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE to RFC0019EncryptionEnvelope(),
                PROTOCOL_URI_RFC0023_DID_EXCHANGE to RFC0023DidExchangeProtocol(),
                PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1 to RFC0434OutOfBandProtocol(),
            ),
        )
    }

    @Suppress("UNCHECKED_CAST")
    fun <T: Protocol> getProtocol(id: ProtocolId<T>, agent: WalletAgent? = null): T {
        if (agent != null) {
            val wallets = WalletService.getService()
            return wallets.assertProtocol(agent, id)
        }
        return supportedProtocols[id] as? T
            ?: throw IllegalArgumentException("Unknown protocol: ${id.name}")
    }
}
