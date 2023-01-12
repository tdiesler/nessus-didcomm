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
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocol
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.wallet.WalletAgent

val PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE = ProtocolId("https://rfc0019/application/didcomm-enc-env", RFC0019EncryptionEnvelope::class.java)
val PROTOCOL_URI_RFC0095_BASIC_MESSAGE = ProtocolId("https://didcomm.org/basicmessage/1.0", RFC0095BasicMessageProtocol::class.java)
val PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1 = ProtocolId("https://didcomm.org/out-of-band/1.1", RFC0434OutOfBandProtocol::class.java)

class ProtocolId<T: Protocol>(uri: String, type: Class<T>): AttachmentKey<T>(uri, type)

class ProtocolService() : NessusBaseService() {
    override val implementation get() = serviceImplementation<ProtocolService>()

    companion object: ServiceProvider {
        private val implementation = ProtocolService()
        override fun getService() = implementation
    }

    @Suppress("UNCHECKED_CAST")
    fun <T: Protocol> getProtocol(id: ProtocolId<T>, agent: WalletAgent?=null): T {
        if (agent != null) {
            val wallets = WalletService.getService()
            return wallets.assertProtocol(agent, id)
        }
        val protocol = when(id) {
            PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE -> RFC0019EncryptionEnvelope()
            PROTOCOL_URI_RFC0095_BASIC_MESSAGE -> RFC0095BasicMessageProtocol()
            PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1 -> RFC0434OutOfBandProtocol()
            else -> throw IllegalArgumentException("Unknown protocol: ${id.name}")
        }
        return protocol as T
    }
}
