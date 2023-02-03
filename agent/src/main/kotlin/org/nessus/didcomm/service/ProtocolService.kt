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
import mu.KotlinLogging
import org.nessus.didcomm.protocol.*
import org.nessus.didcomm.util.AttachmentKey
import kotlin.reflect.KClass

val RFC0019_ENCRYPTED_ENVELOPE = ProtocolKey("https://rfc0019/application/didcomm-enc-env", RFC0019EncryptionEnvelope::class)
val RFC0023_DIDEXCHANGE = ProtocolKey("https://didcomm.org/didexchange/1.0", RFC0023DidExchangeProtocol::class)
val RFC0048_TRUST_PING = ProtocolKey("https://didcomm.org/trust_ping/1.0", RFC0048TrustPingProtocol::class)
val RFC0095_BASIC_MESSAGE = ProtocolKey("https://didcomm.org/basicmessage/1.0", RFC0095BasicMessageProtocol::class)
val RFC0434_OUT_OF_BAND = ProtocolKey("https://didcomm.org/out-of-band/1.1", RFC0434OutOfBandProtocol::class)

class ProtocolKey<T: Protocol<T>>(uri: String, type: KClass<T>): AttachmentKey<T>(uri, type) {
    val uri get() = this.name
}

class ProtocolService : NessusBaseService() {
    override val implementation get() = serviceImplementation<ProtocolService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = ProtocolService()
        override fun getService() = implementation

        val supportedProtocols: List<ProtocolKey<*>> get() = listOf(
                RFC0019_ENCRYPTED_ENVELOPE,
                RFC0023_DIDEXCHANGE,
                RFC0048_TRUST_PING,
                RFC0095_BASIC_MESSAGE,
                RFC0434_OUT_OF_BAND,
            )
    }

    fun findProtocolKey(uri: String): ProtocolKey<*> {
        val keyPair = supportedProtocols.find { it.uri == uri }
        checkNotNull(keyPair) { "Unknown protocol uri: $uri" }
        return keyPair
    }

    @Suppress("UNCHECKED_CAST")
    fun <T: Protocol<T>> getProtocol(key: ProtocolKey<T>, mex: MessageExchange): T {
        return when(key) {
            RFC0019_ENCRYPTED_ENVELOPE -> RFC0019EncryptionEnvelope()
            RFC0023_DIDEXCHANGE -> RFC0023DidExchangeProtocol(mex)
            RFC0048_TRUST_PING -> RFC0048TrustPingProtocol(mex)
            RFC0095_BASIC_MESSAGE -> RFC0095BasicMessageProtocol(mex)
            RFC0434_OUT_OF_BAND -> RFC0434OutOfBandProtocol(mex)
            else -> throw IllegalStateException("Unknown protocol: $key")
        } as T
    }

    fun getProtocolKey(messageType: String): ProtocolKey<*>? {
        return supportedProtocols.firstOrNull { messageType.startsWith(it.name) }
    }
}
