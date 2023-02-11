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
val RFC0023_DIDEXCHANGE_V1 = ProtocolKey("https://didcomm.org/didexchange/1.0", RFC0023DidExchangeProtocolV1::class)
val RFC0048_TRUST_PING_V1 = ProtocolKey("https://didcomm.org/trust_ping/1.0", RFC0048TrustPingProtocolV1::class)
val RFC0095_BASIC_MESSAGE_V1 = ProtocolKey("https://didcomm.org/basicmessage/1.0", RFC0095BasicMessageProtocolV1::class)
val RFC0434_OUT_OF_BAND_V1 = ProtocolKey("https://didcomm.org/out-of-band/1.1", RFC0434OutOfBandProtocolV1::class)

val RFC0023_DIDEXCHANGE_V2 = ProtocolKey("https://didcomm.org/didexchange/2.0-preview", RFC0023DidExchangeProtocolV2::class)
val RFC0048_TRUST_PING_V2 = ProtocolKey("https://didcomm.org/trust_ping/2.0-preview", RFC0048TrustPingProtocolV2::class)
val RFC0095_BASIC_MESSAGE_V2 = ProtocolKey("https://didcomm.org/basicmessage/2.0-preview", RFC0095BasicMessageProtocolV2::class)
val RFC0434_OUT_OF_BAND_V2 = ProtocolKey("https://didcomm.org/out-of-band/2.0-preview", RFC0434OutOfBandProtocolV2::class)

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
            RFC0023_DIDEXCHANGE_V1,
            RFC0048_TRUST_PING_V1,
            RFC0095_BASIC_MESSAGE_V1,
            RFC0434_OUT_OF_BAND_V1,

            RFC0048_TRUST_PING_V2,
            RFC0095_BASIC_MESSAGE_V2,
            RFC0023_DIDEXCHANGE_V2,
            RFC0434_OUT_OF_BAND_V2,
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
            RFC0023_DIDEXCHANGE_V1 -> RFC0023DidExchangeProtocolV1(mex)
            RFC0048_TRUST_PING_V1 -> RFC0048TrustPingProtocolV1(mex)
            RFC0095_BASIC_MESSAGE_V1 -> RFC0095BasicMessageProtocolV1(mex)
            RFC0434_OUT_OF_BAND_V1 -> RFC0434OutOfBandProtocolV1(mex)

            RFC0048_TRUST_PING_V2 -> RFC0048TrustPingProtocolV2(mex)
            RFC0023_DIDEXCHANGE_V2 -> RFC0023DidExchangeProtocolV2(mex)
            RFC0095_BASIC_MESSAGE_V2 -> RFC0095BasicMessageProtocolV2(mex)
            RFC0434_OUT_OF_BAND_V2 -> RFC0434OutOfBandProtocolV2(mex)

            else -> throw IllegalStateException("Unknown protocol: $key")
        } as T
    }

    fun getProtocolKey(messageType: String): ProtocolKey<*>? {
        return supportedProtocols.firstOrNull { messageType.startsWith(it.name) }
    }
}
