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
import org.nessus.didcomm.protocol.ProtocolWrapper
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelopeWrapper
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocolWrapper
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocolWrapper
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocol
import org.nessus.didcomm.protocol.RFC0095BasicMessageProtocolWrapper
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocolWrapper
import org.nessus.didcomm.util.AttachmentKey

val RFC0019_ENCRYPTED_ENVELOPE = ProtocolKey("https://rfc0019/application/didcomm-enc-env", RFC0019EncryptionEnvelope::class.java)
val RFC0023_DIDEXCHANGE = ProtocolKey("https://didcomm.org/didexchange/1.0", RFC0023DidExchangeProtocol::class.java)
val RFC0048_TRUST_PING = ProtocolKey("https://didcomm.org/trust_ping/1.0", RFC0048TrustPingProtocol::class.java)
val RFC0095_BASIC_MESSAGE = ProtocolKey("https://didcomm.org/basicmessage/1.0", RFC0095BasicMessageProtocol::class.java)
val RFC0434_OUT_OF_BAND = ProtocolKey("https://didcomm.org/out-of-band/1.1", RFC0434OutOfBandProtocol::class.java)

val RFC0019_ENCRYPTED_ENVELOPE_WRAPPER = ProtocolWrapperKey("https://rfc0019/application/didcomm-enc-env", RFC0019EncryptionEnvelopeWrapper::class.java)
val RFC0023_DIDEXCHANGE_WRAPPER = ProtocolWrapperKey("https://didcomm.org/didexchange/1.0", RFC0023DidExchangeProtocolWrapper::class.java)
val RFC0048_TRUST_PING_WRAPPER = ProtocolWrapperKey("https://didcomm.org/trust_ping/1.0", RFC0048TrustPingProtocolWrapper::class.java)
val RFC0095_BASIC_MESSAGE_WRAPPER = ProtocolWrapperKey("https://didcomm.org/basicmessage/1.0", RFC0095BasicMessageProtocolWrapper::class.java)
val RFC0434_OUT_OF_BAND_WRAPPER = ProtocolWrapperKey("https://didcomm.org/out-of-band/1.1", RFC0434OutOfBandProtocolWrapper::class.java)

class ProtocolKey<P: Protocol>(uri: String, type: Class<P>): AttachmentKey<P>(uri, type) {
    val uri get() = this.name
}

class ProtocolWrapperKey<W: ProtocolWrapper<W, *>>(uri: String, type: Class<W>): AttachmentKey<W>(uri, type) {
    val uri get() = this.name
}

class ProtocolService : NessusBaseService() {
    override val implementation get() = serviceImplementation<ProtocolService>()

    companion object: ServiceProvider {
        private val implementation = ProtocolService()
        override fun getService() = implementation

        val supportedProtocols: List<Pair<ProtocolKey<*>,ProtocolWrapperKey<*>>> get() = listOf(
                Pair(RFC0019_ENCRYPTED_ENVELOPE, RFC0019_ENCRYPTED_ENVELOPE_WRAPPER),
                Pair(RFC0023_DIDEXCHANGE, RFC0023_DIDEXCHANGE_WRAPPER),
                Pair(RFC0048_TRUST_PING, RFC0048_TRUST_PING_WRAPPER),
                Pair(RFC0095_BASIC_MESSAGE, RFC0095_BASIC_MESSAGE_WRAPPER),
                Pair(RFC0434_OUT_OF_BAND, RFC0434_OUT_OF_BAND_WRAPPER),
            )
    }

    fun findProtocolKey(uri: String): ProtocolKey<*> {
        val keyPair = supportedProtocols.find { it.first.uri == uri }
        checkNotNull(keyPair) { "Unknown protocol uri: $uri" }
        return keyPair.first
    }

    fun findProtocolWrapperKey(uri: String): ProtocolWrapperKey<*> {
        val keyPair = supportedProtocols.find { it.first.uri == uri }
        checkNotNull(keyPair) { "Unknown protocol uri: $uri" }
        return keyPair.second
    }

    @Suppress("UNCHECKED_CAST")
    fun <P: Protocol> getProtocol(key: ProtocolKey<P>): P {
        return when(key) {
            RFC0019_ENCRYPTED_ENVELOPE -> RFC0019EncryptionEnvelope()
            RFC0023_DIDEXCHANGE -> RFC0023DidExchangeProtocol()
            RFC0048_TRUST_PING -> RFC0048TrustPingProtocol()
            RFC0095_BASIC_MESSAGE -> RFC0095BasicMessageProtocol()
            RFC0434_OUT_OF_BAND -> RFC0434OutOfBandProtocol()
            else -> throw IllegalStateException("Unknown protocol: $key")
        } as P
    }

    @Suppress("UNCHECKED_CAST")
    fun <W: ProtocolWrapper<W, *>> getProtocolWrapper(key: ProtocolWrapperKey<W>, mex: MessageExchange): W {
        return when(key) {
            RFC0019_ENCRYPTED_ENVELOPE_WRAPPER -> RFC0019EncryptionEnvelopeWrapper(mex)
            RFC0023_DIDEXCHANGE_WRAPPER -> RFC0023DidExchangeProtocolWrapper(mex)
            RFC0048_TRUST_PING_WRAPPER -> RFC0048TrustPingProtocolWrapper(mex)
            RFC0095_BASIC_MESSAGE_WRAPPER -> RFC0095BasicMessageProtocolWrapper(mex)
            RFC0434_OUT_OF_BAND_WRAPPER -> RFC0434OutOfBandProtocolWrapper(mex)
            else -> throw IllegalStateException("Unknown protocol: $key")
        } as W
    }
}
