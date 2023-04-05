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

import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.protocol.BasicMessageProtocolV2
import org.nessus.didcomm.protocol.IssueCredentialProtocolV3
import org.nessus.didcomm.protocol.OutOfBandProtocolV2
import org.nessus.didcomm.protocol.PresentProofProtocolV3
import org.nessus.didcomm.protocol.Protocol
import org.nessus.didcomm.protocol.ReportProblemProtocolV2
import org.nessus.didcomm.protocol.RoutingProtocolV2
import org.nessus.didcomm.protocol.TrustPingProtocolV2
import org.nessus.didcomm.util.AttachmentKey
import kotlin.reflect.KClass

val TRUST_PING_PROTOCOL_V2 = ProtocolKey("https://didcomm.org/trust-ping/2.0", TrustPingProtocolV2::class)
val BASIC_MESSAGE_PROTOCOL_V2 = ProtocolKey("https://didcomm.org/basicmessage/2.0", BasicMessageProtocolV2::class)
val OUT_OF_BAND_PROTOCOL_V2 = ProtocolKey("https://didcomm.org/out-of-band/2.0", OutOfBandProtocolV2::class)
val ISSUE_CREDENTIAL_PROTOCOL_V3 = ProtocolKey("https://didcomm.org/issue-credential/3.0", IssueCredentialProtocolV3::class)
val PRESENT_PROOF_PROTOCOL_V3 = ProtocolKey("https://didcomm.org/present_proof/3.0", PresentProofProtocolV3::class)
val REPORT_PROBLEM_PROTOCOL_V2 = ProtocolKey("https://didcomm.org/report-problem/2.0", ReportProblemProtocolV2::class)
val ROUTING_PROTOCOL_V2 = ProtocolKey("https://didcomm.org/routing/2.0", RoutingProtocolV2::class)

class ProtocolKey<T: Protocol<T>>(uri: String, type: KClass<T>): AttachmentKey<T>(uri, type) {
    val uri get() = this.name
}

object ProtocolService : ObjectService<ProtocolService>() {

    override fun getService() = apply { }

    private val supportedProtocols: List<ProtocolKey<*>> get() = listOf(

        BASIC_MESSAGE_PROTOCOL_V2,
        ISSUE_CREDENTIAL_PROTOCOL_V3,
        OUT_OF_BAND_PROTOCOL_V2,
        PRESENT_PROOF_PROTOCOL_V3,
        ROUTING_PROTOCOL_V2,
        TRUST_PING_PROTOCOL_V2,
    )

    fun findProtocolKey(uri: String): ProtocolKey<*> {
        val keyPair = supportedProtocols.find { it.uri == uri }
        checkNotNull(keyPair) { "Unknown protocol uri: $uri" }
        return keyPair
    }

    @Suppress("UNCHECKED_CAST")
    fun <T: Protocol<T>> getProtocol(key: ProtocolKey<T>, mex: MessageExchange): T {
        return when(key) {

            BASIC_MESSAGE_PROTOCOL_V2 -> BasicMessageProtocolV2(mex)
            ISSUE_CREDENTIAL_PROTOCOL_V3 -> IssueCredentialProtocolV3(mex)
            OUT_OF_BAND_PROTOCOL_V2 -> OutOfBandProtocolV2(mex)
            PRESENT_PROOF_PROTOCOL_V3 -> PresentProofProtocolV3(mex)
            ROUTING_PROTOCOL_V2 -> RoutingProtocolV2(mex)
            TRUST_PING_PROTOCOL_V2 -> TrustPingProtocolV2(mex)

            else -> throw IllegalStateException("Unknown protocol: $key")
        } as T
    }

    fun getProtocolKey(messageType: String): ProtocolKey<*>? {
        return supportedProtocols.firstOrNull { messageType.startsWith(it.name) }
    }
}
