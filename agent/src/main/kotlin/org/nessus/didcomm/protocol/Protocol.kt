/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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
package org.nessus.didcomm.protocol

import id.walt.services.keystore.KeyStoreService
import mu.KLogger
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.*
import org.nessus.didcomm.util.unionMap
import org.nessus.didcomm.w3c.NessusSignatoryService

abstract class Protocol<T: Protocol<T>>(protected val mex: MessageExchange) {

    abstract val log: KLogger
    abstract val protocolUri: String

    val didService get() = DidService.getService()
    val didComm get() = DidCommService.getService()
    val diddocV1Service get() = DidDocumentV1Service.getService()
    val diddocV2Service get() = DidDocumentV2Service.getService()
    val dispatchService get() = MessageDispatchService.getService()
    val keyStore get() = KeyStoreService.getService()
    val modelService get() = ModelService.getService()
    val protocolService get() = ProtocolService.getService()
    val signatory get() = NessusSignatoryService.getService()

    abstract val supportedAgentTypes: List<AgentType>

    fun checkAgentType(agentType: AgentType) {
        require(agentType in supportedAgentTypes) { "Protocol not supported by $agentType" }
    }


    internal open fun invokeMethod(to: Wallet, messageType: String): Boolean {
        throw IllegalStateException("Dispatch not supported in protocol: $protocolUri")
    }

    fun <T :Protocol<T>> withProtocol(key: ProtocolKey<T>): T {
        return mex.withProtocol(key)
    }

    fun getMessageExchange(): MessageExchange {
        return mex
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchTo(target: Wallet, headers: Map<String, Any?> = mapOf()): T {

        // Merge headers and create the follow-up message if needed
        val effectiveHeaders = mex.last.headers.unionMap(headers).toMutableMap()
        if (effectiveHeaders != mex.last.headers) {
            mex.addMessage(EndpointMessage(mex.last.body, effectiveHeaders.toMap()))
        }

        dispatchService.dispatchToWallet(target, mex)
        return this as T
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchToEndpoint(url: String?, epm: EndpointMessage): T {
        requireNotNull(url) { "No endpoint url" }
        dispatchService.dispatchToEndpoint(url, epm)
        return this as T
    }
}
