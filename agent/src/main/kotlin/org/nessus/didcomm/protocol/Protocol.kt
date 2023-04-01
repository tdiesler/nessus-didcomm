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
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.DidCommService
import org.nessus.didcomm.service.DidDocResolverService
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.NessusAuditorService
import org.nessus.didcomm.service.NessusCustodianService
import org.nessus.didcomm.service.NessusSignatoryService
import org.nessus.didcomm.service.PropertiesService
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.service.ProtocolService

abstract class Protocol<T: Protocol<T>>(protected val mex: MessageExchange) {

    abstract val log: KLogger
    abstract val protocolUri: String

    val auditor get() = NessusAuditorService.getService()
    val custodian get() = NessusCustodianService.getService()
    val signatory get() = NessusSignatoryService.getService()

    val properties get() = PropertiesService.getService()

    val didService get() = DidService.getService()
    val didComm get() = DidCommService.getService()
    val didResolverService get() = DidDocResolverService.getService()
    val dispatchService get() = MessageDispatchService.getService()
    val keyStore get() = KeyStoreService.getService()
    val modelService get() = ModelService.getService()
    val protocolService get() = ProtocolService.getService()

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

    fun getConnection(): Connection {
        return mex.getConnection()
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchToEndpoint(url: String?, epm: EndpointMessage): T {
        requireNotNull(url) { "No endpoint url" }
        check(epm.messageDirection == MessageDirection.OUT) { "Unexpected message direction: ${epm.messageDirection}" }
        dispatchService.dispatchToEndpoint(url, epm)
        return this as T
    }
}
