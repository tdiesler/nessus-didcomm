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

import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.agent.NessusAgentService
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport

val ARIES_AGENT_SERVICE_KEY = AttachmentKey("Aries", AgentService::class.java)
val NESSUS_AGENT_SERVICE_KEY = AttachmentKey("Nessus", AgentService::class.java)

val WALLET_SERVICE_KEY = AttachmentKey(WalletService::class.java)

// [TODO] document all services
interface Service {
    val type: Class<out Service>
}

// [TODO] document ServiceRegistry
object ServiceRegistry {

    private val registry = AttachmentSupport()

    fun <T : Service> getService(key: AttachmentKey<T>) : T? {
        return registry.getAttachment(key)
    }

    fun <T : Service> putService(key: AttachmentKey<T>, service: T) {
        registry.putAttachment(key, service)
    }

    fun ariesAgentService(): AriesAgentService {
        return getService(ARIES_AGENT_SERVICE_KEY) as AriesAgentService
    }

    fun nessusAgentService(): NessusAgentService {
        return getService(NESSUS_AGENT_SERVICE_KEY) as NessusAgentService
    }

    fun walletService(): WalletService {
        return getService(WALLET_SERVICE_KEY) as WalletService
    }
}