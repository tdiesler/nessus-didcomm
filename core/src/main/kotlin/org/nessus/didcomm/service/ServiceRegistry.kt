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

// [TODO] document all services
interface Service {
    val type: Class<out Service>
}

// [TODO] document ServiceRegistry
object ServiceRegistry {

    private val registry : MutableMap<String, Service> = mutableMapOf()

    fun <T : Service> getService(type : Class<T>) : T {
        return registry[type.name] as T
    }

    fun <T : Service> addService(service: T) {
        registry[service.type.name] = service
    }
}

fun agentService(): AgentService {
    return ServiceRegistry.getService(AgentService.type)
}

fun walletService(): WalletService {
    return ServiceRegistry.getService(WalletService.type)
}
