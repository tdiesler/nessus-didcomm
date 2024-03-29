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
package org.nessus.didcomm.service

import id.walt.servicematrix.BaseService
import id.walt.servicematrix.ServiceProvider
import id.walt.servicematrix.ServiceRegistry

abstract class EndpointService<T: AutoCloseable>: BaseService() {
    override val implementation get() = serviceImplementation<EndpointService<T>>()

    companion object: ServiceProvider {
        override fun getService(): EndpointService<out AutoCloseable> = ServiceRegistry.getService()
        override fun defaultImplementation() = HttpEndpointService()
    }

    /**
     * Starts the endpoint service for a given wallet
     *
     * @return A handle specific to the endpoint implementation
     */
    open fun startEndpoint(endpointUrl: String, dispatcher: MessageReceiver? = null): T {
        throw IllegalStateException("Override startEndpoint")
    }

    /**
     * Stops the endpoint service represented by the given handle
     */
    open fun <T: AutoCloseable> stopEndpoint(handle: T) {
        handle.close()
    }
}
