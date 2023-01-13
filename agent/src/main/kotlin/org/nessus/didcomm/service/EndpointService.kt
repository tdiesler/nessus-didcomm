package org.nessus.didcomm.service

import id.walt.servicematrix.ServiceProvider
import org.nessus.didcomm.protocol.MessageListener


abstract class EndpointService<T: Any>: NessusBaseService() {
    override val implementation get() = serviceImplementation<EndpointService<Any>>()

    companion object: ServiceProvider {
        override fun getService() = object : EndpointService<Any>() {}
        override fun defaultImplementation() = CamelEndpointService()
    }

    open val endpointUrl: String? get() = implementation.endpointUrl

    /**
     * Starts the endpoint service
     * @return A handle specific to the endpoint implementation
     */
    open fun startEndpoint(listener: MessageListener? = null): T? {
        return null
    }

    /**
     * Stops the endpoint service represented by the given handle
     */
    open fun stopEndpoint(handle: T? = null) {
        // Do nothing
    }
}
