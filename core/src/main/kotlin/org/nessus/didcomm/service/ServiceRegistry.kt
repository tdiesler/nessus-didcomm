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
