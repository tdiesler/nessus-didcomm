package org.nessus.didcomm.service

import id.walt.servicematrix.ServiceProvider


class JWTService: NessusBaseService() {
    override val implementation get() = serviceImplementation<DidService>()

    companion object: ServiceProvider {
        private val implementation = JWTService()
        override fun getService() = implementation
    }

}