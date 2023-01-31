package org.nessus.didcomm.cli

import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.nessus.didcomm.service.AbstractAttachmentsService


class CLIService: AbstractAttachmentsService() {
    override val implementation get() = serviceImplementation<CLIService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = CLIService()
        override fun getService() = implementation
    }

    fun execute(args: String): Result<Any> {
        return NessusCli().execute(args)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}