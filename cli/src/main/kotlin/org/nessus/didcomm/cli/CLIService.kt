/*-
 * #%L
 * Nessus DIDComm :: CLI
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
package org.nessus.didcomm.cli

import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.nessus.didcomm.service.AbstractAttachmentsService
import picocli.CommandLine


class CLIService: AbstractAttachmentsService() {
    override val implementation get() = serviceImplementation<CLIService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = CLIService()
        override fun getService() = implementation
    }

    fun execute(args: String, cmdln: CommandLine? = null): Result<Any> {
        return NessusCli().execute(args, cmdln)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
