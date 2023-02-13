/*-
 * #%L
 * Nessus DIDComm :: ITests
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
package org.nessus.didcomm.test.cli

import mu.KotlinLogging
import org.junit.jupiter.api.BeforeAll
import org.nessus.didcomm.cli.service.CLIService
import org.nessus.didcomm.cli.NessusCli
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.ServiceMatrixLoader
import picocli.CommandLine
import picocli.CommandLine.IExecutionExceptionHandler


abstract class AbstractCmdTest {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            val filePath = "etc/config/service-matrix.properties"
            ServiceMatrixLoader.loadServiceDefinitions(filePath)
        }
    }

    val cliService get() = CLIService.getService()
    val modelService get() = ModelService.getService()

    fun safeExecutionCommandLine(): CommandLine {
        val cmdln = NessusCli.defaultCommandLine
        cmdln.executionExceptionHandler = IExecutionExceptionHandler { ex, _, _ ->
            val log = KotlinLogging.logger { }
            log.debug { ex.message }
            1
        }
        return cmdln
    }
}
