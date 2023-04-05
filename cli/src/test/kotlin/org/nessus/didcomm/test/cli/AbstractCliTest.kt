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

import io.kotest.core.spec.style.AnnotationSpec
import mu.KotlinLogging
import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.cli.CLIService
import org.nessus.didcomm.cli.NessusCli
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.PropertiesService
import org.nessus.didcomm.service.ServiceMatrixLoader
import org.nessus.didcomm.util.NessusPlaygroundReachable
import picocli.CommandLine
import picocli.CommandLine.IExecutionExceptionHandler
import java.io.OutputStream
import java.io.PrintStream


abstract class AbstractCLITest: AnnotationSpec() {

    @BeforeAll
    fun beforeAll() {

        val filePath = "src/test/resources/config/service-matrix.properties"
        ServiceMatrixLoader.loadServiceDefinitions(filePath)

        // Disable console output
        AbstractBaseCommand.out = PrintStream(OutputStream.nullOutputStream())
    }

    val properties get() = PropertiesService.getService()

    val cliService get() = CLIService.getService()
    val didService get() = DidService.getService()
    val modelService get() = ModelService.getService()

    fun isPlaygroundRunning() = NessusPlaygroundReachable().enabled(RunScriptTest::class)

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
