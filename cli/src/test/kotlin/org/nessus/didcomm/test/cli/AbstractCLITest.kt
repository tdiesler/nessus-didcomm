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

import org.junit.jupiter.api.BeforeAll
import org.nessus.didcomm.cli.CLIService
import org.nessus.didcomm.service.DataModelService


const val RESOURCES_PATH: String = "src/test/resources"

abstract class AbstractCLITest {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            // ServiceMatrix("$RESOURCES_PATH/service-matrix.properties")
        }
    }

    val cliService get() = CLIService.getService()
    val modelService get() = DataModelService.getService()
}
