/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
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

import id.walt.servicematrix.ServiceMatrix
import java.nio.file.Paths
import kotlin.io.path.absolutePathString

const val NESSUS_HOME = "NESSUS_HOME"
const val SERVICE_MATRIX_PROPERTIES = "SERVICE_MATRIX_PROPERTIES"

object ServiceMatrixLoader {

    /**
     * Discovery of the `service-matrix.properties` file works like this ...
     *
     * 1. Value of system property `serviceMatrixProperties`
     * 2. Value of env var `SERVICE_MATRIX_PROPERTIES`
     * 3. Fallback to NESSUS_HOME/config/service-matrix.properties
     */
    @JvmStatic
    fun loadServiceDefinitions() {
        val filePath = Paths.get(System.getProperty("serviceMatrixProperties")
            ?: System.getenv(SERVICE_MATRIX_PROPERTIES)
            ?: run {
                val nessusHome = System.getenv(NESSUS_HOME)
                checkNotNull(nessusHome) { "No $NESSUS_HOME" }
                "$nessusHome/config/service-matrix.properties"
            })
        loadServiceDefinitions(filePath.absolutePathString())
    }

    @JvmStatic
    fun loadServiceDefinitions(filePath: String) {
        ServiceMatrix(filePath)
    }
}