/*-
 * #%L
 * Nessus DIDComm :: Core
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
package org.nessus.didcomm.test.service

import io.kotest.matchers.collections.shouldContainAll
import mu.KotlinLogging
import org.nessus.didcomm.test.AbstractAgentTest

class SignatoryServiceTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun listTemplates() {
        val templates = signatory.templates.map { it.name }
        templates shouldContainAll listOf(
            "BirthCertificate",
            "Email",
            "MarriageCertificate",
            "Passport",
            "TravelPermission",
            "UniversityTranscript",
            "VerifiableId")
        templates.forEach { log.info { it } }
    }
}