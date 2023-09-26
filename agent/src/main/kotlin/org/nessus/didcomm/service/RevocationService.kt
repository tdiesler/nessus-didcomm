/*-
 * #%L
 * Nessus DIDComm :: Agent
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
package org.nessus.didcomm.service

import id.walt.signatory.ProofConfig
import id.walt.signatory.revocation.RevocationClientService
import id.walt.signatory.revocation.RevocationResult
import id.walt.signatory.revocation.RevocationStatus
import id.walt.signatory.revocation.StatusListEntryFactory
import id.walt.signatory.revocation.StatusListEntryFactoryParameter
import id.walt.signatory.revocation.statuslist2021.StatusListCredentialStorageService
import id.walt.signatory.revocation.statuslist2021.StatusListIndexService
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mu.KotlinLogging
import org.nessus.didcomm.model.CredentialStatus
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.toWaltIdType
import org.nessus.didcomm.util.decodeJson

object RevocationService: ObjectService<RevocationService>() {
    val log = KotlinLogging.logger {}

    @JvmStatic
    fun getService() = apply { }

    fun check(vc: W3CVerifiableCredential): RevocationStatus {
        val status = RevocationClientService.check(vc.toWaltIdType())
        log.info { status }
        return status
    }

    fun revoke(vc: W3CVerifiableCredential): RevocationResult {
        val result = RevocationClientService.revoke(vc.toWaltIdType())
        log.info { result }
        return result
    }

    fun createStatus(config: ProofConfig): CredentialStatus {

        val credentialUrl = checkNotNull(config.credentialsEndpoint) { "No credentials endpoint" }

        val parameter = StatusListEntryFactoryParameter(
            purpose = checkNotNull(config.proofPurpose) { "No proof purpose" },
            credentialUrl = "$credentialUrl/status/${config.proofPurpose}",
        )

        val credentialStatusFactory = StatusListEntryFactory(
            StatusListIndexService.getService(),
            StatusListCredentialStorageService.getService(),
        )

        val waltStatus = credentialStatusFactory.create(parameter)
        val statusData = Json.encodeToString(waltStatus).decodeJson().toMutableMap()

        // [TODO] Remove file location hack for status VC
        val statusVCUrl = statusData["statusListCredential"] as String
        if (statusVCUrl.startsWith("https://example.edu/credential"))
            statusData["statusListCredential"] = "data/revocation/${config.proofPurpose}.cred"

        return CredentialStatus.fromMap(statusData)
    }
}
