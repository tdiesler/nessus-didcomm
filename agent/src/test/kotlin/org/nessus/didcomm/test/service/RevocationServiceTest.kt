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

import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.revocation.RevocationResult
import id.walt.signatory.revocation.StatusListEntryFactory
import id.walt.signatory.revocation.StatusListEntryFactoryParameter
import id.walt.signatory.revocation.statuslist2021.StatusListCredentialStorageService
import id.walt.signatory.revocation.statuslist2021.StatusListIndexService
import io.ktor.http.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.nessus.didcomm.model.CredentialStatus
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.toWaltIdType
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeJson

class RevocationServiceTest: AbstractAgentTest() {

    @Test
    fun revokeJobCertificate() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        val config = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            // [TODO] signatoryConfig.proofConfig.credentialsEndpoint
            credentialsEndpoint = "https://example.com/credentials/status",
            proofType = ProofType.LD_PROOF)

        val vc = W3CVerifiableCredential.Builder
            .fromTemplate(
                "JobCertificate",
                true,
                """{
                    "issuer": "${issuerDid.uri}",
                    "credentialSubject": {
                        "id": "${holderDid.uri}",
                        "givenName": "Alice",
                        "familyName": "Garcia",
                        "employee_status": "permanent",
                        "salary": "2500"
                    }
                }""".decodeJson())
            .credentialStatus(statusListCredentialStatus(config))
            .build()
            .validate()

        // Issue the job certificate
        val signedVc = signatory.issue(vc, config, false)

        // Revoke the job certificate
        val revResult: RevocationResult = revocationService.revoke(signedVc.toWaltIdType())
        // revResult.succeed shouldBe true
    }

    private fun statusListCredentialStatus(config: ProofConfig): CredentialStatus {

        val purpose = checkNotNull(config.proofPurpose) { "No proof purpose" }
        val credentialUrl = checkNotNull(config.credentialsEndpoint) { "No credentials endpoint" }

        val parameter = StatusListEntryFactoryParameter(
            purpose = purpose,
            credentialUrl = URLBuilder().takeFrom(credentialUrl).appendPathSegments("status", purpose).buildString(),
        )

        val credentialStatusFactory = StatusListEntryFactory(
            StatusListIndexService.getService(),
            StatusListCredentialStorageService.getService(),
        )

        val waltStatus = credentialStatusFactory.create(parameter)
        return CredentialStatus.fromMap(Json.encodeToString(waltStatus).decodeJson())
    }
}
