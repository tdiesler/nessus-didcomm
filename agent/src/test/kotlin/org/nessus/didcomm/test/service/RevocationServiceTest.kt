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
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.service.NessusAuditorService.plusDefaultPolicies
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.trimJson
import java.util.UUID

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
            credentialsEndpoint = "https://example.edu/credential",
            proofType = ProofType.LD_PROOF)

        val vc = W3CVerifiableCredential.Builder
            .fromTemplate(
                pathOrName = "JobCertificate",
                subjectData = """{
                    "id": "uri:uuid:${UUID.randomUUID()}",
                    "issuer": "${issuerDid.uri}",
                    "credentialSubject": {
                        "id": "${holderDid.uri}",
                        "givenName": "Alice",
                        "familyName": "Garcia",
                        "employee_status": "permanent",
                        "salary": "2500"
                    }
                }""".decodeJson())
            .credentialStatus(revocationService.createStatus(config))
            .build()
            .validate()

        // Issue the job certificate VC
        val signedVc = signatory.issue(vc, config)

        // Check revocation status for the job certificate
        val statusA = revocationService.check(signedVc)
        statusA.isRevoked shouldBe false

        // Create the job certificate VP
        val vp = custodian.createPresentation(
            vcs = listOf(signedVc),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri)

        // verification policy
        val policy = policyService.getPolicyWithJsonArg("DynamicPolicy",
            """{
                "input": { "employee_status": "permanent", "salary": 2000 },
                "policy": "src/test/resources/rego/job-certificate-policy.rego"
            }""".trimJson())

        // Verify VP
        val vrGood = auditor.verify(vp, plusDefaultPolicies(policy))
        check(vrGood.result) { "Verification failed" }

        // Revoke the job certificate
        val result = revocationService.revoke(signedVc)
        result.succeed shouldBe true

        // Check revocation status for the job certificate
        val statusB = revocationService.check(signedVc)
        statusB.isRevoked shouldBe true

        // Verify revoked VP
        val vrBad = auditor.verify(vp, plusDefaultPolicies(policy))
        check(vrBad.policyResults["CredentialStatusPolicy"]!!.isFailure)
        check(vrBad.policyResults["DynamicPolicy"]!!.isSuccess)
        vrBad.result shouldBe false
    }
}
