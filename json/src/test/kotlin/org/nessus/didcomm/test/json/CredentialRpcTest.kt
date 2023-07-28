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
package org.nessus.didcomm.test.json

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.json.model.VCData
import org.nessus.didcomm.model.WalletRole
import org.nessus.didcomm.util.toValueMap

class CredentialRpcTest: AbstractJsonRpcTest() {

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
    }

    @Test
    fun issueCredential() {
        val faber = createWallet("Faber", WalletRole.ENDORSER)
        val alice = createWallet("Alice")
        try {
            val faberAliceCon = peerConnect(faber, alice)
            val holderDid = faberAliceCon.theirDid.uri

            issueCredential(VCData(
                issuerId = faber.id,
                holderDid = holderDid,
                template = "UniversityTranscript",
                subjectData = """
                {
                  "givenName": "Alice",
                  "familyName": "Garcia",
                  "ssn": "123-45-6789",
                  "degree": "Bachelor of Science, Marketing",
                  "status": "graduated",
                  "year": "2015",
                  "average": "5"
                }                
                """.toValueMap()))

            val vc = alice.findVerifiableCredentialsByType("UniversityTranscript")
                .first { "${it.credentialSubject.id}" == holderDid }

            val subject = vc.credentialSubject
            val claims = subject.toMap()
            subject.id.toString() shouldBe holderDid
            claims["givenName"] shouldBe "Alice"
            claims["familyName"] shouldBe "Garcia"
            claims["ssn"] shouldBe "123-45-6789"
            claims["degree"] shouldBe "Bachelor of Science, Marketing"
            claims["status"] shouldBe "graduated"
            claims["year"] shouldBe "2015"
            claims["average"] shouldBe "5"

        } finally {
            removeWallets()
        }
    }

    // [TODO] list connections
    // [TODO] remove connection
}
