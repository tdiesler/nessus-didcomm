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
package org.nessus.didcomm.test.protocol

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V2
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.service.RFC0453_ISSUE_CREDENTIAL_V3
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.test.NESSUS_OPTIONS_01
import org.nessus.didcomm.util.decodeJson

/**
 * WACI DIDComm RFC0453: Issue Credential Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/tree/main/issue_credential
 */
class RFC0453IssueCredentialV3Test: AbstractAgentTest() {

    @Test
    fun testRFC0453_IssueCredential() {

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            val faber = Wallet.Builder(Faber.name)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .build()

            try {
                val issuerDid = faber.createDid(DidMethod.KEY)
                val holderDid = alice.createDid(DidMethod.KEY)

                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V2)
                    .createOutOfBandInvitation(faber, issuerDid)
                    .receiveOutOfBandInvitation(alice, holderDid)

                    .withProtocol(RFC0048_TRUST_PING_V2)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .withProtocol(RFC0453_ISSUE_CREDENTIAL_V3)
                    .sendCredentialOffer(
                        issuer = faber,
                        holder = alice,
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
                            }""".decodeJson())
                    .awaitCredentialRequest(faber)
                    .issueCredential(faber)
                    .awaitIssuedCredential(alice)

                    .getMessageExchange()

                val pcon = mex.getConnection()
                pcon.state shouldBe ConnectionState.ACTIVE

                val vc = alice.findVerifiableCredential { vc -> vc.hasType("UniversityTranscript") }
                val subject = vc?.credentialSubject
                val claims = subject?.claims as Map<*, *>
                subject.id.toString() shouldBe holderDid.uri
                claims["givenName"] shouldBe "Alice"
                claims["familyName"] shouldBe "Garcia"
                claims["ssn"] shouldBe "123-45-6789"
                claims["degree"] shouldBe "Bachelor of Science, Marketing"
                claims["status"] shouldBe "graduated"
                claims["year"] shouldBe "2015"
                claims["average"] shouldBe "5"

            } finally {
                removeWallet(alice)
                removeWallet(faber)
            }
        }
    }
}
