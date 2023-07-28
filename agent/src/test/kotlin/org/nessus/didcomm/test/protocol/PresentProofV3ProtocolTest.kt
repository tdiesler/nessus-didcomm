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
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Acme
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.trimJson

/**
 * WACI DIDComm: Present Proof Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/blob/main/present_proof/present-proof-v3.md
 */
class PresentProofV3ProtocolTest: AbstractAgentTest() {

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
    }

    @Before
    fun beforeEach() {
        Wallet.Builder(Faber.name).build()
        Wallet.Builder(Acme.name).build()
        Wallet.Builder(Alice.name).build()
    }

    @After
    fun afterEach() {
        removeWallets()
    }

    @Test
    fun presentProof_FromRequest() {

        val faber = walletByName(Faber.name)
        val alice = walletByName(Alice.name)

        val faberAliceCon = peerConnect(faber, alice)
        val holderDid = faberAliceCon.theirDid

        issueCredential(
            issuer = faber,
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
            }""".decodeJson())

        val acme = walletByName(Acme.name)
        val acmeAliceCon = peerConnect(acme, alice)
        val verifierDid = acmeAliceCon.myDid
        val proverDid = acmeAliceCon.theirDid

        val unsignedVc = W3CVerifiableCredential.fromTemplate("UniversityTranscript")

        // verification policy
        val policy = policyService.getPolicyWithJsonArg("DynamicPolicy",
            """{
                "input": { "status": "graduated", "average": 4 },
                "policy": "src/test/resources/rego/transcript-policy.rego"
            }""".trimJson())

        MessageExchange()
            .withConnection(acmeAliceCon)
            .withProtocol(PRESENT_PROOF_PROTOCOL_V3)
            .sendPresentationRequest(
                verifier = acme,
                proverDid = proverDid,
                vc = unsignedVc,
                options = mapOf("goal_code" to "Verify University Transcript")
            )
            .awaitPresentation(acme, proverDid)
            .verifyPresentation(acme, listOf(policy))
            .awaitPresentationAck(alice, verifierDid)
            .getMessageExchange()

        val vp = acme.findVerifiablePresentationsByType("UniversityTranscript").first()
        val vc = vp.verifiableCredential.first()

        val subject = vc.credentialSubject
        val claims = subject.toMap()
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }

    @Test
    fun presentProof_FromProposal() {

        val faber = walletByName(Faber.name)
        val alice = walletByName(Alice.name)

        val faberAliceCon = peerConnect(faber, alice)
        val holderDid = faberAliceCon.theirDid

        issueCredential(
            issuer = faber,
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
            }""".decodeJson())

        val acme = walletByName(Acme.name)
        val aliceAcmeCon = peerConnect(acme, alice, true)
        val verifierDid = aliceAcmeCon.theirDid

        val unsignedVc = W3CVerifiableCredential.fromTemplate(
            pathOrName = "UniversityTranscript",
            stripValues = false)

        MessageExchange()
            .withConnection(aliceAcmeCon)
            .withProtocol(PRESENT_PROOF_PROTOCOL_V3)
            .sendPresentationProposal(
                prover = alice,
                verifierDid = verifierDid,
                vcs = listOf(unsignedVc),
                options = mapOf("goal_code" to "Verify University Transcript")
            )
            .awaitPresentationRequest(alice, verifierDid)
            .awaitPresentationAck(alice, verifierDid)
            .getMessageExchange()

        val vp = acme.findVerifiablePresentationsByType("UniversityTranscript").first()
        val vc = vp.verifiableCredential.first()

        val subject = vc.credentialSubject
        val claims = subject.toMap()
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }
}
