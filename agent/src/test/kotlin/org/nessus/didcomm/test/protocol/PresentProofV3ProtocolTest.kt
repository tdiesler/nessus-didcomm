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

import id.walt.credentials.w3c.VerifiablePresentation
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredentialHelper
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.service.PropertiesService
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber

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

        var verifierDid: Did?
        var proverDid: Did?

        val unsignedVc = W3CVerifiableCredentialHelper.fromTemplate(
            pathOrName = "UniversityTranscript",
            stripValues = true)
        val unsignedVp = VerifiablePresentation.fromVerifiableCredential(unsignedVc)

        MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(faber)
            .receiveOutOfBandInvitation(alice, inviterAlias = faber.name)

            .withProperty(PropertiesService.PROTOCOL_TRUST_PING_ROTATE_DID, false)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                check(pcon.theirLabel == faber.name)
                check(pcon.myLabel == alice.name)
                verifierDid = pcon.theirDid
                proverDid = pcon.myDid
            }

            .withProtocol(PRESENT_PROOF_PROTOCOL_V3)
            .sendPresentationRequest(
                verifier = faber,
                proverDid = proverDid!!,
                vp = unsignedVp,
                options = mapOf("goal_code" to "Verify University Transcript")
            )
            .awaitPresentation(faber, proverDid!!)
            .awaitPresentationAck(alice, verifierDid!!)
            .getMessageExchange()

        val vp = faber.findVerifiablePresentationsByType("UniversityTranscript").first()
        val vc = vp.verifiableCredential!!.first()

        val subject = vc.credentialSubject!!
        val claims = subject.properties
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

        var verifierDid: Did?
        var proverDid: Did?

        val unsignedVc = W3CVerifiableCredentialHelper.fromTemplate(
            pathOrName = "UniversityTranscript",
            stripValues = false)

        MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(faber)
            .receiveOutOfBandInvitation(alice, inviterAlias = faber.name)

            .withProperty(PropertiesService.PROTOCOL_TRUST_PING_ROTATE_DID, false)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                check(pcon.theirLabel == faber.name)
                check(pcon.myLabel == alice.name)
                verifierDid = pcon.theirDid
                proverDid = pcon.myDid
            }

            .withProtocol(PRESENT_PROOF_PROTOCOL_V3)
            .sendPresentationProposal(
                prover = alice,
                verifierDid = verifierDid!!,
                vcs = listOf(unsignedVc),
                options = mapOf("goal_code" to "Verify University Transcript")
            )
            .awaitPresentationRequest(alice, verifierDid!!)
            .awaitPresentationAck(alice, verifierDid!!)
            .getMessageExchange()

        val vp = faber.findVerifiablePresentationsByType("UniversityTranscript").first()
        val vc = vp.verifiableCredential!!.first()

        val subject = vc.credentialSubject!!
        val claims = subject.properties
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }
}
