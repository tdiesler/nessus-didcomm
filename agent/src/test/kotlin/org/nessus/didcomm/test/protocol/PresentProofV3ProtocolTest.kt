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
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.service.PropertiesService
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.Holder
import org.nessus.didcomm.util.decodeJson

/**
 * WACI DIDComm: Present Proof Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/blob/main/present_proof/present-proof-v3.md
 */
class PresentProofV3ProtocolTest<T: AutoCloseable>: AbstractAgentTest() {

    data class Context(
        val faber: Wallet,
        val alice: Wallet,
    )

    private val contextHolder = Holder<Context>()

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
        val faber = Wallet.Builder(Faber.name).build()
        val alice = Wallet.Builder(Alice.name).build()
        contextHolder.value = Context(faber = faber, alice = alice)
    }

    @AfterAll
    fun stopAgent() {
        val ctx = contextHolder.value!!
        removeWallet(ctx.alice)
        removeWallet(ctx.faber)
        stopNessusEndpoint<T>()
    }

    @Test
    fun presentProof_FromProposal() {

        val faber = contextHolder.value!!.faber
        val alice = contextHolder.value!!.alice

        var verifierDid: Did?
        var proverDid: Did?

        val unsignedVc = W3CVerifiableCredential.fromTemplate(
            pathOrName = "UniversityTranscript",
            stripValues = false)

        val mex = MessageExchange()
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
                verifierDid = verifierDid!!,
                prover = alice,
                vcs = listOf(unsignedVc),
                options = """{ "goal_code": "Verify University Transcript" }""".decodeJson()
            )
            .awaitPresentationRequest(alice, verifierDid!!)
            .awaitPresentationAck(alice, verifierDid!!)
            .getMessageExchange()

        val pcon = mex.getConnection()
        pcon.myLabel shouldBe alice.name
        pcon.myDid shouldBe proverDid

        val vp = alice.findVerifiablePresentationByType("UniversityTranscript").first()
        val vc = vp.verifiableCredentials?.firstOrNull()

        val subject = vc?.credentialSubject
        val claims = subject?.claims as Map<*, *>
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }
}
