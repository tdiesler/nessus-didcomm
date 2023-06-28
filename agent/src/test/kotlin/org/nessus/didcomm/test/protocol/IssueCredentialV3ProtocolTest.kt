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
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.PropertiesService.PROTOCOL_TRUST_PING_ROTATE_DID
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.Holder
import org.nessus.didcomm.util.decodeJson

/**
 * WACI DIDComm: Issue Credential Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/tree/main/issue_credential
 */
class IssueCredentialV3ProtocolTest: AbstractAgentTest() {

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
    override fun stopAgent() {
        val ctx = contextHolder.value!!
        removeWallet(ctx.alice)
        removeWallet(ctx.faber)
        super.stopAgent()
    }

    @Test
    fun issueCredential_FromProposal() {

        val faber = contextHolder.value!!.faber
        val alice = contextHolder.value!!.alice

        var issuerDid: Did?
        var holderDid: Did?

        val mex = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(faber, didMethod = DidMethod.PEER)
            .receiveOutOfBandInvitation(alice, inviterAlias = faber.name)

            .withProperty(PROTOCOL_TRUST_PING_ROTATE_DID, false)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                check(pcon.theirLabel == faber.name)
                check(pcon.myLabel == alice.name)
                issuerDid = pcon.theirDid
                holderDid = pcon.myDid
            }

            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                issuerDid = issuerDid!!,
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
                }""".decodeJson(),
                options = """
                {
                    "goal_code": "Issue University Transcript Credential"
                }
                """.decodeJson()
            )
            .awaitCredentialOffer(alice, issuerDid!!)
            .awaitIssuedCredential(alice, issuerDid!!)

            .getMessageExchange()

        val pcon = mex.getConnection()
        pcon.myLabel shouldBe alice.name
        pcon.myDid shouldBe holderDid

        val vc = alice.findVerifiableCredentialsByType("UniversityTranscript")
            .first { "${it.credentialSubject.id}" == pcon.myDid.uri }

        val subject = vc.credentialSubject
        val claims = subject?.claims as Map<*, *>
        subject.id.toString() shouldBe holderDid?.uri
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }

    @Test
    fun issueCredential_FromOffer() {

        val faber = contextHolder.value!!.faber
        val alice = contextHolder.value!!.alice

        var issuerDid: Did?
        var holderDid: Did?

        val mex = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(faber)
            .receiveOutOfBandInvitation(alice, inviterAlias = faber.name)

            .withProperty(PROTOCOL_TRUST_PING_ROTATE_DID, false)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()

            .also {
                val pcon = it.getConnection()
                check(pcon.theirLabel == faber.name)
                check(pcon.myLabel == alice.name)
                issuerDid = pcon.theirDid
                holderDid = pcon.myDid
            }

            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialOffer(
                issuer = faber,
                holderDid = holderDid!!,
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
                }""".decodeJson()
            )
            .awaitCredentialRequest(faber, holderDid!!)
            .awaitIssuedCredential(alice, issuerDid!!)

            .getMessageExchange()

        val pcon = mex.getConnection()
        pcon.theirDid shouldBe holderDid

        val vc = alice.findVerifiableCredentialsByType("UniversityTranscript")
            .firstOrNull { "${it.credentialSubject.id}" == holderDid!!.uri }

        val subject = vc?.credentialSubject
        val claims = subject?.claims as Map<*, *>
        subject.id.toString() shouldBe holderDid?.uri
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }
}
