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
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.toValueMap

/**
 * WACI DIDComm: Issue Credential Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/tree/main/issue_credential
 */
class IssueCredentialV3ProtocolTest: AbstractAgentTest() {

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
    fun issueCredential_FromOffer() {

        val faber = walletByName(Faber.name)
        val alice = walletByName(Alice.name)

        val faberAliceCon = peerConnect(faber, alice)
        val holderDid = faberAliceCon.theirDid

        MessageExchange()
            .withConnection(faberAliceCon)
            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialOffer(
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
                }""".decodeJson()
            )
            .awaitCredentialRequest(faber, holderDid)
            .awaitCredentialAck(faber, holderDid)

        val vc = alice.findVerifiableCredentialsByType("UniversityTranscript")
            .first { "${it.credentialSubject.id}" == holderDid.uri }

        val subject = vc.credentialSubject
        val claims = subject.toMap()
        subject.id.toString() shouldBe holderDid.uri
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }

    @Test
    fun issueCredential_FromProposal() {

        val faber = walletByName(Faber.name)
        val alice = walletByName(Alice.name)

        val aliceFaberCon = peerConnect(faber, alice, true)
        val issuerDid = aliceFaberCon.theirDid
        val holderDid = aliceFaberCon.myDid

        MessageExchange()
            .withConnection(aliceFaberCon)
            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                holder = alice,
                issuerDid = issuerDid,
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
                }""".toValueMap(),
                options = """
                {
                    "goal_code": "Issue University Transcript Credential"
                }
                """.toValueMap()
            )
            .awaitCredentialOffer(alice, issuerDid)
            .awaitIssuedCredential(alice, issuerDid)
            .getMessageExchange()

        val vc = alice.findVerifiableCredentialsByType("UniversityTranscript")
            .first { "${it.credentialSubject.id}" == holderDid.uri }

        val subject = vc.credentialSubject
        val claims = subject.toMap()
        subject.id.toString() shouldBe holderDid.uri
        claims["givenName"] shouldBe "Alice"
        claims["familyName"] shouldBe "Garcia"
        claims["ssn"] shouldBe "123-45-6789"
        claims["degree"] shouldBe "Bachelor of Science, Marketing"
        claims["status"] shouldBe "graduated"
        claims["year"] shouldBe "2015"
        claims["average"] shouldBe "5"
    }
}
