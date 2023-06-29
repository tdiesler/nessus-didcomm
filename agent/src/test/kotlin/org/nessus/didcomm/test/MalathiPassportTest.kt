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
package org.nessus.didcomm.test

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.verifiableCredential
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.util.toValueMap


class MalathiPassportTest: AbstractAgentTest() {

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
    }

    @Test
    fun malathiPresentsPassport() {

        val gov = Wallet.Builder("Government").build()
        val airport = Wallet.Builder("Airport").build()
        val malathi = Wallet.Builder("Malathi").build()
        try {

            val malathiGovCon = MessageExchange()
                .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
                .createOutOfBandInvitation(gov, didMethod = DidMethod.PEER)
                .receiveOutOfBandInvitation(malathi, inviterAlias = gov.name)
                .withProtocol(TRUST_PING_PROTOCOL_V2)
                .sendTrustPing()
                .awaitTrustPingResponse()
                .getMessageExchange()
                .getConnection()
            malathiGovCon.state shouldBe ConnectionState.ACTIVE
            val malathiGovDid = malathiGovCon.myDid
            val govDid = malathiGovCon.theirDid

            val malathiAirCon = MessageExchange()
                .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
                .createOutOfBandInvitation(airport, didMethod = DidMethod.PEER)
                .receiveOutOfBandInvitation(malathi, inviterAlias = airport.name)
                .withProtocol(TRUST_PING_PROTOCOL_V2)
                .sendTrustPing()
                .awaitTrustPingResponse()
                .getMessageExchange()
                .getConnection()
            malathiAirCon.state shouldBe ConnectionState.ACTIVE
            val airportDid = malathiAirCon.theirDid

            MessageExchange()
                .withConnection(malathiAirCon)
                .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
                .sendCredentialProposal(
                    issuerDid = govDid,
                    holder = malathi,
                    template = "Passport",
                    subjectData = """
                    {
                        "givenName": "Malathi", 
                        "familyName": "Hamal", 
                        "citizenship": 
                        "US"
                    }""".toValueMap(),
                )
                .awaitCredentialOffer(malathi, govDid)
                .awaitIssuedCredential(malathi, govDid)
                .getMessageExchange()

            val vc = malathi.findVerifiableCredentialsByType("Passport").first()
            "${vc.credentialSubject?.id}" shouldBe malathiGovDid.uri

            MessageExchange()
                .withConnection(malathiAirCon)
                .withProtocol(PRESENT_PROOF_PROTOCOL_V3)
                .sendPresentationProposal(
                    verifierDid = airportDid,
                    prover = malathi,
                    vcs = listOf(vc)
                )
                .awaitPresentationRequest(malathi, airportDid)
                .awaitPresentationAck(malathi, airportDid)
                .getMessageExchange()

            val vp = malathi.findVerifiablePresentationsByType("Passport").first()
            val vpc = vp.verifiableCredential?.first()
            "${vpc?.credentialSubject?.id}" shouldBe malathiGovDid.uri

        } finally {
            removeWallets()
        }
    }
}
