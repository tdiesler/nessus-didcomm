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
package org.nessus.didcomm.test.cli

import io.kotest.core.annotation.EnabledIf
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.NessusIsLiveCondition
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson

/**
 * Use Case: International Travel with Minor
 * https://www.w3.org/TR/vc-use-cases/#international-travel-with-minor-and-upgrade
 */
@EnabledIf(NessusIsLiveCondition::class)
class TravelWithMinorClientTest<T: AutoCloseable> : AbstractCLITest() {

    @BeforeAll
    fun startAgent() {
        cliService.execute("agent start --uri 0.0.0.0:9000")
        cliService.execute("wallet create --name Malathi")
        cliService.execute("wallet create --name Rajesh")
        cliService.execute("wallet create --name Anand")
    }

    @AfterAll
    fun stopAgent() {
        cliService.execute("wallet remove Anand")
        cliService.execute("wallet remove Rajesh")
        cliService.execute("wallet remove Malathi")
        cliService.execute("agent stop --uri 0.0.0.0:9000")
    }

    @Test
    fun travelWithMinor_DidKey() {

        val (malathi, malathiGov) = connect("Government", "Malathi")
        val (rajesh, rajeshGov) = connect("Government", "Rajesh")
        val (anand, anandHos) = connect("Hospital", "Anand")
        malathiGov.state shouldBe ConnectionState.ACTIVE
        rajeshGov.state shouldBe ConnectionState.ACTIVE
        anandHos.state shouldBe ConnectionState.ACTIVE

        cliService.getVar("Malathi_Government.myDid") shouldNotBe null
        cliService.getVar("Malathi_Government.theirDid") shouldNotBe null

        cliService.getVar("Rajesh_Government.myDid") shouldNotBe null
        cliService.getVar("Rajesh_Government.theirDid") shouldNotBe null

        cliService.getVar("Anand_Hospital.myDid") shouldNotBe null
        cliService.getVar("Anand_Hospital.theirDid") shouldNotBe null

        val malathiPassportVc = proposeVc(
            template = "Passport",
            issuerAlias = "Malathi_Government.theirDid",
            subjectAlias = "Malathi_Government.myDid",
            subjectData = """{
                "givenName": "Malathi", 
                "familyName": "Hamal", 
                "citizenship": "US"
            }""".decodeJson())

        val rajeshPassportVc = proposeVc(
            template = "Passport",
            issuerAlias = "Rajesh_Government.theirDid",
            subjectAlias = "Rajesh_Government.myDid",
            subjectData = """{
                "givenName": "Rajesh", 
                "familyName": "Hamal", 
                "citizenship": "US"
            }""".decodeJson())

        val anandBirthCertificateVc = proposeVc(
            template = "BirthCertificate",
            issuerAlias = "Anand_Hospital.theirDid",
            subjectAlias = "Anand_Hospital.myDid",
            subjectData = """{
                "givenName": "Anand",
                "familyName": "Hamal",
                "birthDate": "2022-03-29T00:00:00Z",
                "birthPlace": {
                    "type": "Hospital",
                    "address": {
                        "type": "US address",
                        "addressLocality": "Denver",
                        "addressRegion": "CO",
                        "postalCode": "80209",
                        "streetAddress": "123 Main St."
                    }
                },
                "citizenship": "US",
                "parent": [
                    {
                      "id": "${'$'}Malathi_Government.myDid",
                      "givenName": "Malathi",
                      "familyName": "Hamal"
                    },
                    {
                      "id": "${'$'}Rajesh_Government.myDid",
                      "givenName": "Rajesh",
                      "familyName": "Hamal"
                    }]
            }""".decodeJson())

        malathiPassportVc shouldNotBe null
        rajeshPassportVc shouldNotBe null
        anandBirthCertificateVc shouldNotBe null
    }

    private fun connect(inviterName: String, inviteeName: String): Pair<Wallet, Connection> {
        val invitationUrl = "http://localhost:9100/message/invitation?inviter=${inviterName}&method=key"
        val command = "protocol invitation receive --inviter=${inviterName} --invitee=${inviteeName} --url=${invitationUrl}"
        cliService.execute(command).isSuccess shouldBe true
        val invitee = modelService.findWalletByName(inviteeName)
        val pcon = invitee?.findConnection { c -> c.theirLabel == inviterName }
        checkNotNull(pcon) { "No connection: $inviteeName-$inviterName"}
        return Pair(invitee, pcon)
    }

    private fun proposeVc(template: String, issuerAlias: String, subjectAlias: String, subjectData: Map<String, Any>): W3CVerifiableCredential? {
        val issuerDid = cliService.getVar(issuerAlias)
        val subjectDid = cliService.getVar(subjectAlias)
        checkNotNull(issuerDid) { "No issuer did for: $issuerAlias" }
        checkNotNull(subjectDid) { "No subject did for: $subjectDid" }
        val command = "vc propose -t $template -i $issuerAlias -s $subjectAlias --data=${subjectData.encodeJson()}"
        cliService.execute(command).isSuccess shouldBe true
        val holder = modelService.findWalletByDid(subjectDid) as Wallet
        return holder.findVerifiableCredentialByType(template, subjectDid)
    }
}
