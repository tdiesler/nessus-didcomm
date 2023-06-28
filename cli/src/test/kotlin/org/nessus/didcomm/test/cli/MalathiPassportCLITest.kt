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
import io.kotest.matchers.string.shouldStartWith
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.NessusPlaygroundReachable

/*

docker run --detach --name didcomm \
  -p 9100:9100 \
  -e NESSUS_USER_PORT=9100 \
  nessusio/nessus-didcomm:dev \
    run --headless script/travel-with-minor-bootstrap.txt

docker logs -fn400 didcomm

*/

@EnabledIf(NessusPlaygroundReachable::class)
class MalathiPassportCLITest: AbstractCLITest() {

    @Test
    fun malathiPresentsPassport() {

        val agentUri = "0.0.0.0:9000"

        val internalIp = System.getenv("INTERNAL_IP")
        internalIp shouldNotBe null

        val playgroundUrl = "http://$internalIp:9100"

        cliService.execute("agent start --uri $agentUri").isSuccess shouldBe true
        cliService.execute("wallet create --name Malathi --url=http://$internalIp:9000").isSuccess shouldBe true
        cliService.execute("did create --wallet Malathi --method=peer").isSuccess shouldBe true

        try {
            val malathi = modelService.findWalletByName("Malathi") as Wallet
            val malathiDid = properties.getVar("Malathi.Did")
            malathiDid shouldStartWith "did:peer:2"

            val govInvitationUrl = "$playgroundUrl/invitation?inviter=Government&method=peer"
            cliService.execute("protocol invitation receive --inviter Government --invitee-did Malathi.Did --url=$govInvitationUrl").isSuccess shouldBe true

            val malathiGovCon = malathi.findConnection { it.alias == "Malathi_Government" } as Connection
            properties.getVar("Malathi_Government.myDid") shouldBe malathiDid
            malathiGovCon.state shouldBe ConnectionState.ACTIVE

            val malathiPassportData = """{"givenName": "Malathi", "familyName": "Hamal", "citizenship": "US"}"""
            cliService.execute("vc propose -t Passport -i Malathi_Government.theirDid -s Malathi_Government.myDid --data $malathiPassportData").isSuccess shouldBe true

            val vcPassport = malathi.findVerifiableCredentialsByType("Passport").firstOrNull()
            properties.getVar("Malathi.Passport.Vc") shouldNotBe null
            "${vcPassport?.credentialSubject?.id}" shouldBe malathiDid

            val airInvitationUrl = "$playgroundUrl/invitation?inviter=Airport&method=peer"
            cliService.execute("protocol invitation receive --inviter Airport --invitee-did Malathi.Did --url=$airInvitationUrl").isSuccess shouldBe true

            val malathiAirCon = malathi.findConnection { it.alias == "Malathi_Airport" } as Connection
            properties.getVar("Malathi_Airport.myDid") shouldBe malathiDid
            malathiAirCon.state shouldBe ConnectionState.ACTIVE

            cliService.execute("vc present -h Malathi.Did -y Airport.Did --vc Malathi.Passport.Vc").isSuccess shouldBe true

        } finally {
            cliService.execute("wallet remove Malathi").isSuccess shouldBe true
            cliService.execute("agent stop --uri $agentUri").isSuccess shouldBe true
        }
    }
}
