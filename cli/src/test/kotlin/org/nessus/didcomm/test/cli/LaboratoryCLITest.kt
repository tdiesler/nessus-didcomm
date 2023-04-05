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

docker run --name=playground --rm -it \
  -p 9100:9100 \
  -e NESSUS_USER_PORT=9100 \
  -e NESSUS_USER_HOST=$INTERNAL_IP \
  nessusio/nessus-didcomm:dev \
    run --headless script/travel-with-minor-bootstrap.txt

docker run --name=mediator --rm -it \
  -p 9200:9200 \
  -e NESSUS_USER_PORT=9200 \
  -e NESSUS_USER_HOST=$INTERNAL_IP \
  nessusio/nessus-didcomm:dev \
    run --headless script/mediator-bootstrap.txt

docker run --name=malathi --rm -it \
  -p 9000:9000 \
  -e NESSUS_USER_PORT=9000 \
  -e NESSUS_USER_HOST=$INTERNAL_IP \
  nessusio/nessus-didcomm:dev agent start

*/

@EnabledIf(NessusPlaygroundReachable::class)
class LaboratoryCLITest: AbstractCLITest() {

    @Test
    fun invitationV2_DidPeer() {

        val internalIp = System.getenv("INTERNAL_IP")
        internalIp shouldNotBe null

        val playgroundUrl = "http://$internalIp:9100"
        val mediatorUrl = "http://$internalIp:9200"
        val userUrl = "http://$internalIp:9000"

        cliService.execute("agent start --uri 0.0.0.0:9000").isSuccess shouldBe true
        cliService.execute("wallet create --name=Malathi --url=$userUrl").isSuccess shouldBe true

        cliService.execute("var set --key=protocol.out-of-band.routing-key-as-endpoint-url --val=false").isSuccess shouldBe true

        try {
            val malathi = modelService.findWalletByName("Malathi") as Wallet

            val mediatorInvitation = "$mediatorUrl/message/invitation?inviter=Mediator&method=peer"
            cliService.execute("protocol invitation receive --mediator=Mediator --invitee=Malathi --url=$mediatorInvitation").isSuccess shouldBe true

            val malathiDid = properties.getVar("Malathi.Did")
            val mediatorDid = properties.getVar("Mediator.Did")
            malathiDid shouldStartWith "did:peer:2"
            mediatorDid shouldStartWith "did:peer:2"

            val malathiDidDoc = didService.loadDidDoc(malathiDid as String)
            malathiDidDoc.didCommServices.first().routingKeys shouldBe listOf(mediatorDid)

            val governmentInvitation = "$playgroundUrl/message/invitation?inviter=Government&method=peer"
            cliService.execute("protocol invitation receive --inviter=Government --invitee-did=Malathi.Did --url=$governmentInvitation").isSuccess shouldBe true

            val malathiGov = malathi.findConnection { c -> c.alias == "Malathi_Government" } as Connection
            val malathiMed = malathi.findConnection { c -> c.alias == "Malathi_Mediator" } as Connection
            malathiGov.state shouldBe ConnectionState.ACTIVE
            malathiMed.state shouldBe ConnectionState.ACTIVE

        } finally {
            cliService.execute("wallet remove Malathi").isSuccess shouldBe true
            cliService.execute("agent stop --uri 0.0.0.0:9000").isSuccess shouldBe true
        }
    }
}
