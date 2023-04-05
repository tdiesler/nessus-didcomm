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
class PlaygroundCLITest: AbstractCLITest() {

    @Test
    fun invitationV2_DidPeer() {

        val agentUri = "0.0.0.0:9000"

        val externalIp = System.getenv("EXTERNAL_IP")
        externalIp shouldNotBe null

        val playgroundUrl = "http://$externalIp:9100"
        val userUrl = "http://$externalIp:9000"

        cliService.execute("agent start --uri $agentUri").isSuccess shouldBe true
        cliService.execute("wallet create --name Malathi --url=$userUrl").isSuccess shouldBe true
        cliService.execute("did create --wallet Malathi --method=peer").isSuccess shouldBe true

        try {

            val invitationUrl = "$playgroundUrl/message/invitation?inviter=Government&method=peer"
            cliService.execute("protocol invitation receive --inviter Government --invitee-did Malathi.Did --url=$invitationUrl").isSuccess shouldBe true

        } finally {
            cliService.execute("wallet remove Malathi").isSuccess shouldBe true
            cliService.execute("agent stop --uri $agentUri").isSuccess shouldBe true
        }
    }
}
