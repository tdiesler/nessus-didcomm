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
package org.nessus.didcomm.test.cli.protocol

import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldStartWith
import org.nessus.didcomm.test.cli.AbstractCLITest

class OutOfBandV2CmdTest: AbstractCLITest() {

    @Test
    fun testOutOfBandInvitationV2_DidKey() {

        cliService.execute("wallet create --name Faber").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("agent start").isSuccess shouldBe true

        try {

            cliService.execute("protocol invitation create --inviter Faber").isSuccess shouldBe true
            cliService.execute("protocol invitation receive --invitee Alice").isSuccess shouldBe true

        } finally {
            cliService.execute("agent stop").isSuccess shouldBe true
            cliService.execute("wallet remove Alice").isSuccess shouldBe true
            cliService.execute("wallet remove Faber").isSuccess shouldBe true
        }
    }

    @Test
    fun testOutOfBandInvitationV2_DidPeer() {

        cliService.execute("wallet create --name Faber").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("agent start").isSuccess shouldBe true

        try {

            cliService.execute("did create --wallet Faber --method=peer?numalgo=2").isSuccess shouldBe true
            cliService.execute("did set-public Faber.Did").isSuccess shouldBe true

            val faberDid = properties.asString("Faber.Did")
            faberDid shouldStartWith "did:peer:2"

            cliService.execute("var set --key=protocol.trust-ping.rotate-did --val=false").isSuccess shouldBe true

            cliService.execute("protocol invitation create --inviter-did Faber.Did").isSuccess shouldBe true
            cliService.execute("protocol invitation receive --invitee Alice").isSuccess shouldBe true

            properties.asString("Alice_Faber.myDid") shouldStartWith "did:peer:2"
            properties.asString("Alice_Faber.theirDid") shouldBe faberDid

        } finally {
            cliService.execute("agent stop").isSuccess shouldBe true
            cliService.execute("wallet remove Alice").isSuccess shouldBe true
            cliService.execute("wallet remove Faber").isSuccess shouldBe true
        }
    }
}
