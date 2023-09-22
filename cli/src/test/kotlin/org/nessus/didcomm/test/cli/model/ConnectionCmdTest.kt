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
package org.nessus.didcomm.test.cli.model

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.test.cli.AbstractCLITest

class ConnectionCmdTest: AbstractCLITest() {

    @BeforeAll
    fun startAgent() {
        cliService.execute("agent start").isSuccess shouldBe true
        cliService.execute("wallet create --name Acme").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("wallet create --name Bob").isSuccess shouldBe true
    }

    @AfterAll
    fun stopAgent() {
        cliService.execute("wallet remove Bob").isSuccess shouldBe true
        cliService.execute("wallet remove Alice").isSuccess shouldBe true
        cliService.execute("wallet remove Acme").isSuccess shouldBe true
        cliService.execute("agent stop").isSuccess shouldBe true
    }

    @Test
    fun switchCurrentConnection() {

        val acme = modelService.findWalletByName("Acme") as Wallet
        val alice = modelService.findWalletByName("Alice") as Wallet
        val bob = modelService.findWalletByName("Bob") as Wallet

        cliService.findContextWallet() shouldBe bob // created last

        acme.currentConnection shouldBe null
        alice.currentConnection shouldBe null
        bob.currentConnection shouldBe null

        cliService.execute("protocol invitation connect --inviter=acme --invitee=alice").isSuccess shouldBe true
        acme.currentConnection?.myLabel shouldBe acme.alias
        acme.currentConnection?.theirLabel shouldBe alice.alias
        acme.currentConnection?.alias shouldBe "Acme_Alice"
        alice.currentConnection?.myLabel shouldBe alice.alias
        alice.currentConnection?.theirLabel shouldBe acme.alias
        alice.currentConnection?.alias shouldBe "Alice_Acme"

        cliService.execute("protocol invitation connect --inviter=bob --invitee=alice").isSuccess shouldBe true
        bob.currentConnection?.myLabel shouldBe bob.alias
        bob.currentConnection?.theirLabel shouldBe alice.alias
        bob.currentConnection?.alias shouldBe "Bob_Alice"
        alice.currentConnection?.myLabel shouldBe alice.alias
        alice.currentConnection?.theirLabel shouldBe bob.alias
        alice.currentConnection?.alias shouldBe "Alice_Bob"


        cliService.execute("wallet switch alice").isSuccess shouldBe true
        cliService.findContextWallet() shouldBe alice // created last
        alice.currentConnection?.alias shouldBe "Alice_Bob"

        cliService.execute("connection switch alice_acme").isSuccess shouldBe true
        alice.currentConnection?.alias shouldBe "Alice_Acme"
    }
}
