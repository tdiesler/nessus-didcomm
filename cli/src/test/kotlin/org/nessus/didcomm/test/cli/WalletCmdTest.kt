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

import io.kotest.matchers.shouldBe

class WalletCmdTest: AbstractCliTest() {

    @Test
    fun walletCommands() {

        cliService.execute("wallet --all").isSuccess shouldBe true

        cliService.execute("wallet create --name Faber --agent AcaPy").isSuccess shouldBe true
        cliService.findContextWallet()?.name shouldBe "Faber"

        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.findContextWallet()?.name shouldBe "Alice"

        cliService.execute("wallet switch faber").isSuccess shouldBe true
        cliService.findContextWallet()?.name shouldBe "Faber"

        cliService.execute("wallet remove --alias Alice").isSuccess shouldBe true
        cliService.execute("wallet remove --alias Faber").isSuccess shouldBe true
    }
}
