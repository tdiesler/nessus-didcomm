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

class AgentCmdTest: AbstractCliTest() {

    @Test
    fun testInvalidUri() {
        val cmdln = safeExecutionCommandLine()
        cliService.execute("agent start --uri foo", cmdln).isFailure shouldBe true
    }

    @Test
    fun testValidUri() {

        cliService.execute("agent start --uri 0.0.0.0:8130").isSuccess shouldBe true

        Thread.sleep(500)

        cliService.execute("agent stop --uri 0.0.0.0:8130").isSuccess shouldBe true
    }

    @Test
    fun testWalletAgent() {

        cliService.execute("wallet create --name Alice").isSuccess shouldBe true

        try {

            cliService.execute("agent start").isSuccess shouldBe true

            Thread.sleep(500)

            cliService.execute("agent stop").isSuccess shouldBe true

        } finally {
            cliService.execute("wallet remove alice").isSuccess shouldBe true
        }
    }
}
