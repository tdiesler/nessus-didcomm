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

@EnabledIf(AcaPyOnlyCondition::class)
class RFC0095CmdV1Test: AbstractCliTest() {

    @Test
    fun testRFC0095Commands() {

        cliService.execute("wallet create --name Faber --agent AcaPy").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("agent start").isSuccess shouldBe true

        try {

            cliService.execute("rfc0434 connect faber alice").isSuccess shouldBe true

            cliService.execute("rfc0095 send 'Your hovercraft is full of eels'").isSuccess shouldBe true

        } finally {
            cliService.execute("agent stop").isSuccess shouldBe true
            cliService.execute("wallet remove Alice").isSuccess shouldBe true
            cliService.execute("wallet remove Faber").isSuccess shouldBe true
        }
    }
}
