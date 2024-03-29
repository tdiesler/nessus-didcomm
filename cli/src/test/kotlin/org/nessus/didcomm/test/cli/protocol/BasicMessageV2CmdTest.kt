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
import org.nessus.didcomm.test.cli.AbstractCLITest

class BasicMessageV2CmdTest: AbstractCLITest() {

    @Test
    fun testBasicMessageV2() {

        cliService.execute("wallet create --name Acme").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("agent start").isSuccess shouldBe true

        try {

            cliService.execute("protocol invitation connect --inviter=acme").isSuccess shouldBe true

            cliService.execute("protocol basic-message send 'Your hovercraft is full of eels'").isSuccess shouldBe true
            cliService.execute("protocol basic-message send 'Your hovercraft is full of eels' --sign").isSuccess shouldBe true
            cliService.execute("protocol basic-message send 'Your hovercraft is full of eels' --encrypt").isSuccess shouldBe true

        } finally {
            cliService.execute("agent stop").isSuccess shouldBe true
            cliService.execute("wallet remove Alice").isSuccess shouldBe true
            cliService.execute("wallet remove Acme").isSuccess shouldBe true
        }
    }
}
