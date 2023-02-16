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

class RFC0434CmdV2Test: AbstractCliTest() {

    @Test
    fun testRFC0434CommandsV2() {

        cliService.execute("wallet create --name Acme").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("agent start").isSuccess shouldBe true

        try {

            cliService.execute("rfc0434 create-invitation --inviter Acme --dcv2").isSuccess shouldBe true
            cliService.execute("rfc0434 receive-invitation --invitee Alice --dcv2").isSuccess shouldBe true

        } finally {
            cliService.execute("agent stop").isSuccess shouldBe true
            cliService.execute("wallet remove --alias Alice").isSuccess shouldBe true
            cliService.execute("wallet remove --alias Acme").isSuccess shouldBe true
        }
    }
}
