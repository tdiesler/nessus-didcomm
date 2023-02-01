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

import org.junit.jupiter.api.Test
import kotlin.test.assertTrue


class RFC0048CmdTest: AbstractCmdTest() {

    @Test
    fun testRFC0048Commands() {

        assertTrue(cliService.execute("agent start 0.0.0.0:8130").isSuccess)
        assertTrue(cliService.execute("wallet create --name Alice").isSuccess)

        try {

            assertTrue(cliService.execute("rfc0023 connect alice faber").isSuccess)
            assertTrue(cliService.execute("rfc0048 send-ping").isSuccess)

        } finally {
            assertTrue(cliService.execute("wallet remove --name alice").isSuccess)
            assertTrue(cliService.execute("agent stop 0.0.0.0:8130").isSuccess)
        }
    }
}
