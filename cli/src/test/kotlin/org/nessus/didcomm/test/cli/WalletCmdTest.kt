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
import kotlin.test.assertEquals
import kotlin.test.assertTrue


class WalletCmdTest: AbstractCmdTest() {

    @Test
    fun walletCommands() {

        assertTrue(cliService.execute("wallet --all").isSuccess)
        assertEquals(2, modelService.wallets.size)

        assertTrue(cliService.execute("wallet create --name Alice --agent Nessus").isSuccess)

        assertEquals("Alice", cliService.findContextWallet()?.name)

        assertTrue(cliService.execute("wallet switch faber").isSuccess)
        assertEquals("Faber", cliService.findContextWallet()?.name)

        assertTrue(cliService.execute("wallet remove --alias Alice").isSuccess)
        assertEquals(2, modelService.wallets.size)

        assertEquals("Faber", cliService.findContextWallet()?.name)
    }
}
