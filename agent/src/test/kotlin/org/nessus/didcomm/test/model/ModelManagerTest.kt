/*-
 * #%L
 * Nessus DIDComm :: Core
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
package org.nessus.didcomm.test.model

import id.walt.common.prettyPrint
import org.junit.jupiter.api.Test
import org.nessus.didcomm.service.ModelManagerService
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ModelManagerTest: AbstractDidCommTest() {

    private val modelService get() = ModelManagerService.getService()

    @Test
    fun testModelManager() {

        // Show empty state
        log.info { modelService.modelAsJson.prettyPrint() }

        Wallet.Builder(Alice.name)
            .agentType(AgentType.NESSUS)
            .build()

        assertEquals(3, modelService.listWallets().size)
        assertNotNull(modelService.findWalletByName(Alice.name))
        log.info { modelService.modelAsJson.prettyPrint() }

        removeWallet(Alice.name)
        assertEquals(2, modelService.listWallets().size)
        assertNull(modelService.findWalletByName(Alice.name))
    }
}
