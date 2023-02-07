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
import mu.KotlinLogging
import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Alice
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ModelServiceTest: AbstractDidCommTest() {
    val log = KotlinLogging.logger {}

    private val modelService get() = ModelService.getService()

    @Test
    fun testModelManager() {

        // Show empty state
        log.info { modelService.modelAsJson.prettyPrint() }

        Wallet.Builder(Alice.name)
            .agentType(AgentType.NESSUS)
            .build()

        assertEquals(3, modelService.wallets.size)
        assertNotNull(modelService.findWalletByName(Alice.name))
        log.info { modelService.modelAsJson.prettyPrint() }

        removeWallet(Alice.name)
        assertEquals(2, modelService.wallets.size)
        assertNull(modelService.findWalletByName(Alice.name))
    }
}
