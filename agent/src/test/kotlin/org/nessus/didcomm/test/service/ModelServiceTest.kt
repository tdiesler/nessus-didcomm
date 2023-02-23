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
package org.nessus.didcomm.test.service

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import mu.KotlinLogging
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.encodeJson

class ModelServiceTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun testModelService() {

        // Show empty state
        log.info { modelService.model.encodeJson(true) }

        val alice = Wallet.Builder(Alice.name)
            .agentType(AgentType.NESSUS)
            .build()

        modelService.findWalletByName(Alice.name) shouldNotBe null
        log.info { modelService.model.encodeJson(true) }

        removeWallet(alice)

        modelService.findWalletByName(Alice.name) shouldBe null
    }
}
