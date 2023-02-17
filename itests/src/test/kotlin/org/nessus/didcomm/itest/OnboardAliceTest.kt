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
package org.nessus.didcomm.itest

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet

/**
 * Onboard Alice in_memory with did:key
 */
class OnboardAliceTest : AbstractITest() {

    @Test
    fun testOnboardAlice() {

        val alice = Wallet.Builder(Alice.name)
            .agentType(AgentType.ACAPY)
            .storageType(StorageType.IN_MEMORY)
            .build()
        try {

            val pubDid = alice.getPublicDid()
            pubDid shouldBe null

            val did = alice.createDid(DidMethod.KEY)
            did.qualified.startsWith("did:key") shouldBe true

        } finally {
            removeWallet(Alice.name)
        }
    }
}
