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

import org.junit.jupiter.api.Test
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.StorageType
import org.nessus.didcomm.wallet.Wallet
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Onboard Alice in_memory with did:key
 */
class OnboardAliceTest : AbstractIntegrationTest() {

    @Test
    fun testOnboardAlice() {

        val alice = Wallet.Builder(Alice.name)
            .agentType(AgentType.ACAPY)
            .storageType(StorageType.IN_MEMORY)
            .build()
        try {

            val pubDid = alice.getPublicDid()
            assertNull(pubDid)

            val did = alice.createDid(DidMethod.KEY)
            assertTrue(did.qualified.startsWith("did:key"))

        } finally {
            removeWallet(Alice.name)
        }
    }
}
