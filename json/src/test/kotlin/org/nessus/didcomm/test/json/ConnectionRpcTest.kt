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
package org.nessus.didcomm.test.json

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.json.model.ConnectionData
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.WalletRole

class ConnectionRpcTest: AbstractJsonRpcTest() {

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
    }

    @Test
    fun createConnection() {
        val faber = createWallet("Faber", WalletRole.ENDORSER)
        val alice = createWallet("Alice")
        try {
            val pcon = createConnection(ConnectionData(faber.id, alice.id))
            pcon.state shouldBe ConnectionState.ACTIVE
            pcon.theirLabel shouldBe alice.name
            pcon.myLabel shouldBe faber.name
        } finally {
            removeWallets(alice, faber)
        }
    }

    // [TODO] list connections
    // [TODO] remove connection
}