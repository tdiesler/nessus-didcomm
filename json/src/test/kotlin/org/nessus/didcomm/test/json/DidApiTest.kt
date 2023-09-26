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

import io.kotest.matchers.result.shouldBeSuccess
import org.junit.jupiter.api.Assertions.assertEquals
import org.nessus.didcomm.json.model.DidData
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.WalletRole

class DidApiTest: AbstractApiTest() {

    @Test
    fun createFindRemoveDid() {
        val gov = createWallet("Government", WalletRole.TRUSTEE)
        try {
            val didKey = createDid(gov, DidMethod.KEY)
            assertEquals(DidMethod.KEY, didKey.method)
            log.info { didKey.uri }

            val didPeer0 = createDid(gov, DidMethod.PEER, mapOf("numalgo" to 0))
            assertEquals(DidMethod.PEER, didPeer0.method)
            log.info { didPeer0.uri }

            val didPeer2 = createDid(gov, DidMethod.PEER)
            assertEquals(DidMethod.PEER, didPeer2.method)
            log.info { didPeer2.uri }

            val didSov = createDid(gov, DidMethod.SOV)
            assertEquals(DidMethod.SOV, didSov.method)
            log.info { didSov.uri }

            var res = rpcService.dispatchApiMessage("/did/list", DidData(ownerId = gov.id).toJson())
            var dids = res.shouldBeSuccess() as List<*>
            dids.forEach { log.info { (it as Did).uri } }

            res = rpcService.dispatchApiMessage("/did/list",
                DidData(ownerId = gov.id, method = DidMethod.PEER).toJson())
            dids = res.shouldBeSuccess() as List<*>
            dids.forEach { log.info { (it as Did).uri } }

        } finally {
            removeWallet(gov)
        }
    }
}
