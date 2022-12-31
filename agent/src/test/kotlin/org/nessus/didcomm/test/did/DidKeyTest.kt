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
package org.nessus.didcomm.test.did

import id.walt.crypto.KeyAlgorithm
import id.walt.services.crypto.TinkCryptoService
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class DidKeyTest {

    @Test
    fun testCreateLocalDID() {

        // Wallet().createLocalDID("sov")
        // Wallet().createLocalDID("sov", seed = "000000000000000000000000Trustee1")

        val data = "some data".toByteArray()
        val tinkCryptoService = TinkCryptoService()
        val keyId = tinkCryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519)
        val sig = tinkCryptoService.sign(keyId, data)
        val res = tinkCryptoService.verify(keyId, sig, data)
        assertTrue(res)
    }
}
