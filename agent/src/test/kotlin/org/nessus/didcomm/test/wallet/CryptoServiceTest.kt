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
package org.nessus.didcomm.test.wallet

import id.walt.crypto.KeyAlgorithm
import id.walt.services.crypto.CryptoService
import org.junit.jupiter.api.Test
import org.nessus.didcomm.test.AbstractDidcommTest
import kotlin.test.assertTrue

class CryptoServiceTest: AbstractDidcommTest() {

    @Test
    fun signVerifyMessage() {

        val crypto = CryptoService.getService()
        val keyId = crypto.generateKey(KeyAlgorithm.EdDSA_Ed25519)

        val data = "Hello".toByteArray()
        val signed = crypto.sign(keyId, data)
        assertTrue(crypto.verify(keyId, signed, data))
    }
}
