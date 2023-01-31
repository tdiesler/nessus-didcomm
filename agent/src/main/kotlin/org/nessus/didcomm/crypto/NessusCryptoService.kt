/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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
package org.nessus.didcomm.crypto

import id.walt.crypto.Key
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.crypto.keyPairGeneratorEd25519
import id.walt.crypto.newKeyId
import id.walt.services.CryptoProvider
import id.walt.services.crypto.SunCryptoService
import id.walt.services.keystore.KeyStoreService
import java.security.SecureRandom

class NessusCryptoService: SunCryptoService() {

    private val keyStore get() = KeyStoreService.getService()

    fun generateKey(algorithm: KeyAlgorithm, seed: ByteArray?): KeyId {

        val generator = when (algorithm) {
            KeyAlgorithm.EdDSA_Ed25519 -> keyPairGeneratorEd25519()
            else -> throw IllegalArgumentException("Key algorithm not supported: $algorithm")
        }

        if (seed != null) {
            val secureRandom = object: SecureRandom() {
                override fun nextBytes(bytes: ByteArray) {
                    check(seed.size == 32) { "Seed must be 32 bytes" }
                    seed.copyInto(bytes)
                }
            }
            generator.initialize(255, secureRandom)
        }

        val keyPair = generator.generateKeyPair()
        val key = Key(newKeyId(), algorithm, CryptoProvider.SUN, keyPair)
        keyStore.store(key)

        return key.keyId
    }
}
