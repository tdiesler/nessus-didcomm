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

package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.decBase64
import id.walt.crypto.keyPairGeneratorEd25519
import id.walt.crypto.toBase64
import id.walt.crypto.toHexString
import io.ipfs.multibase.Base58
import mu.KotlinLogging
import java.security.SecureRandom


fun ByteArray.encodeBase58(): String = Base58.encode(this)

fun String.decodeBase58(): ByteArray = Base58.decode(this)

class OldNessusWallet {

    private val log = KotlinLogging.logger {}

    /**
     * Create and store a new local DID.
     */
    fun createLocalDID(method: String, keyType: String = DEFAULT_KEY_ALGORITHM.name, seed: String? = null) {

        val didMethod = DIDMethod.valueOf(method.uppercase())
        val keyAlgorithm = KeyAlgorithm.fromString(keyType)
        var seedBytes = validateSeed(seed)
        log.info(seedBytes.toHexString())

        // validate key_type
        if (keyAlgorithm !in didMethod.supportedAlgorithms())
            throw WalletException("Invalid key type $keyType for method $method")

        var secureRandom = SecureRandom.getInstance("SHA1PRNG")
        secureRandom.setSeed(seedBytes)

        val randomBytes = ByteArray(32)
        secureRandom.nextBytes(randomBytes)
        log.info(randomBytes.toHexString())

        val keyPairGenerator = keyPairGeneratorEd25519()
        keyPairGenerator.initialize(255, secureRandom)

        val keypair = keyPairGenerator.generateKeyPair()
        log.info("pubk {}", keypair.public.encoded.toHexString())
        val verkey64 = keypair.public.toBase64()
        val verkeyBytes = decBase64(verkey64)
        val verkey58 = verkeyBytes.encodeBase58()

        log.info("$verkey64")
        log.info("$verkey58")
    }

    /**
     * Convert a seed parameter to standard format and check length.
     *
     * @property seed the seed to validate.
     * @return The validated and encoded seed
     */
    private fun validateSeed(seed: String? = null): ByteArray {
        var byteArray = ByteArray(32);
        if (seed != null) {
            byteArray = seed.toByteArray(Charsets.UTF_8)
        } else {
            SecureRandom().nextBytes(byteArray);
        }
        if (byteArray.size != 32) {
            throw WalletException("Seed value must be 32 bytes in length")
        }
        return byteArray
    }
}
