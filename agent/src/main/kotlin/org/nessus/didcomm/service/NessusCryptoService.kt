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
package org.nessus.didcomm.service

import com.goterl.lazysodium.interfaces.Sign
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import id.walt.crypto.Key
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.crypto.keyPairGeneratorEd25519
import id.walt.crypto.newKeyId
import id.walt.servicematrix.ServiceProvider
import id.walt.services.CryptoProvider
import id.walt.services.crypto.SunCryptoService
import id.walt.services.key.Keys
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.service.LazySodiumService.convertEd25519toCurve25519
import org.nessus.didcomm.util.encodeBase64Url
import org.nessus.didcomm.util.trimJson
import java.security.SecureRandom

fun Key.toOctetKeyPair(): OctetKeyPair {
    check(keyPair != null) { "No keyPair" }
    return Keys(keyId.id, keyPair!!, "SunEC").toOctetKeyPair()
}

fun Did.toOctetKeyPair(): OctetKeyPair {
    val keyStore = KeyStoreService.getService()
    return keyStore.load(uri, KeyType.PRIVATE).toOctetKeyPair()
}

class NessusCryptoService: SunCryptoService() {

    companion object: ServiceProvider {
        private val implementation = NessusCryptoService()
        override fun getService() = implementation
    }

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

    fun toOctetKeyPair(kid: String, crv: Curve, keyType: KeyType = KeyType.PUBLIC): OctetKeyPair {

        val key: Key = keyStore.load(kid, keyType)
        check(key.cryptoProvider == CryptoProvider.SUN) { "Unexpected provider: ${key.cryptoProvider}" }
        check(key.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unexpected algorithm: ${key.algorithm}" }

        return when(crv) {

            Curve.Ed25519 -> {
                when(keyType) {

                    KeyType.PRIVATE -> {
                        key.toOctetKeyPair()
                    }

                    KeyType.PUBLIC -> {
                        val ed25519PubBytes = key.getPublicKeyBytes()
                        OctetKeyPair.parse("""
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": "${ed25519PubBytes.encodeBase64Url()}"
                        }                
                        """.trimJson())
                    }
                }
            }

            Curve.X25519 -> {
                when(keyType) {

                    KeyType.PRIVATE -> {
                        val keys = Keys(key.keyId.id, key.keyPair!!, "SunEC")
                        val ed25519PubBytes = keys.getPubKey()
                        val ed25519PrvBytes = keys.getPrivKey()

                        val ed25519KeyPair = com.goterl.lazysodium.utils.KeyPair(
                            com.goterl.lazysodium.utils.Key.fromBytes(ed25519PubBytes),
                            com.goterl.lazysodium.utils.Key.fromBytes(ed25519PrvBytes)
                        )

                        val lazySign = LazySodiumService.lazySodium as Sign.Lazy
                        val x25519KeyPair = lazySign.convertKeyPairEd25519ToCurve25519(ed25519KeyPair)
                        val x25519PubBytes = x25519KeyPair.publicKey.asBytes
                        val x25519PrvBytes = x25519KeyPair.secretKey.asBytes

                        OctetKeyPair.parse("""
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "${x25519PubBytes.encodeBase64Url()}",
                            "d": "${x25519PrvBytes.encodeBase64Url()}"
                        }                
                        """.trimJson())
                    }

                    KeyType.PUBLIC -> {
                        val ed25519PubBytes = key.getPublicKeyBytes()
                        val x25519PubBytes = ed25519PubBytes.convertEd25519toCurve25519().asBytes
                        OctetKeyPair.parse("""
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "${x25519PubBytes.encodeBase64Url()}"
                        }                
                        """.trimJson())
                    }
                }
            }

            else -> throw IllegalArgumentException("Unsupported curve: $crv")
        }
    }
}

