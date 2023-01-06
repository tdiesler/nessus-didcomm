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

    private val keyStore = KeyStoreService.getService()

    fun generateKey(algorithm: KeyAlgorithm, seed: ByteArray? = null): KeyId {

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