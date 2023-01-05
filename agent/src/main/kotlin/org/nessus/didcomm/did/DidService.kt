package org.nessus.didcomm.did

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.encodeBase58
import id.walt.crypto.getMulticodecKeyCode
import id.walt.crypto.keyPairGeneratorEd25519
import org.nessus.didcomm.wallet.DidMethod
import org.web3j.utils.Numeric
import java.security.SecureRandom

fun ByteArray.toHex() = Numeric.toHexString(this).substring(2)

object DidService {

    val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

    fun createDid(method: DidMethod, algorithm: KeyAlgorithm? = null, seed: ByteArray? = null): DidInfo {
        require(method == DidMethod.KEY) { "Method not supported: $method" }

        val keyAlgorithm = algorithm ?: DEFAULT_KEY_ALGORITHM
        val keyPairGenerator = keyPairGeneratorEd25519()

        if (seed != null) {
            val secureRandom = object: SecureRandom() {
                override fun nextBytes(bytes: ByteArray) {
                    check(seed.size == 32) { "Seed must be 32 bytes" }
                    seed.copyInto(bytes)
                }
            }
            keyPairGenerator.initialize(255, secureRandom)
        }

        val keyPair = keyPairGenerator.generateKeyPair()

        val pubKey = keyPair.public
        val pubKeyX509 = pubKey.encoded
        check("X.509" == pubKey.format)

        // Assume that the last 32 bytes are equal to the pubkey raw bytes
        val pubKeyRaw = pubKeyX509.sliceArray(pubKeyX509.size - 32 until pubKeyX509.size)
        val id = convertRawKeyToMultiBase58Btc(pubKeyRaw, getMulticodecKeyCode(keyAlgorithm))
        val verkey = pubKeyRaw.encodeBase58()

        return DidInfo(Did(id, method, keyAlgorithm, verkey), keyPair.public, keyPair.private)
    }
}